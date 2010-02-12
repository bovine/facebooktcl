#!/usr/bin/tclsh
#* 
#* ------------------------------------------------------------------
#* tcl2tex-2.tcl - Extract comments from Tcl source files, generating LaTeX output
#* Created by Robert Heller on Wed Feb 25 14:34:04 2009
#* ------------------------------------------------------------------
#* ------------------------------------------------------------------
#* Contents:
#* ------------------------------------------------------------------
#*  
#*     Facebook API in Tcl Project
#*     Copyright (C) 2009  Robert Heller D/B/A Deepwoods Software
#* 			51 Locke Hill Road
#* 			Wendell, MA 01379-9728
#* 
#*     This program is free software; you can redistribute it and/or modify
#*     it under the terms of the GNU General Public License as published by
#*     the Free Software Foundation; either version 2 of the License, or
#*     (at your option) any later version.
#* 
#*     This program is distributed in the hope that it will be useful,
#*     but WITHOUT ANY WARRANTY; without even the implied warranty of
#*     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#*     GNU General Public License for more details.
#* 
#*     You should have received a copy of the GNU General Public License
#*     along with this program; if not, write to the Free Software
#*     Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#* 
#*  
#* 

# tcl2tex 2: strip the doc out of an Tcl source file, rewriten.
# <in> options and the Tcl(s)  to parse; see help information.
# <in> (optional) the output file (LaTeX).
# <auth> Jeroen Hoppenbrouwers
# <auth> Robert Heller

namespace eval tcl2tex {
  variable tagOn 0
  variable o {}
  variable wasVar yes
  variable doComments no
}

proc tcl2tex::forceExtension {filename extension} {
  # Function; forces the filename to have the extension, either by
  # appending or by replacing a current extendion.  There can be at most
  # one dot in the resulting filename (alas... DOS strikes again).
  # <in> filename = The file name to process.
  # <in> extension = The extension to force upon the file name.
  # <out> The new file name.
 
  # Separate the path and the file name (the path might contain dots).
  set dirname [file dirname $filename]
  set tail [file tail $filename]
 
  # Look for the first occurrence of a dot in the actual file name.
  set dot [string first "." $tail]
  if {$dot!=-1} {
    # Chop off everything from the dot on, including the dot itself.
    set tail [string range $tail 0 [expr $dot-1]]
  }
 
  return $dirname/$tail.$extension
}


proc tcl2tex::unTag {l} {
  # Rewrites the tag format into proper LaTeX.
  # <in> l = the line to rewrite.
  # <out> the rewritten line.

  variable tagOn 
  variable o

  # Replace some characters that need TeX escapes.
  regsub -all {\$} $l {\\$} l
  regsub -all {_} $l {\\_} l
  regsub -all {&} $l {\\&} l
  regsub -all {\{} $l {\{} l
  regsub -all {\}} $l {\}} l
  regsub      {\^$} $l {\\\\} l
  while {[regexp {^(.*)@([A-Za-z0-9:_\\-]+)@(.*)$} "$l" => before label after] > 0} {
    regsub -all {\\_} $label {_} label
    set l "$before\\cite{$label}$after"
  }
  while {[regexp {^(.*)\?([A-Za-z0-9:_\\-]+)\?(.*)$} "$l" => before label after] > 0} {
    regsub -all {\\_} $label {_} label
    set l "$before\\ref{$label}$after"
  }
  while {[regexp {^(.*)=([A-Za-z0-9:_\\-]+)=(.*)$} "$l" => before label after] > 0} {
    regsub -all {\\_} $label {_} label
    set l "$before\\pageref{$label}$after"
  }

  if {[regexp {^\[([^]]+)\](.*)$} $l whole word rest] > 0} {
    set rest [string trim $rest " \t"]
    if {[string equal "$word" {label}] || [string equal "$word" {url}]} {
      regsub -all {\\$} $rest {\$} rest
      regsub -all {\\_} $rest {_} rest
      regsub -all {\\&} $rest {&} rest
    }
    set l "\\$word{$rest}"
    # Replace the tag if there is one
  } elseif {![string compare [string index $l 0] "<"]} {
    if {! $tagOn} {
      puts $o "\\begin{description}"
      set tagOn 1
    }
    set p [string first ">" $l]; # find the index of ">"
    set tagName [string range $l 1 [expr $p - 1]]
    set tagName [string trim "$tagName"]
    if {[string length "$tagName"] == 0} {
      set l "\\end{description}"
      set tagOn 0
    } else {
      set l "\\item \[$tagName\] [string range $l [expr $p + 1 ] end]"
    }
  }

  return $l
}; # unTag


proc tcl2tex::stopTag {} {
  # Close a description environment if it is open
  variable tagOn 
  variable o
  if {$tagOn} {
    puts $o "\\end{description}"
    set tagOn 0
  }
}; # stopTag

proc tcl2tex::convert {filename} {
  # Runs the actual conversion on a file.
  # <in> filename = The file name to convert.

  variable o;#	The output handle.

  # Open the input file (Tcl file)
  set f [open $filename]

  puts $o "% Begin of input file $filename"

  # First, parse the header of the file. Skip the first line if it starts
  # with #! (shell interpreter).
  set line [string trim [gets $f]]
  if {[string range $line 0 1]=="#!"} {gets $f line}

  # Search for the first line starting with a comment sign (#).
  while {[string index $line 0] != "#"} {
    set line [string trim [gets $f]]
  }

  # Skip documentation header
  while {[string range $line 0 1]=="#*"} {
    set line [string trim [gets $f]]
  }

  # Search for the first line starting with a comment sign (#).
  while {[string index $line 0] != "#"} {
    set line [string trim [gets $f]]
  }

  # Print the file header (everything until the first empty line)
  #puts $o "\\vspace{1cm}"
  set fname "[file tail $filename]"
  regsub -all {\$} $fname {\\$} fname
  regsub -all {_} $fname {\\_} fname
  regsub -all {&} $fname {\\&} fname
  regsub -all {\{} $fname {\{} fname
  regsub -all {\}} $fname {\}} fname
  set theChapter "File: `$fname'"
  set theLabel   "$fname"
  set didChapter 0
  while {$line!=""} {
    set line [string trimleft $line " #\t"]
    set line [string trim $line]
    if {[string range $line 0 2] == {$Id}} {
      puts $o "\\typeout{Generated from $line}"
    } elseif {[regexp {^@([^:]+):(.*)$} $line whole word rest] > 0} {
      switch -exact -- $word {
	Chapter {
		puts $o "\\chapter{[string trim $rest]}"
		set didChapter 1
		}
	Label {puts $o "\\label{[string trim $rest]}"}
	Typeout {puts $o "\\typeout{[string trim $rest]}"}
      }
    } else {
      if {!$didChapter} {
	puts $o "\\chapter{$theChapter}"
	puts $o "\\label{$theLabel}"
	set didChapter 1
      }
      puts $o [unTag $line]
    }
    if {[eof $f]} {break}
    gets $f line
    if {[regexp {^[[:space:]]*#} "$line"] == 0} {break}
  }
  stopTag
  puts $o ""

  variable wasVar yes
  variable doComments no


  processCompleteStatements no yes [read $f]
  puts $o "% End of input file $filename"

  close $f  
}; # convert

proc tcl2tex::processCompleteStatements {docBody isEnv statements {environment {}} {level 0}} {

  set statements [string trimleft "$statements" "\n"]
  variable doComments $docBody
  variable o
  set index 0

  set tryline ""
  set newstatement 1
  set firstline ""

  set bracelevel 0
  set lineno 0
  set hasStartedDoc no

#  if {$doComments} {
#    puts stderr "*** processCompleteStatements: working on commented statement body starting with [string range $statements 0 50]"
#    puts stderr "*** processCompleteStatements: lineno = $lineno, hasStartedDoc is $hasStartedDoc"
#  }

  foreach line [split $statements \n] {
    # Here we must remember that "line" misses the \n that split ate.
    # When line is used below we add \n.
    # The extra \n generated on the last line does not matter.

#   if {$doComments} {
#	puts stderr "*** processCompleteStatements (top of foreach loop, while doing comments): line is '$line'"
#	puts stderr "*** processCompleteStatements (top of foreach loop, while doing comments): tryline is '$tryline'"
#	puts stderr "*** processCompleteStatements (top of foreach loop, while doing comments): hasStartedDoc is $hasStartedDoc"
#    }
    if {[string is space "$line"] &&
	[string is space "$tryline"] &&
	$doComments && $hasStartedDoc} {
      stopTag
      set doComments no
#      puts stderr "*** processCompleteStatements (top of foreach loop, while doing comments): stop doc from comments"
    }

    incr lineno
    if {$bracelevel > 0} {
      # Manual brace parsing is entered when we know we are in
      # a braced block.  Return to ordinary parsing as soon
      # as a balanced brace is found.

      # Extract relevant characters
      foreach char [regexp -all -inline {\\.|{|}} $line] {
        if {$char eq "\{"} {
          incr bracelevel
        } elseif {$char eq "\}"} {
          incr bracelevel -1
          if {$bracelevel <= 0} break
        }
      }
      if {$bracelevel > 0} {
        # We are still in a braced block so go on to the next line
	append tryline $line\n
	set line ""
        continue
      }
    }


    if {[string is space $line]} {
      if {$tryline eq ""} {
        incr index [string length $line]
        incr index
      } else {
        append tryline $line\n
      }
      continue
    }

#    puts stderr "*** processCompleteStatements after completeness and blank line checks: tryline starts with [string range $tryline 0 50]"
#    puts stderr "*** processCompleteStatements: working on line: $line"
    append line \n

    while {$line ne ""} {

      # Move everything up to the next semicolon, newline or eof
      # to tryline

      set i [string first ";" $line]
      if {$i != -1} {
	append tryline [string range $line 0 $i]
        if {$newstatement} {
	  set newstatement 0
          set firstline [string range $line 0 $i]
        }
	incr i
	set line [string range $line $i end]
        set splitSemi 1
      } else {
	append tryline $line
        if {$newstatement} {
          set newstatement 0
          set firstline $line
        }
	set line ""
	set splitSemi 0
      }
      # If we split at a ; we must check that it really may be an end
      if {$splitSemi} {
	# Comment lines don't end with ;
	#if {[regexp {^\s*#} $tryline]} {continue}
        if {[string equal [string index [string trimleft $tryline] 0]\
               "#"]} {continue}
	# Look for \'s before the ;
	# If there is an odd number of \, the ; is ignored
	if {[string equal [string index $tryline end-1] "\\"]} {
	  set i [expr {[string length $tryline] - 2}]
	  set t $i
	  while {[string equal [string index $tryline $t] "\\"]} {
            incr t -1
          }
	  if {($i - $t) % 2 == 1} {continue}
	}
      }
      # Check if it's a complete line
#      puts stderr "*** processCompleteStatements: checking completeness: firstline is $firstline"
      if {[info complete $tryline]} {
#	puts stderr "*** processCompleteStatements: tryline is complete, firstline is $firstline"
       # Remove leading space, keep track of index.
	# Most lines will have no leading whitespace since
	# buildLineDb removes most of it. This takes care
	# of all remaining.
        if {[string is space -failindex i $tryline]} {
	  # Only space, discard the line
          incr index [string length $tryline]
          set tryline ""
          set newstatement 1
          continue
        } else {
          if {$i != 0} {
            set tryline [string range $tryline $i end]
          incr index $i
          }
        }
#	puts stderr "*** processCompleteStatements: checking for comment or statement: firstline is $firstline"
        if {[string equal [string index $tryline 0] "#"]} {
	  # Check and process comments
	  if {$doComments} {
#	    puts stderr "*** processCompleteStatements: tryline contains doc: $tryline"
	    set hasStartedDoc yes
	    puts $o [unTag [string trim [string trimleft $tryline " #\t"]]]
	  }
	} else {
	  if {$doComments} {
	    stopTag
	    set doComments no
	  }
#	  puts stderr "*** processCompleteStatements: complete statement: firstline is $firstline"
	  if {$isEnv} {
	    if {$splitSemi} {
              # Remove the semicolon from the statement
	      set doComments [processStatement [string range $tryline 0 end-1] $environment $level]
	    } else {
	      set doComments [processStatement $tryline $environment $level]
	    }
	    set hasStartedDoc no
	  }
	}
	incr index [string length $tryline]
	set tryline ""
        set newstatement 1
      } else {
      }
    }
    # If the line is complete except for a trailing open brace
    # we can switch to just scanning braces.
    # This could be made more general but since this is the far most
    # common case it's probably not worth complicating it.
    if {[string range $tryline end-2 end] eq " \{\n" && \
                    [info complete [string range $tryline 0 end-2]]} {
       set bracelevel 1
    }
  }
}
    
    

proc tcl2tex::processStatement {statement {environment {}} {level 0}} {
  variable o;#	The output handle.
  variable wasVar
  variable doComments
  variable OPTIONS

#  puts stderr "*** processStatement: environment = $environment, level = $level"
  set statement [string trim "$statement"]

  if {[regexp {^([^ 	]+)} "[string trim $statement]" whole firstWord] < 1} {
    set firstWord {}
  }
#  puts stderr "*** processStatement: firstWord = $firstWord"
  set newEnv no
  if {[lsearch -exact {proc typemethod method typeconstructor constructor 
		       destructor snit::widget snit::type snit::macro 
		       snit::widgetadaptor} $firstWord]!=-1} {
   
    if {[lsearch -exact {proc typemethod method snit::macro} $firstWord]!=-1} {
      set procname [lrange $statement 0 1]
      set params   [lindex $statement 2]
      set body     [lindex $statement 3]
    } elseif {[lsearch -exact {typeconstructor destructor} $firstWord]!=-1} {
      set procname [lindex $statement 0]
      set params   {}
      set body     [lindex $statement 1]
    } elseif {{constructor} eq $firstWord} {
      set procname constructor
      set params   [lindex $statement 1]
      set body     [lindex $statement 2]
    } else {;#	snit::type, snit::widgetadaptor, and snit::widget
      set procname [lrange $statement 0 1]
      set params   {}
      set body     [lindex $statement 2]
      set newEnv yes
    }
#    puts stderr "*** processStatement: procname = $procname, params = $params"
    puts $o "\n\n\\noindent\\rule\{\\textwidth\}\{0.4pt\}"
    sectionHeading $procname $params $level
    puts $o ""
#    if {"$firstWord" eq "typemethod"} {puts stderr "*** processStatement: body = $body"}
    if {$newEnv} {
      set newenv $environment
      lappend newenv $firstWord
      processCompleteStatements yes yes $body $newenv [expr {$level + 1}]
      return false
    } else {
      processCompleteStatements yes no $body $environment $level
      return false
    }
  } elseif {"$firstWord" eq "namespace" && [lindex $statement 1] eq "eval" && 
		$level == 0} {
    set procname "namespace [lindex $statement 2]"
    set body [lindex $statement 3]

    regsub -all {\$} $procname {\\$} procname
    regsub -all {_} $procname {\\_} procname
    regsub -all {&} $procname {\\&} procname
    regsub -all {\{} $procname {\{} procname
    regsub -all {\}} $procname {\}} procname

    puts $o "\\section\[namespace $procname\]{namespace $procname}"

    processCompleteStatements yes yes $body namespace 1
    return false
  } elseif {[lsearch -exact {global variable option} $firstWord] != -1} {
#    puts stderr "*** processStatement: global/variable/option: statement = $statement"
    set procname [lrange $statement 0 1]
    set params   {}
    sectionHeading $procname $params $level
    return true
  } elseif {"$firstWord" eq "::Facebook::facebookCallMethod"} {
    # Special case for Facebook.tcl
    set temp {list }
    append temp "$statement"
    set statement [eval "$temp"]
#    puts stderr "*** processStatement: ::Facebook::facebookCallMethod: statement is '$statement'"
    set procname [list method [lindex $statement 1]]
    set     params   result
    lappend params   [lrange $statement 3 end]
    sectionHeading $procname $params $level
    return true
  } elseif {$firstWord eq "image" && $level == 0} {
    # saw "image" at the toplevel.
    if {[lindex $statement 1] eq {create}} {
      set procname "[lrange $statement 2 3]"
      regsub -all {\$} $procname {\\$} procname
      regsub -all {_} $procname {\\_} procname 
      regsub -all {&} $procname {\\&} procname 
      regsub -all {\{} $procname {\{} procname 
      regsub -all {\}} $procname {\}} procname
      puts $o "\n\n\\noindent\\rule\{\\textwidth\}\{0.4pt\}"
      puts $o "\\section{image $procname}"
      puts $o ""
      return true
    }       
  }
  return false
}
          
    
  

proc tcl2tex::sectionHeading {procname params level} {
  variable o

#  puts stderr "*** sectionHeading $procname $params $level"

  # Replace some characters that need TeX escapes.
  regsub -all {\$} $procname {\\$} procname
  regsub -all {_} $procname {\\_} procname
  regsub -all {&} $procname {\\&} procname
  regsub -all {\{} $procname {\{} procname
  regsub -all {\}} $procname {\}} procname
  regsub -all {\$} $params {\\$} params
  regsub -all {_} $params {\\_} params
  regsub -all {&} $params {\\&} params
  regsub -all {\{} $params {\{} params
  regsub -all {\}} $params {\}} params

  switch $level {
    0 {
      puts $o "\\section\[$procname\]{$procname \\emph\{$params\}}"
    }
    1 {
      puts $o "\\vspace*{0.5cm}"
      puts $o "\\subsection\[$procname\]{$procname \\emph\{$params\}}"
    }
    2 {
      puts $o "\\vspace*{0.5cm}"
      puts $o "\\subsubsection\[$procname\]{$procname \\emph\{$params\}}"
    }
    3 {
      puts $o "\\vspace*{0.5cm}"
      puts $o "\\paragraph\[$procname\]{$procname \\emph\{$params\}}"
    }
  }
}



##### main ###############################################################

namespace eval tcl2tex {

  variable tagOn 0

  variable OPTIONS
  # Process the options. First set the defaults.
  set OPTIONS(forinput) 0
  set OPTIONS(stdout)   0

  variable FILES {}

  # Then scan the command line parameters. Assign known options to their
  # variable, yell if unknown options are encountered, and append all non-
  # option parameters into a list.
  foreach a $argv {
    switch -glob -- $a {
      -stdout {
        set OPTIONS(stdout) 1
      }
      -forinput {
        set OPTIONS(forinput) 1
      }
      -* {
        puts "Unknown option $a!"
        exit
      }
      default {
        lappend FILES $a
      }
    }; # switch
  }; # foreach

  if {$argc == 0} {
    puts "tcl2tex 2.0    (c) Deepwoods Software 2009"
    puts "Usage: tcl2tex \[-options\] <outputfile\[.tex\]> <inputfile> \[<inputfile>...\]"
    puts "Options:"
    puts "    -stdout     outputs to stdout"
    exit
  }

  if {$OPTIONS(stdout)} {
    set o stdout
  } else {
    set outputFile [forceExtension [lindex $FILES 0] "tex"]
    set o [open $outputFile w]
    set FILES [lrange $FILES 1 end]
  }

  # If not generating for input, output the LaTeX preamble etc.
  if {!$OPTIONS(forinput)} {
    puts $o "\\documentclass{book}"
    puts $o "\\begin{document}"
    puts $o "\\noindent \\emph\{This document was generated on"
    puts $o "[clock format [clock seconds]]"
    puts $o "by the \\texttt{tcl2tex} utility (version 1.4).\}"
    puts $o ""
    puts $o {\tableofcontents\newpage}
    puts $o ""
  }

  # Convert the files sequentially.
  foreach f $FILES {
    if {!$OPTIONS(stdout)} {
      puts "Converting $f..."
    }
    convert $f
  }; # foreach

  # If not generating for input, end the document.
  if {!$OPTIONS(forinput)} {
    puts $o {\vfill\centering - o - o - o -\vfill}
    puts $o "\\end{document}"
  }

  close $o

  # end of the program
}

