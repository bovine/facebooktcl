##################################################
#
# cgi.tcl - routines for writing CGI scripts in Tcl
# Author: Don Libes <libes@nist.gov>, January '95
#
# These routines implement the code described in the paper
# "Writing CGI scripts in Tcl" which appeared in the Tcl '96 conference.
# Please read the paper before using this code.  The paper is:
# http://www.cme.nist.gov/msid/pubs/libes96c.ps
#
##################################################

##################################################
# http header support
##################################################

proc cgi_http_head {args} {
    global _cgi env errorInfo

    if [info exists _cgi(http_head_done)] return

    set _cgi(http_head_in_progress) 1

    if {0 == [llength $args]} {
	cgi_content_type
    } else {
	if [catch {uplevel [lindex $args 0]} errMsg] {
	    set savedInfo $errorInfo
	    cgi_content_type
	}
    }
    cgi_puts ""

    unset _cgi(http_head_in_progress)
    set _cgi(http_head_done) 1

    if [info exists savedInfo] {
	error $errMsg $savedInfo
    }
}

# avoid generating http head if not in CGI environment
# to allow generation of pure HTML files
proc cgi_http_head_implicit {} {
    global env

    if [info exists env(REQUEST_METHOD)] cgi_http_head
}

# If these are called manually, they automatically generate the extra newline

proc cgi_content_type {args} {
    global _cgi

    if 0==[llength $args] {
	set t text/html
    } else {
	set t [lindex $args 0]
    }

    if [info exists _cgi(http_head_in_progress)] {
	cgi_puts "Content-type: $t"
    } else {
	cgi_http_head "cgi_content_type $t"
    }
}

proc cgi_location {t} {
    global _cgi

    if [info exists _cgi(http_head_in_progress)] {
	cgi_puts "Location: $t"
    } else {
	cgi_http_head "cgi_location $t"
    }
}

proc cgi_target {t} {
    global _cgi

    if ![info exists _cgi(http_head_in_progress)] {
	error "cgi_target must be set from within cgi_http_head."
    }
    cgi_puts "Window-target: $t"
}

# Make client retrieve url in this many seconds ("client pull").
# With no 2nd arg, current url is retrieved.
proc cgi_refresh {seconds {url ""}} {
    global _cgi

    if ![info exists _cgi(http_head_in_progress)] {
	error "cgi_refresh must be set from within cgi_http_head.  Try using cgi_http_equiv instead."
    }
    cgi_puts "Refresh: $seconds"

    if {0==[string compare $url ""]} {
	cgi_puts "; URL: $url"
    }
}

# Example: cgi_pragma no-cache
proc cgi_pragma {arg} {
    global _cgi

    if ![info exists _cgi(http_head_in_progress)] {
	error "cgi_pragma must be set from within cgi_http_head."
    }
    cgi_puts "Pragma: $arg"
}

##################################################
# support for debugging or other crucial things we need immediately
##################################################

proc cgi_comment	{args}	{}	;# need this asap

proc cgi_html_comment	{args}	{
    regsub -all {>} $args {\&gt;} args
    cgi_puts "<!--[cgi_list_to_string $args] -->"
}

proc cgi_debug {args} {
    global _cgi

    set arg [lindex $args 0]
    if {$arg == "-on"} {
	set _cgi(debug) 1
	set args [lrange $args 1 end]
    } elseif {$arg == "-off"} {
	set _cgi(debug) 0
	set args [lrange $args 1 end]
    } elseif {[regexp "^-t" $arg]} {
	set old $_cgi(debug)
	set _cgi(debug) 1
	set args [lrange $args 1 end]
    } elseif {[regexp "^-noprint$" $arg]} {
	set noprint 1
	set args [lrange $args 1 end]
    }

    set arg [lindex $args 0]
    if {$arg == "--"} {
	set args [lrange $args 1 end]
    }

    if {[llength $args]} {
	if $_cgi(debug) {

	    cgi_close_tag
	    # force http head and open html, head, body
	    catch {
		if [info exists noprint] {
		    uplevel [lindex $args 0]
		} else {
		    cgi_html {
			cgi_head {
			    cgi_title "debugging before complete HTML head"
			}
			# force body open and leave open
			cgi_body_start
			uplevel [lindex $args 0]
			# bop back out to catch, so we don't close body
			error "ignore"
		    }
		}
	    }
	}
    }

    if [info exists old] {
	set _cgi(debug) $old
    }
}

proc cgi_uid_check {user} {
    # leave in so old scripts don't blow up
    if [regexp "^-off$" $user] return

    if {0==[catch {exec who am i} whoami]} {
	# skip over "host!"
	regexp "(.*!)?(\[^ \t]*)" $whoami dummy dummy whoami
	if {$whoami != "$user"} {
	    error \
"Warning: This CGI script expects to run with uid \"$user\".  However,
this script is running as \"$whoami\"."
	}
    }
} 

# print out elements of an array
# like Tcl's parray, but formatted for browser
proc cgi_parray {a {pattern *}} {
    upvar 1 $a array
    if ![array exists array] {
	error "\"$a\" isn't an array"
    }

    set maxl 0
    foreach name [lsort [array names array $pattern]] {
	if {[string length $name] > $maxl} {
	    set maxl [string length $name]
	}
    }
    cgi_preformatted {
	set maxl [expr {$maxl + [string length $a] + 2}]
	foreach name [lsort [array names array $pattern]] {
	    set nameString [format %s(%s) $a $name]
	    cgi_puts [cgi_quote_html [format "%-*s = %s" $maxl $nameString $array($name)]]
	}
    }
	
if 0 {
    cgi_puts "<xmp>"
    set maxl [expr {$maxl + [string length $a] + 2}]
    foreach name [lsort [array names array $pattern]] {
	set nameString [format %s(%s) $a $name]
	cgi_puts [format "%-*s = %s" $maxl $nameString $array($name)]
    }
    cgi_puts "</xmp>"
}
}

proc cgi_eval {cmd} {
    global env _cgi

    # put cmd somewhere that uplevel can find it
    set _cgi(body) $cmd

    uplevel #0 {
	if 1==[catch $_cgi(body)] {
	    # error occurred, handle it

	    set _cgi(errorInfo) $errorInfo

	    # the following code is all to force browsers into a state
	    # such that diagnostics can be reliably shown

	    # close irrelevant things
	    cgi_close_procs
	    # force http head and open html, head, body
	    cgi_html {
		cgi_body {
		    cgi_h3 "An internal error was detected in the service\
			    software.  The diagnostics are being emailed to\
			    the service system administrator ($_cgi(admin_email))."

		    if $_cgi(debug) {
			cgi_puts "Heck, since you're debugging, I'll show you the\
				errors right here:"
			# suppress formatting
			cgi_preformatted {
			    cgi_puts [cgi_quote_html $_cgi(errorInfo)]
			}
		    } else {
			cgi_mail_start $_cgi(admin_email)
			cgi_mail_add "Subject: [cgi_name] CGI problem"
			cgi_mail_add
			if {[info exists env(REQUEST_METHOD)]} {
			    cgi_mail_add "CGI environment:"
			    cgi_mail_add "REQUEST_METHOD: $env(REQUEST_METHOD)"
			    cgi_mail_add "SCRIPT_NAME: $env(SCRIPT_NAME)"
			    # this next few things probably don't need
			    # a catch but I'm not positive
			    catch {cgi_mail_add "HTTP_USER_AGENT: $env(HTTP_USER_AGENT)"}
			    catch {cgi_mail_add "REMOTE_ADDR: $env(REMOTE_ADDR)"}
			    catch {cgi_mail_add "REMOTE_HOST: $env(REMOTE_HOST)"}
			}
			cgi_mail_add "cgi.tcl version: 0.6.4"
			cgi_mail_add "input:"
			catch {cgi_mail_add $_cgi(input)}
			cgi_mail_add "cookie:"
			catch {cgi_mail_add $env(HTTP_COOKIE)}
			cgi_mail_add "errorInfo:"
			cgi_mail_add "$_cgi(errorInfo)"
			cgi_mail_end
		    }
		} ;# end cgi_body
	    } ;# end cgi_html
	} ;# end catch
    } ;# end uplevel
}

# return true if cgi_eval caught an error
proc cgi_error_occurred {} {
    global _cgi

    return [info exists _cgi(errorInfo)]
}

##################################################
# CGI URL creation
##################################################

# declare location of root of CGI files
# this allows all CGI references to be relative in the source
# making it easy to move everything in the future
# If you have multiple roots, just don't call this.
proc cgi_root {args} {
    global _cgi

    if {[llength $args]} {
	set _cgi(root) [lindex $args 0]
    } else {
	set _cgi(root)
    }
}

# make a URL for a CGI script
proc cgi_cgi {args} {
    global _cgi

    set root $_cgi(root)
    if 0!=[string compare $root ""] {
	if ![regexp "/$" $root] {
		append root "/"
	}
    }
		
    if [llength $args]==1 {
	return $root[lindex $args 0].cgi
    } else {
	return $root[lindex $args 0].cgi?[join [lrange $args 1 end] &]
    }
}

proc cgi_cgi_set {variable value} {
    regsub -all {%}  $value "%25" value
    regsub -all {&}  $value "%26" value
    regsub -all {\+} $value "%2b" value
    regsub -all { }  $value "+"   value
    return $variable=$value
}

##################################################
# URL dictionary support
##################################################

proc cgi_link {args} {
    global _cgi_link

    set tag [lindex $args 0]
    if {[llength $args] >= 3} {
	set _cgi_link($tag) [eval cgi_url [lrange $args 1 end]]
    }
    return $_cgi_link($tag)
}

# same as above but for images
# note: uses different namespace
proc cgi_imglink {args} {
    global _cgi_imglink

    set tag [lindex $args 0]
    if {[llength $args] >= 2} {
	set _cgi_imglink($tag) [eval cgi_img [lrange $args 1 end]]
    }
    return $_cgi_imglink($tag)
}

##################################################
# hyperlink support
##################################################

# construct a hyperlink labeled "display"
# last arg is the link destination
# any other args are passed through into <a> display
proc cgi_url {display args} {
    set buf "<a href=\"[lindex $args 0]\""
    foreach a [lrange $args 1 end] {
	if {[regexp "^(target|onClick|onMouseOver|onMouseOut)=(.*)" $a dummy attr str]} {
	    append buf " $attr=\"$str\""
	} else {
	    append buf " $a"
	}
    }
    return "$buf>$display</a>"
}

# fetch a url via http
# only supported under Tcl 7.5 or higher
proc cgi_http_get {url} {
    regexp {^(http://)?([^:/]+)(:([0-9]*))?/?(.*)} $url dummy \
	      http      host    : port    file
    if ![string length $port] {
	set port 80
    }
    set socket [socket $host $port]
    fconfigure $socket -buffering line
    puts $socket "GET /$file\n\r"
    set data [read $socket]
    close $socket
    return $data
}

# generate an image reference (<img ...>)
# first arg is image url
# other args are passed through into <img> tag
proc cgi_img {args} {
    set buf "<img src=\"[lindex $args 0]\""
    foreach a [lrange $args 1 end] {
	if {[regexp "^(alt|width|height|lowsrc|usemap)=(.*)" $a dummy attr str]} {
	    append buf " $attr=[cgi_dquote_html $str]"
	} elseif {[regexp "^onError" $a dummy str]} {
	    append buf " onError=\"$str\""
	} else {
	    append buf " $a"
	}
    }
    return "$buf>"
}

# names an anchor so that it can be linked to
proc cgi_anchor_name {name} {
    cgi_puts "<a name=\"$name\">"
}

proc cgi_base {args} {
    cgi_put "<base"
    foreach a $args {
	if {[regexp "^href=(.*)" $a dummy str]} {
	    cgi_put " href=[cgi_dquote_html $str]"
	} elseif {[regexp "^target=(.*)" $a dummy str]} {
	    cgi_put " target=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}

##################################################
# quoting support
##################################################

proc cgi_unquote_input {buf} {
    # rewrite "+" back to space
    regsub -all {\+} $buf { } buf
    # protect \ from quoting another \ and throwing off other things (first!)
    # protect $ from doing variable expansion
    # protect [ from doing evaluation
    # protect " from terminating string
    regsub -all {([\\["$])} $buf {\\\1} buf

    # replace line delimiters with newlines
    regsub -all -nocase "%0d%0a" $buf "\n" buf
    # Mosaic sends just %0A.  This is handled in the next command.

    # prepare to process all %-escapes 
    regsub -all -nocase {%([a-f0-9][a-f0-9])} $buf {[format %c 0x\1]} buf
    # process %-escapes and undo all protection
    eval return \"$buf\"
}

# return string but with html-special characters escaped,
# necessary if you want to send unknown text to an html-formatted page.
proc cgi_quote_html {s} {
    regsub -all {&}	$s {\&amp;}	s	;# must be first!
    regsub -all {"}	$s {\&quot;}	s
    regsub -all {<}	$s {\&lt;}	s
    regsub -all {>}	$s {\&gt;}	s
    return $s
}

proc cgi_dquote_html {s} {
    return \"[cgi_quote_html $s]\"
}

# return string quoted appropriately to appear in a url
proc cgi_quote_url {in} {
    regsub -all {%}  $in "%25" in
    regsub -all { }  $in "%20" in
    regsub -all {\?} $in "%3f" in
    return $in
}

##################################################
# short or single paragraph support
##################################################

proc cgi_br {args} {
    cgi_put "<br"
    if [llength $args] {
	cgi_put "[cgi_list_to_string $args]"
    }
    cgi_puts ">"
}

# generate cgi_h1 and others
for {set i 1} {$i<8} {incr i} {
    proc cgi_h$i {{args}} "eval cgi_h $i \$args"
}
proc cgi_h {num args} {
    cgi_put "<h$num"
    if {[llength $args] > 1} {
	cgi_put "[cgi_lrange $args 0 [expr [llength $args]-2]]"
	set args [lrange $args end end]
    }
    cgi_puts ">[lindex $args 0]</h$num>"
}

proc cgi_p {args} {
    cgi_put "<p"
    if {[llength $args] > 1} {
	cgi_put "[cgi_lrange $args 0 [expr [llength $args]-2]]"
	set args [lrange $args end end]
    }
    cgi_puts ">[lindex $args 0]</p>"
}

proc cgi_address      {s} {cgi_puts <address>$s</address>}
proc cgi_blockquote   {s} {cgi_puts <blockquote>$s</blockquote>}

##################################################
# long or multiple paragraph support
##################################################

# Shorthand for <div align=center>
proc cgi_center	{cmd}	{
    cgi_puts <center>
    cgi_close_proc_push "cgi_puts </center>"
    uplevel $cmd
    cgi_close_proc
}

proc cgi_division {args} {
    cgi_put "<div"
    cgi_close_proc_push "cgi_puts </div>"

    if {[llength $args]} {
	cgi_put "[cgi_lrange $args 0 [expr [llength $args]-2]]"
    }
    cgi_puts ">"
    uplevel [lindex $args end]
    cgi_close_proc
}

proc cgi_preformatted {args} {
    cgi_put "<pre"
    cgi_close_proc_push "cgi_puts </pre>"

    if {[llength $args]} {
	cgi_put "[cgi_lrange $args 0 [expr [llength $args]-2]]"
    }
    cgi_puts ">"
    uplevel [lindex $args end]
    cgi_close_proc
}

##################################################
# list support
##################################################

proc cgi_li {args} {
    cgi_put <li
    if {[llength $args] > 1} {
	cgi_put "[cgi_lrange $args 0 [expr [llength $args]-2]]"
    }
    cgi_puts ">[lindex $args end]"
}

proc cgi_number_list {args} {
    cgi_put "<ol"
    cgi_close_proc_push "cgi_puts </ol>"

    if {[llength $args] > 1} {
	cgi_put "[cgi_lrange $args 0 [expr [llength $args]-2]]"
    }
    cgi_puts ">"
    uplevel [lindex $args end]

    cgi_close_proc
}

proc cgi_bullet_list {args} {
    cgi_put "<ul"
    cgi_close_proc_push "cgi_puts </ul>"

    if {[llength $args] > 1} {
	cgi_put "[cgi_lrange $args 0 [expr [llength $args]-2]]"
    }
    cgi_puts ">"
    uplevel [lindex $args end]

    cgi_close_proc
}

# Following two are normally used from within definition lists
# but are actually paragraph types on their own.
proc cgi_term            {s} {cgi_puts <dt>$s}
proc cgi_term_definition {s} {cgi_puts <dd>$s}

proc cgi_definition_list {cmd} {
    cgi_puts "<dl>"
    cgi_close_proc_push "cgi_puts </dl>"

    uplevel $cmd
    cgi_close_proc
}

proc cgi_menu_list {cmd} {
    cgi_puts "<menu>"
    cgi_close_proc_push "cgi_puts </menu>"

    uplevel $cmd
    cgi_close_proc
}
proc cgi_directory_list {cmd} {
    cgi_puts "<dir>"
    cgi_close_proc_push "cgi_puts </dir>"

    uplevel $cmd
    cgi_close_proc
}

##################################################
# text support
##################################################

proc cgi_put	    {s} {cgi_puts -nonewline $s}

# some common special characters
proc cgi_lt	     {}  {return "&lt;"}
proc cgi_gt	     {}  {return "&gt;"}
proc cgi_amp	     {}  {return "&amp;"}
proc cgi_quote	     {}  {return "&quot;"}
proc cgi_enspace     {}  {return "&ensp;"}
proc cgi_emspace     {}  {return "&emsp;"}
proc cgi_nbspace     {}  {return "&nbsp;"} ;# nonbreaking space
proc cgi_tm	     {}  {return "&#174;"} ;# registered trademark
proc cgi_copyright   {}  {return "&#169;"}
proc cgi_isochar     {n} {return "&#$n;"}
proc cgi_breakable   {}  {return "<wbr>"}

proc cgi_unbreakable_string {s} {return "<nobr>$s</nobr>"}
proc cgi_unbreakable {cmd} {
    cgi_puts "<nobr>"
    cgi_close_proc_push "cgi_puts </nobr>"
    uplevel $cmd
    cgi_close_proc
}

proc cgi_nl          {args} {
    set buf "<br"
    if [llength $args] {
	append buf "[cgi_list_to_string $args]"
    }
    return "$buf>"
}

proc cgi_bold	    {s} {return "<b>$s</b>"}
proc cgi_italic     {s} {return "<i>$s</i>"}
proc cgi_underline  {s} {return "<u>$s</u>"}
proc cgi_strikeout  {s} {return "<s>$s</s>"}
proc cgi_subscript  {s} {return "<sub>$s</sub>"}
proc cgi_superscript {s} {return "<sup>$s</sup>"}
proc cgi_typewriter {s} {return "<tt>$s</tt>"}
proc cgi_blink	    {s} {return "<blink>$s</blink>"}
proc cgi_emphasis   {s} {return "<em>$s</em>"}
proc cgi_strong	    {s} {return "<strong>$s</strong>"}
proc cgi_cite	    {s} {return "<cite>$s</cite>"}
proc cgi_sample     {s} {return "<samp>$s</samp>"}
proc cgi_keyboard   {s} {return "<kbd>$s</kbd>"}
proc cgi_variable   {s} {return "<var>$s</var>"}
proc cgi_definition {s} {return "<dfn>$s</dfn>"}
proc cgi_big	    {s} {return "<big>$s</big>"}
proc cgi_small	    {s} {return "<small>$s</small>"}

proc cgi_basefont   {size} {cgi_puts "<basefont size=$size>"}

proc cgi_font {args} {
    set buf "<font"
    foreach a [lrange $args 0 [expr [llength $args]-2]] {
	if {[regexp "^color=(.*)" $a dummy str]} {
	    append buf " color=\"$str\""
	} else {
	    append buf " $a"
	}
    }
    return "$buf>[lindex $args end]</font>"
}

##################################################
# html and tags that can appear in html top-level
##################################################

proc cgi_html {html} {
    cgi_html_start
    uplevel $html
    cgi_html_end
}

proc cgi_html_start {} {
    global _cgi
    
    if [info exists _cgi(html_in_progress)] return
    cgi_http_head_implicit

    set _cgi(html_in_progress) 1
    cgi_doctype
    cgi_puts "<html>"
}

proc cgi_html_end {} {
    global _cgi
    unset _cgi(html_in_progress)
    set _cgi(html_done) 1
    cgi_puts "</html>"
}

# force closure of all tags and exit without going through normal returns.
# Very useful if you want to call exit from a deeply stacked CGI script
# and still have the HTML be correct.
proc cgi_exit {} {
    cgi_close_procs
    cgi_html {cgi_body {}}
    exit
}

##################################################
# head support
##################################################

proc cgi_head {{head {}}} {
    global _cgi

    if [info exists _cgi(head_done)] {
	return
    }

    # allow us to be recalled so that we can display errors
    if ![info exists _cgi(head_in_progress)] {
	cgi_http_head_implicit
	set _cgi(head_in_progress) 1
	cgi_puts "<head>"
    }

    # prevent cgi_html (during error handling) from generating html tags
    set _cgi(html_in_progress) 1
    # don't actually generate html tags since there's nothing to clean
    # them up

    if {0 == [string length $head]} {
	if {[catch {cgi_title}]} {
	    set head "cgi_title untitled"
	}
    }
    uplevel $head
    if ![info exists _cgi(head_suppress_tag)] {
	cgi_puts "</head>"
    } else {
	unset _cgi(head_suppress_tag)
    }

    set _cgi(head_done) 1

    # debugging can unset this in the uplevel above
    catch {unset _cgi(head_in_progress)}
}

# with one arg: set, print, and return title
# with no args: return title
proc cgi_title {args} {
    global _cgi

    cgi_http_head_implicit

    # we could just generate <head></head> tags, but  head-level commands
    # might follow so just suppress the head tags entirely
    if ![info exists _cgi(head_in_progress)] {
	set _cgi(head_in_progress) 1
	set _cgi(head_suppress_tag) 1
    }

    set title [lindex $args 0]

    if {[llength $args]} {
	set _cgi(title) $title
	cgi_puts "<title>$title</title>"
    }
    return $_cgi(title)
}

# This tag can only be called from with cgi_head.
# example: cgi_http_equiv Refresh 1
# There's really no reason to call this since it can be done directly
# from cgi_http_head.
proc cgi_http_equiv {type contents} {
    cgi_http_head_implicit
    cgi_puts "<meta http-equiv=\"$type\" content=[cgi_dquote_html $contents]>"
}

# Do whatever you want with meta tags.
# Example: <meta name="author" content="Don Libes">
proc cgi_meta {args} {
    cgi_put "<meta"
    foreach a $args {
	if {[regexp "^(name|content|http-equiv)=(.*)" $a dummy attr str]} {
	    cgi_put " $attr=[cgi_dquote_html $str]"
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}

proc cgi_relationship {rel href args} {
    cgi_puts "<link rel=\"$rel\" href=\"$href\""
    foreach a $args {
	if {[regexp "^title=(.*)" $a dummy str]} {
	    cgi_put " title=[cgi_dquote_html $str]"
	} else {
	    cgi_put " $a"
	}
    }
    cgi_put ">"
}

proc cgi_name {args} {
    global _cgi

    if [llength $args] {
	set _cgi(name) [lindex $args 0]
    }
    return $_cgi(name)
}

##################################################
# body and other top-level support
##################################################

proc cgi_body {args} {
    global errorInfo _cgi

    # allow user to "return" from the body without missing cgi_body_end
    if 1==[catch {
	eval cgi_body_start [lrange $args 0 [expr [llength $args]-2]]
	uplevel [lindex $args end]
    } errMsg] {
	set savedInfo $errorInfo
	error $errMsg $savedInfo
    }
    cgi_body_end
}

proc cgi_body_start {args} {
    global _cgi
    if [info exists _cgi(body_in_progress)] return

    cgi_head

    set _cgi(body_in_progress) 1

    if {[string compare "$_cgi(body_args)" {{}}] == 0} {set _cgi(body_args) {}}
    cgi_html_comment "*** llength $_cgi(body_args) = [llength $_cgi(body_args)]"
    cgi_put "<body"
    
    if {[string length "$_cgi(body_args)"] > 0} {
    	set allargs [string trim "$args $_cgi(body_args)"]
    } else {
    	set allargs "$args"
    }
    foreach a "$allargs" {
	if {[regexp "^(background|bgcolor|text|link|vlink|alink|onLoad|onUnload)=(.*)" $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"

    cgi_html_comment "*** allargs = \"$allargs\""
#    cgi_uid_check nobody
    cgi_debug {
	global env
	catch {cgi_puts "Input: <pre>$_cgi(input)</pre>"}
	catch {cgi_puts "Cookie: <pre>$env(HTTP_COOKIE)</pre>"}
    }

    if ![info exists _cgi(errorInfo)] {
	uplevel 2 app_body_start
    }
}

proc cgi_body_end {} {
    global _cgi
    if ![info exists _cgi(errorInfo)] {
	uplevel 2 app_body_end
    }
    unset _cgi(body_in_progress)
    cgi_puts "</body>"
}

proc cgi_body_args {args} {
    global _cgi

    set _cgi(body_args) $args
}

proc cgi_script {args} {
    cgi_puts "<script[cgi_lrange $args 0 [expr [llength $args]-2]]>"
    cgi_close_proc_push "cgi_puts </script>"

    uplevel [lindex $args end]

    cgi_close_proc
}

proc cgi_javascript {args} {
    cgi_puts "<script[cgi_lrange $args 0 [expr [llength $args]-2]]>"
    cgi_puts "<!--- Hide script from browsers that don't understand JavaScript"
    cgi_close_proc_push {cgi_puts "// End hiding -->\n</script>"}

    uplevel [lindex $args end]

    cgi_close_proc
}

proc cgi_noscript {args} {
    cgi_puts "<noscript[cgi_lrange $args 0 [expr [llength $args]-2]]>"
    cgi_close_proc_push {puts "</noscript>"}

    uplevel [lindex $args end]

    cgi_close_proc
}

proc cgi_applet {args} {
    cgi_puts "<applet[cgi_lrange $args 0 [expr [llength $args]-2]]>"
    cgi_close_proc_push "cgi_puts </applet>"

    uplevel [lindex $args end]
    cgi_close_proc
}

proc cgi_param {nameval} {
    regexp "(\[^=]*)(=?)(.*)" $nameval dummy name q value

    if {$q != "="} {
	set value ""
    }
    cgi_puts "<param name=\"$name\" value=[cgi_dquote_html $value]>"
}

# record any proc's that must be called prior to displaying an error
proc cgi_close_proc_push {p} {
    global _cgi
    if ![info exists _cgi(close_proc)] {
	set _cgi(close_proc) ""
    }
    set _cgi(close_proc) "$p; $_cgi(close_proc)"
}

proc cgi_close_proc_pop {} {
    global _cgi
    regexp "^(\[^;]*);(.*)" $_cgi(close_proc) dummy lastproc _cgi(close_proc)
    return $lastproc
}

# generic proc to close whatever is on the top of the stack
proc cgi_close_proc {} {
    eval [cgi_close_proc_pop]
}

proc cgi_close_procs {} {
    global _cgi

    cgi_close_tag
    if [info exists _cgi(close_proc)] {
	uplevel #0 $_cgi(close_proc)
    }
}

proc cgi_close_tag {} {
    global _cgi

    if [info exists _cgi(tag_in_progress)] {
	cgi_puts ">"
	unset _cgi(tag_in_progress)
    }
}

##################################################
# hr support
##################################################

proc cgi_hr {args} {
    global _cgi

    cgi_put "<hr"
    if [llength $args] {
	cgi_put "[cgi_list_to_string $args]"
    }
    cgi_puts ">"
}

##################################################
# form & isindex
##################################################

proc cgi_form {action args} {
    global _cgi

    cgi_form_multiple_check
    set _cgi(form_in_progress) 1

    cgi_close_proc_push cgi_form_end
    cgi_put "<form action="
    if [regexp {^[a-z]*:} $action] {
	cgi_put "\"$action\""
    } else {
	cgi_put "\"[cgi_cgi $action]\""
    }
    set method "method=post"
    foreach a [lrange $args 0 [expr [llength $args]-2]] {
	if {[regexp "^method=" $a]} {
	    set method $a
	} elseif {[regexp "^(target|enctype|onReset|onSubmit)=(.*)" $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts " $method>"
    uplevel [lindex $args end]
    cgi_close_proc
}

proc cgi_form_end {} {
    global _cgi
    unset _cgi(form_in_progress)
    cgi_puts "</form>"
}

proc cgi_form_multiple_check {} {
    global _cgi
    if [info exists _cgi(form_in_progress)] {
	error "Cannot create form (or isindex) with form already in progress."
    }
}

proc cgi_isindex {args} {
    cgi_form_multiple_check

    cgi_put "<isindex"
    foreach a $args {
	if {[regexp "^href=(.*)" $a dummy str]} {
	    cgi_put " href=\"$str\""
	} elseif {[regexp "^prompt=(.*)" $a dummy str]} {
	    cgi_put " prompt=[cgi_dquote_html $str]"
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}

##################################################
# argument handling
##################################################

proc cgi_input {{fakeinput {}} {fakecookie {}}} {
    global env _cgi _cgi_uservar _cgi_cookie _cgi_cookie_shadowed

    set _cgi(uservars) {}

    if {[info exists env(CONTENT_TYPE)] && [regexp ^multipart/form-data $env(CONTENT_TYPE)]} {
	if {![info exists env(REQUEST_METHOD)]} {
	    # running by hand
	    set fid [open $fakeinput]
	} else {
	    set fid stdin
	}
	if {[catch exp_version] || [info exists _cgi(no_binary_upload)]} {
	    cgi_input_multipart $fid
	} else {
	    cgi_input_multipart_binary $fid
	}
    } else {
	if {![info exists env(REQUEST_METHOD)]} {
	    set input $fakeinput
	    set env(HTTP_COOKIE) $fakecookie
	} elseif { $env(REQUEST_METHOD) == "GET" } {
	    set input ""
	    catch {set input $env(QUERY_STRING)} ;# doesn't have to be set
	} elseif { $env(REQUEST_METHOD) == "HEAD" } {
	    set input ""
	} elseif {![info exists env(CONTENT_LENGTH)]} {
	    error "unexpected server behavior: CONTENT_LENGTH undefined, please report this to the http administrator"
	} else {
	    set length $env(CONTENT_LENGTH)
	    if {0!=[string compare $length "-1"]} {
		set input [read stdin $env(CONTENT_LENGTH)]		
	    } else {
		error "unexpected server behavior: CONTENT_LENGTH = -1, please report this to the http administrator"
	    }
	}
	# save input for possible diagnostics later
	set _cgi(input) $input

	set pairs [split $input &]
	foreach pair $pairs {
	    if {0 == [regexp (.*)=(.*) $pair dummy varname val]} {
		# if no match, unquote and leave it at that
		# this is typical of <isindex>-style queries
		set varname anonymous
		set val $pair
	    }

	    set varname [cgi_unquote_input $varname]
	    set val [cgi_unquote_input $val]
	    cgi_set_uservar $varname $val
	}
    }

    # O'Reilly's web server incorrectly uses COOKIE
    catch {set env(HTTP_COOKIE) $env(COOKIE)}
    if ![info exists env(HTTP_COOKIE)] return
    foreach pair [split $env(HTTP_COOKIE) ";"] {
	# pairs are actually split by "; ", sigh
	set pair [string trimleft $pair " "]
	# spec is not clear but seems to allow = unencoded
	# only sensible interpretation is to assume no = in var names
	regexp (\[^=]*)=(.*) $pair dummy varname val

	set varname [cgi_unquote_input $varname]
	set val [cgi_unquote_input $val]

	if [info exists _cgi_cookie($varname)] {
	    lappend _cgi_cookie_shadowed($varname) $val
	} else {
	    set _cgi_cookie($varname) $val
	}
    }
}

proc cgi_input_multipart {fin} {
    global env _cgi _cgi_uservar _cgi_userfile

    cgi_debug -noprint {
	# save file for debugging purposes
	set dbg_filename /tmp/CGIdbg.[pid]
	# explicitly flush all writes to fout, because sometimes the writer
	# can hang and we won't get to the termination code
	set dbg_fout [open $dbg_filename w]
	set _cgi(input) $dbg_filename
	catch {fconfigure $dbg_fout -translation binary}
    }

    # figure out boundary
    if 0==[regexp boundary=(.*) $env(CONTENT_TYPE) dummy boundary] {
	error "could not find \"boundary=\" in CONTENT_TYPE: $env(CONTENT_TYPE)"
    }
    set boundary --$boundary

    # don't corrupt or modify uploads yet allow Tcl 7.4 to work
    catch {fconfigure $fin -translation binary}

    # get first boundary line
    gets $fin buf
    if [info exists dbg_fout] {puts $dbg_fout $buf; flush $dbg_fout}

    set filecount 0
    while 1 {
	# process Content-Disposition:
	if {-1 == [gets $fin buf]} break
	if [info exists dbg_fout] {puts $dbg_fout $buf; flush $dbg_fout}
	catch {unset filename}
	foreach b $buf {
	    regexp {^name="(.*)"} $b dummy varname
	    regexp {^filename="(.*)"} $b dummy filename
	}

	# Skip remaining headers until blank line.
	# Content-Type: can appear here.  Ignore it.
	while 1 {
	    if {-1 == [gets $fin buf]} break
	    if [info exists dbg_fout] {puts $dbg_fout $buf; flush $dbg_fout}
	    if {0==[string compare $buf "\r"]} break
	}

	if {[info exists filename]} {
	    # read the part into a file
	    set foutname /tmp/CGI[pid].[incr filecount]
	    set fout [open $foutname w]
	    # "catch" permits this to work with Tcl 7.4
	    catch {fconfigure $fout -translation binary}
	    cgi_set_uservar $varname [list $foutname $filename]
	    set _cgi_userfile($varname) [list $foutname $filename]

	    # This is tricky stuff - be very careful changing anything here!
	    # The problems is that we have to look for TWO lines before
	    # being able to decide whether we're at the end.  So we must
	    # buffer each empty line and wait for the next before deciding
	    # what to do.

	    # crlf	== "\r\n" if we've seen one, else == ""
	    #           Yes, strange, but so much more efficient
	    #		that I'm willing to sacrifice readability, sigh.

	    set crlf ""
	    while 1 {
		if {-1 == [gets $fin buf]} break
		if [info exists dbg_fout] {puts $dbg_fout $buf; flush $dbg_fout}

		if {[regexp ^\r$ $buf]} {
		    if {$crlf == "\r\n"} {
			puts $fout $crlf
		    }
		    set crlf \r\n
		    continue
		}		
		if {[regexp ^[set boundary](--)?\r$ $buf dummy dashdash]} {
		    if {$dashdash == "--"} {set eof 1}
		    break
		}
		puts $fout $crlf$buf
		set crlf ""
	    }
	    close $fout
	    unset fout
	} else {
	    # read the part into a variable
	    set val ""
	    while 1 {
		if {-1 == [gets $fin buf]} break
		if [info exists dbg_fout] {puts $dbg_fout $buf; flush $dbg_fout}
		if {[regexp ^[set boundary](--)?\r$ $buf dummy dashdash]} {
		    if {$dashdash == "--"} {set eof 1}
		    break
		}
		regexp (.*)\r$ $buf dummy buf
		append val $buf
	    }
	    cgi_set_uservar $varname $val
	}
        if [info exists eof] break
    }
    if [info exists dbg_fout] {close $dbg_fout}
}

proc cgi_input_multipart_binary {fin} {
    global env _cgi _cgi_uservar _cgi_userfile

    log_user 0

    cgi_debug -noprint {
	# save file for debugging purposes
	set dbg_filename /tmp/CGIdbg.[pid]
	set _cgi(input) $dbg_filename
	spawn -open [open $dbg_filename w]
	set dbg_sid $spawn_id
    }
    spawn -open $fin
    set fin_sid $spawn_id
    remove_nulls 0

    if 0 {
	# dump input to screen
	cgi_debug {
	    puts "<xmp>"
	    expect {
		-i $fin_sid
		-re ^\r {puts -nonewline "CR"; exp_continue}
		-re ^\n {puts "NL"; exp_continue}
		-re . {puts -nonewline $expect_out(buffer); exp_continue}
	    }
	    puts "</xmp>"
	    exit
	}
    }

    # figure out boundary
    if 0==[regexp boundary=(.*) $env(CONTENT_TYPE) dummy boundary] {
	error "could not find \"boundary=\" in CONTENT_TYPE: $env(CONTENT_TYPE)"
    }

    set boundary --$boundary
    set linepat "(\[^\r]*)\r\n"

    # get first boundary line
    expect -i $fin_sid -re $linepat {
	set buf $expect_out(1,string)
	if [info exists dbg_sid] {send -i $dbg_sid -- $buf\n}
    }

    set filecount 0
    while 1 {
	# process Content-Disposition:
	expect {
	    -i $fin_sid
	    -re $linepat {
		set buf $expect_out(1,string)
		if [info exists dbg_sid] {send -i $dbg_sid -- $buf\n}
	    }
	    eof break
	}
	catch {unset filename}
	foreach b $buf {
	    regexp {^name="(.*)"} $b dummy varname
	    regexp {^filename="(.*)"} $b dummy filename
	}

	# Skip remaining headers until blank line.
	# Content-Type: can appear here.  Ignore it.
	expect {
	    -i $fin_sid
	    -re $linepat {
		set buf $expect_out(1,string)
		if [info exists dbg_sid] {send -i $dbg_sid -- $buf\n}
		if 0!=[string compare $buf ""] exp_continue
	    }
	    eof break
	}

	if {[info exists filename]} {
	    # read the part into a file
	    set foutname /tmp/CGI[pid].[incr filecount]
	    spawn -open [open $foutname w]
	    set fout_sid $spawn_id

	    cgi_set_uservar $varname [list $foutname $filename]
	    set _cgi_userfile($varname) [list $foutname $filename]

	    # This is tricky stuff - be very careful changing anything here!
	    # In theory, all we have to is record everything up to
	    # \r\n$boundary\r\n.  Unfortunately, we can't simply wait on
	    # such a pattern because the input can overflow any possible
	    # buffer we might choose.  We can't simply catch buffer_full
	    # because the boundary might straddle a buffer.  I doubt that
	    # doing my own buffering would be any faster than taking the
	    # approach I've done here.
	    #
	    # The code below basically implements a simple scanner that
	    # keeps track of whether it's seen crlfs or pieces of them.
	    # The idea is that we look for crlf pairs, separated by
	    # things that aren't crlfs (or pieces of them).  As we encounter
	    # things that aren't crlfs (or pieces of them), or when we decide
	    # they can't be, we mark them for output and resume scanning for
	    # new pairs.
	    #
	    # The scanner runs tolerably fast because the [...]+ pattern picks
	    # up most things.  The \r and \n are ^-anchored so the pattern
	    # match is pretty fast and these don't happen that often so the
	    # huge \n action is executed rarely (once per line on text files).
	    # The null pattern is, of course, only used when everything
	    # else fails.

	    # crlf	== "\r\n" if we've seen one, else == ""
	    # cr	== "\r" if we JUST saw one, else == ""
	    #           Yes, strange, but so much more efficient
	    #		that I'm willing to sacrifice readability, sigh.
	    # buf	accumulated data between crlf pairs

	    set buf ""
	    set cr ""
	    set crlf ""

	    expect {
		-i $fin_sid
		-re "^\r" {
		    if {$cr == "\r"} {
			append buf "\r"
		    }
		    set cr \r
		    exp_continue
		} -re "^\n" {
		    if {$cr == "\r"} {
			if {$crlf == "\r\n"} {
			    # do boundary test
			    if {[regexp ^[set boundary](--)?$ $buf dummy dashdash]} {
				if {$dashdash == "--"} {
				    set eof 1
				}
			    } else {
				# boundary test failed
				if [info exists dbg_sid] {send -i $dbg_sid -- \r\n$buf}
				send -i $fout_sid \r\n$buf ; set buf ""
				set cr ""
				exp_continue
			    }
			} else {
			    set crlf "\r\n"
			    set cr ""
			    if [info exists dbg_sid] {send -i $dbg_sid -- $buf}
			    send -i $fout_sid -- $buf ; set buf ""
			    exp_continue
			}
		    } else {
			if [info exists dbg_sid] {send -i $dbg_sid -- $crlf$buf\n}
			send -i $fout_sid -- $crlf$buf\n ; set buf ""
			set crlf ""
			exp_continue
		    }
		} -re "\[^\r\n]+" {
		    if {$cr == "\r"} {
			set buf $crlf$buf\r$expect_out(buffer)
			set crlf ""
			set cr ""
		    } else {
			append buf $expect_out(buffer)
		    }
		    exp_continue
		} null {
		    if [info exists dbg_sid] {
			send -i $dbg_sid -- $crlf$buf$cr
			send -i $dbg_sid -null
		    }
		    send -i $fout_sid -- $crlf$buf$cr ; set buf ""
		    send -i $fout_sid -null
		    set cr ""
		    set crlf ""
		    exp_continue
		}
	    }
	    exp_close -i $fout_sid    ;# implicitly closes fout
	    exp_wait -i $fout_sid
	    unset fout_sid
	} else {
	    # read the part into a variable
	    set val ""
	    expect {
		-i $fin_sid
		-re $linepat {
		    set buf $expect_out(1,string)
		    if [info exists dbg_sid] {send -i $dbg_sid -- $buf\n}
		    if {[regexp ^[set boundary](--)?$ $buf dummy dashdash]} {
			if {$dashdash == "--"} {set eof 1}
		    } else {
			regexp (.*)\r$ $buf dummy buf
			append val $buf
			exp_continue
		    }
		}
	    }
	    cgi_set_uservar $varname $val
	}	    
        if [info exists eof] break
    }
    if [info exists fout] {
	exp_close -i $dbg_sid
	exp_wait -i $dbg_sid
    }

    # no need to close fin, fin_sid, or dbg_sid
}

# internal routine for defining user variables
proc cgi_set_uservar {varname val} {
    global _cgi _cgi_uservar

    set exists [info exists _cgi_uservar($varname)]

    if $exists {
	lappend _cgi(uservars) $varname
    }

    # handle lists of values correctly
    if [regexp List$ $varname] {
	lappend _cgi_uservar($varname) $val
    } else {
	if $exists {
	    error "Multiple definitions of $varname encountered in input.
	    If you're trying to do this intentionally (such as with select),
	    the variable must have a \"List\" suffix."
	} else {
	    set _cgi_uservar($varname) $val
	    lappend _cgi(uservars) $varname
	}
    }
}

# export named variable
proc cgi_export {nameval} {
    regexp "(\[^=]*)(=?)(.*)" $nameval dummy name q value

    if {$q != "="} {
	set value [uplevel set [list $name]]
    }

    cgi_puts "<input type=hidden name=\"$name\" value=[cgi_dquote_html $value]>"
}

proc cgi_export_cookie {name args} {
    upvar $name x
    eval cgi_cookie_set [list $name=$x] $args
}

# return list of variables available for import
# Explicit list is used to keep items in order originally found in form.
proc cgi_import_list {} {
    global _cgi

    return $_cgi(uservars)
}

# import named variable
proc cgi_import {name} {
    global _cgi_uservar
    upvar $name var

    set var $_cgi_uservar($name)
}

proc cgi_import_as {name tclvar} {
    global _cgi_uservar
    upvar $tclvar var

    set var $_cgi_uservar($name)
}

# like cgi_import but if not available, try cookie
proc cgi_import_cookie {name} {
    global _cgi_uservar
    upvar $name var

    if {0==[catch {set var $_cgi_uservar($name)}]} return
    set var [cgi_cookie_get $name]
}

# like cgi_import but if not available, try cookie
proc cgi_import_cookie_as {name tclvar} {
    global _cgi_uservar
    upvar $tclvar var

    if {0==[catch {set var $_cgi_uservar($name)}]} return
    set var [cgi_cookie_get $name]
}

proc cgi_import_filename {type name} {
    global _cgi_userfile
    upvar $name var

    set var $_cgi_userfile($name)
    if {$type == "-local"} {
	lindex $var 0
    } else {
	lindex $var 1
    }
}

##################################################
# button support
##################################################

# not sure about arg handling, do we need to support "name="?
proc cgi_button {value args} {
    cgi_put "<input type=button value=[cgi_dquote_html $value]"
    foreach a $args {
	if {[regexp "^onClick=(.*)" $a dummy str]} {
	    cgi_put " onClick=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}

proc cgi_submit_button {{nameval {=Submit Query}} args} {
    regexp "(\[^=]*)=(.*)" $nameval dummy name value
    cgi_put "<input type=submit"
    if {0!=[string compare "" $name]} {
	cgi_put " name=\"$name\""
    }
    cgi_put " value=[cgi_dquote_html $value]"
    foreach a $args {
	if {[regexp "^onClick=(.*)" $a dummy str]} {
	    cgi_put " onClick=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}


proc cgi_reset_button {{value Reset} args} {
    cgi_put "<input type=reset value=[cgi_dquote_html $value]"

    foreach a $args {
	if {[regexp "^onClick=(.*)" $a dummy str]} {
	    cgi_put " onClick=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}

proc cgi_radio_button {nameval args} {
    regexp "(\[^=]*)=(.*)" $nameval dummy name value

    cgi_put "<input type=radio name=\"$name\" value=[cgi_dquote_html $value]"

    foreach a $args {
	if [regexp "^checked_if_equal=(.*)" $a dummy default] {
	    if 0==[string compare $default $value] {
		cgi_put " checked"
	    }
	} elseif {[regexp "^onClick=(.*)" $a dummy str]} {
	    cgi_put " onClick=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}

proc cgi_image_button {nameval args} {
    regexp "(\[^=]*)=(.*)" $nameval dummy name value
    cgi_put "<input type=image"
    if {0!=[string compare "" $name]} {
	cgi_put " name=\"$name\""
    }
    cgi_put " src=\"$value\""
    foreach a $args {
	if {[regexp "^(alt|width|height|lowsrc|usemap)=(.*)" $a dummy attr str]} {
	    cgi_put " $attr=[cgi_dquote_html $str]"
	} elseif {[regexp "^onError" $a dummy str]} {
	    cgi_put " onError=\"$str\""
	} elseif {[regexp "^onClick=(.*)" $a dummy str]} {
	    cgi_put " onClick=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}

# map/area implement client-side image maps
proc cgi_map {name cmd} {
    cgi_put "<map name=\"$name\">"
    cgi_close_proc_push "cgi_puts </map>"

    uplevel $cmd
    cgi_close_proc
}

proc cgi_area {args} {
    cgi_put "<area"
    foreach a $args {
	if {[regexp "^(coords|shape|href|target|onMouseOut)=(.*)" $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}

##################################################
# checkbox support
##################################################

proc cgi_checkbox {nameval args} {
    regexp "(\[^=]*)(=?)(.*)" $nameval dummy name q value
    cgi_put "<input type=checkbox name=\"$name\""

    if {0!=[string compare "" $value]} {
	cgi_put " value=[cgi_dquote_html $value]"
    }

    foreach a $args {
	if [regexp "^checked_if_equal=(.*)" $a dummy default] {
	    if 0==[string compare $default $value] {
		cgi_put " checked"
	    }
	} elseif {[regexp "^onClick=(.*)" $a dummy str]} {
	    cgi_put " onClick=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}

##################################################
# textentry support
##################################################

proc cgi_text {nameval args} {
    regexp "(\[^=]*)(=?)(.*)" $nameval dummy name q value

    cgi_put "<input name=\"$name\""

    if {$q != "="} {
	set value [uplevel set [list $name]]
    }
    cgi_put " value=[cgi_dquote_html $value]"

    foreach a $args {
	if {[regexp "^on(Select|Focus|Blur|Change)=(.*)" $a dummy event str]} {
	    cgi_put " on$event=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}

##################################################
# password support
##################################################

proc cgi_password {nameval args} {
    regexp "(\[^=]*)(=?)(.*)" $nameval dummy name q value

    cgi_put "<input type=PASSWORD name=\"$name\""

    if {$q != "="} {
	set value [uplevel set [list $name]]
    }
    cgi_put " value=[cgi_dquote_html $value]"

    foreach a $args {
	if {[regexp "^on(Select|Focus|Blur|Change)=(.*)" $a dummy event str]} {
	    cgi_put " on$event=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}

##################################################
# textarea support
##################################################

proc cgi_textarea {nameval args} {
    regexp "(\[^=]*)(=?)(.*)" $nameval dummy name q value

    cgi_put "<textarea name=\"$name\""
    foreach a $args {
	if {[regexp {^([^=]*)=(.*)} $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"

    if {$q != "="} {
	set value [uplevel set [list $name]]
    }
    cgi_puts [cgi_quote_html $value]

    cgi_puts "</textarea>"
}

##################################################
# file upload support
##################################################

# for this to work, pass enctype=multipart/form-data to cgi_form
proc cgi_file_button {name args} {
    cgi_puts "<input type=file name=\"$name\"[cgi_list_to_string $args]>"
}

##################################################
# select support
##################################################

proc cgi_select {name args} {
    cgi_put "<select name=\"$name\""
    cgi_close_proc_push "cgi_puts </select>"
    foreach a [lrange $args 0 [expr [llength $args]-2]] {
	if {[regexp "^on(Focus|Blur|Change)=(.*)" $a dummy event str]} {
	    cgi_put " on$event=\"$str\""
	} else {
	    if 0==[string compare multiple $a] {
		;# sanity check
		if ![regexp "List$" $name] {
		    cgi_puts ">" ;# prevent error from being absorbed
		    error "When selecting multiple options, select variable \
			    must end in \"List\" to allow the value to be \
			    recognized as a list when it is processed later."
		}
	    }
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
    uplevel [lindex $args end]
    cgi_close_proc
}

proc cgi_option {o args} {
    cgi_put "<option"
    foreach a $args {
	if [regexp "^selected_if_equal=(.*)" $a dummy default] {
	    if 0==[string compare $default $o] {
		cgi_put " selected"
	    }
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">[cgi_quote_html $o]"
}

##################################################
# plug-in support
##################################################

proc cgi_embed {src wh args} {
    regexp (.*)x(.*) $wh dummy width height
    cgi_put "<embed src=[cgi_dquote_html $src] width=\"$width\" height=\"$height\""
    foreach a $args {
	if {[regexp "^palette=(.*)" $a dummy str]} {
	    cgi_put " palette=\"$str\""
	} elseif {[regexp "-quote" $a]} {
	    set quote 1
	} else {
	    if [info exists quote] {
		regexp "(\[^=]*)=(.*)" $a dummy var val
		cgi_put " var=[cgi_dquote_url $var]"
	    } else {
		cgi_put " $a"
	    }
	}
    }
    cgi_puts ">"
}

##################################################
# mail support
##################################################

# mail to/from the service itself
proc cgi_mail_addr {args} {
    global _cgi

    if [llength $args] {
	set _cgi(email) [lindex $args 0]
    }
    return $_cgi(email)
}

proc cgi_mail_start {to} {
    global _cgi

    set _cgi(mailfile) /tmp/cgimail.[pid]
    set _cgi(mailfid) [open $_cgi(mailfile) w]

    # mail is actually sent by "nobody".  To force bounce messages
    # back to us, override the default return-path.
    cgi_mail_add "Return-Path: <$_cgi(email)>"
    cgi_mail_add "From: [cgi_name] <$_cgi(email)>"
    cgi_mail_add "To: $to"
}

# add another line to outgoing mail
# if no arg, add a blank line
proc cgi_mail_add {{arg {}}} {
    global _cgi

    puts $_cgi(mailfid) $arg
}	

# end the outgoing mail and send it
proc cgi_mail_end {} {
    global _cgi

    close $_cgi(mailfid)

    catch "exec /usr/lib/sendmail -t -odb < $_cgi(mailfile)"
    # Explanation:
    # -t   means: pick up recipient from body
    # -odb means: deliver in background
    # note: bogus local address cause sendmail to fail immediately

    catch "exec /bin/rm -f $_cgi(mailfile)"
}

##################################################
# cookie support
##################################################

# calls to cookie_set look like this:
#   cgi_cookie_set user=don domain=nist.gov expires=never
#   cgi_cookie_set user=don domain=nist.gov expires=now
#   cgi_cookie_set user=don domain=nist.gov expires=...actual date...

proc cgi_cookie_set {nameval args} {
    global _cgi

    if ![info exists _cgi(http_head_in_progress)] {
	error "Cookies must be set from within cgi_http_head."
    }
    cgi_puts -nonewline "Set-Cookie: [cgi_cookie_encode $nameval];"

    foreach a $args {
	if [regexp "^expires=(.*)" $a dummy expiration] {
	    if {0==[string compare $expiration "never"]} {
		set expiration "Friday, 31-Dec-99 23:59:59 GMT"
	    } elseif {0==[string compare $expiration "now"]} {
		set expiration "Friday, 31-Dec-90 23:59:59 GMT"
	    }
	    cgi_puts -nonewline " expires=$expiration;"
	} elseif [regexp "^(domain|path)=(.*)" $a dummy attr str] {
	    cgi_puts -nonewline " $attr=[cgi_cookie_encode $str];"
	} elseif [regexp "^secure$" $a] {
	    cgi_puts -nonewline " secure;"
	}
    }
    cgi_puts ""
}

# return list of cookies available for import
proc cgi_cookie_list {} {
    global _cgi_cookie

    array names _cgi_cookie
}

proc cgi_cookie_get {args} {
    global _cgi_cookie

    set flag ""
    if [llength $args]>1 {
	set flag [lindex $args 0]
	set args [lrange $args 1 end]
    }
    set name [lindex $args 0]

    if {$flag == "-all"} {
	global _cgi_cookie_shadowed

	foreach {flag name} $args {}
	if [info exists $_cgi_cookie_shadowed($name)] {
	    return [concat $_cgi_cookie($name) $_cgi_cookie_shadowed($name)]
	} else {
	    return [concat $_cgi_cookie($name)]
	}
    }
    return $_cgi_cookie($name)
}

proc cgi_cookie_encode {in} {
    regsub -all " " $in "+" in
    regsub -all "%" $in "%25" in   ;# must preceed other subs that produce %
    regsub -all ";" $in "%3B" in
    regsub -all "," $in "%2C" in
    return $in
}

##################################################
# table support
##################################################

proc cgi_table {args} {
    cgi_put "<table"
    cgi_close_proc_push "cgi_puts </table>"

    if {[llength $args]} {
	foreach a [lrange $args 0 [expr [llength $args]-2]] {
	  if {[regexp {^([^=]*)=(.*)} $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	  } else {
	    cgi_put " $a"
	  }
	}
    }
    cgi_puts ">"
    uplevel [lindex $args end]
    cgi_close_proc
}

proc cgi_caption {args} {
    cgi_put "<caption"
    cgi_close_proc_push "cgi_puts </caption>"

    if {[llength $args]} {
	cgi_put "[cgi_lrange $args 0 [expr [llength $args]-2]]"
    }
    cgi_puts ">"
    uplevel [lindex $args end]
    cgi_close_proc
}

proc cgi_table_row {args} {
    cgi_put "<tr"
    cgi_close_proc_push "cgi_puts </tr>"
    if {[llength $args]} {
	foreach a [lrange $args 0 [expr [llength $args]-2]] {
	  if {[regexp {^([^=]*)=(.*)} $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	  } else {
	    cgi_put " $a"
	  }
	}
    }
    cgi_puts ">"
    uplevel [lindex $args end]
    cgi_close_proc
}

# like table_row but without eval
proc cgi_tr {args} {
    cgi_puts <tr
    if {[llength $args]} {
	foreach a [lrange $args 0 [expr [llength $args]-2]] {
	  if {[regexp {^([^=]*)=(.*)} $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	  } else {
	    cgi_put " $a"
	  }
	}
    }
    foreach i [lindex $args end] {
	cgi_td $i
    }
    cgi_puts </tr>
}

proc cgi_table_head args {
    cgi_put "<th"
    cgi_close_proc_push "cgi_puts </th>"

    if {[llength $args]} {
	foreach a [lrange $args 0 [expr [llength $args]-2]] {
	  if {[regexp {^([^=]*)=(.*)} $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	  } else {
	    cgi_put " $a"
	  }
	}
    }
    cgi_puts ">"
    uplevel [lindex $args end]
    cgi_close_proc
}

proc cgi_table_data args {
    cgi_put "<td"
    cgi_close_proc_push "cgi_puts </td>"

    if {[llength $args]} {
	foreach a [lrange $args 0 [expr [llength $args]-2]] {
	  if {[regexp {^([^=]*)=(.*)} $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	  } else {
	    cgi_put " $a"
	  }
	}
    }
    cgi_puts ">"
    uplevel [lindex $args end]
    cgi_close_proc
}

# like table_data but without eval
proc cgi_td {args} {
    cgi_put "<td"

    if {[llength $args] > 1} {
	foreach a [lrange $args 0 [expr [llength $args]-2]] {
	  if {[regexp {^([^=]*)=(.*)} $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	  } else {
	    cgi_put " $a"
	  }
	}
    }
    cgi_puts ">[lindex $args end]</td>"
}

##################################################
# frames
##################################################

proc cgi_frameset {args} {
    cgi_head ;# force it out, just in case none

    cgi_put "<frameset"
    cgi_close_proc_push "cgi_puts </frameset>"

    foreach a [lrange $args 0 [expr [llength $args]-2]] {
	if {[regexp "^(rows|cols|onUnload|onLoad|onBlur)=(.*)" $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
    uplevel [lindex $args end]

    cgi_close_proc
}

proc cgi_frame {namesrc args} {
    cgi_put "<frame"

    regexp "(\[^=]*)(=?)(.*)" $namesrc dummy name q src

    if {$name != ""} {
	cgi_put " name=\"$name\""
    }

    if {$src != ""} {
	cgi_put " src=\"$src\""
    }

    foreach a $args {
	if {[regexp "^(marginwidth|marginheight|scrolling|onFocus)=(.*)" $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
}

proc cgi_iframe {namesrc args} {
    cgi_put "<iframe"
    cgi_close_proc_push "cgi_puts </iframe>"

    regexp "(\[^=]*)(=?)(.*)" $namesrc dummy name q src

    if {$name != ""} {
	cgi_put " name=\"$name\""
    }

    if {$src != ""} {
	cgi_put " src=\"$src\""
    }

    foreach a [lrange $args 0 [expr [llength $args]-2]] {
	if {[regexp "^(width|height|marginwidth|marginheight|scrolling|onFocus)=(.*)" $a dummy attr str]} {
	    cgi_put " $attr=\"$str\""
	} else {
	    cgi_put " $a"
	}
    }
    cgi_puts ">"
    uplevel [lindex $args end]
    cgi_close_proc
}

proc cgi_noframes {args} {
    cgi_puts "<noframes>"
    cgi_close_proc_push "cgi_puts </noframes>"
    uplevel [lindex $args end]
    cgi_close_proc
}

##################################################
# admin support
##################################################

# mail address of the administrator
proc cgi_admin_mail_addr {args} {
    global _cgi

    if [llength $args] {
	set _cgi(admin_email) [lindex $args 0]
    }
    return $_cgi(admin_email)
}

##################################################
# if possible, make each cmd available without cgi_ prefix
##################################################

if {[info tclversion] >= 7.5} {
    foreach old [info procs cgi_*] {
	regexp "cgi_(.*)" $old dummy new
	if [llength [info commands $new]] continue
	interp alias {} $new {} $old
    }
} else {
    foreach p [info procs cgi_*] {
	regexp "cgi_(.*)" $p dummy name
	if [llength [info commands $name]] continue
	proc $name {args} "uplevel 1 $p \$args"
	#proc $name {args} "upvar _cgi_local x; set x \$args; uplevel \"$p \$x\""
    }
}

##################################################
# internal utilities
##################################################

# undo Tcl's quoting due to list protection
# This leaves a space at the beginning if the string is non-null
# but this is always desirable in the HTML context in which it is called
# and the resulting HTML looks more readable.
# (Alas, it makes the Tcl callers a little less readable - however, there
#  aren't more than a handful and they're all right here, so we'll live
#  with it.)
proc cgi_list_to_string {list} {
    set string ""
    foreach l $list {
	append string " $l"
    }
    # remove first space if possible
    # regexp "^ ?(.*)" $string dummy string
    return $string
}

# do lrange but return as string
# needed for stuff like: cgi_puts "[cgi_lrange $args ...]
# Like cgi_list_to_string, also returns string with initial blank if non-null
proc cgi_lrange {list i1 i2} {
    cgi_list_to_string [lrange $list $i1 $i2]
}

##################################################
# user-defined procedures
##################################################

# User-defined procedure called immediately after <body>
# Good mechanism for controlling things such as if all of your pages
# start with the same graphic or other boilerplate.
proc app_body_start {} {}

# User-defined procedure called just before </body>
# Good place to generate signature lines, last-updated-by, etc.
proc app_body_end {} {}

proc cgi_puts {args} {
    eval puts $args
}

# User-defined procedure to generate DOCTYPE declaration
proc cgi_doctype {} {}

##################################################
# do some initialization
##################################################

cgi_debug -off
cgi_name ""
cgi_root ""
cgi_body_args ""

# email addr of person responsible for this service
cgi_admin_mail_addr "root"	;# you should override this!

# most services won't have an actual email addr
cgi_mail_addr "CGI script - do not reply"

global tcl_version
if {$tcl_version > 7.4} {package provide cgi 0.6.4}
