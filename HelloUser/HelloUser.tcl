#!/usr/bin/tclsh
#* 
#* ------------------------------------------------------------------
#* HelloUser.tcl - Hello User example Facebook application
#* Created by Robert Heller on Wed Feb 25 13:30:33 2009
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

#@Chapter:HelloUser.tcl -- Sample Application
#@Label:HelloUser.tcl
#$Id: HelloUser.tcl 799 2010-02-04 19:11:13Z heller $
# This is a trivial application and is a minor variation of a classic 
# 'Hello World' program.

# Check to see how we were started up -- this would either be as a bare
# Tcl script or as a Starkit or Starpack.  If as a Tcl script, we need to
# find our support code (Facebook.tcl and cgi.tcl, plus support packages).
# As a Tcl script, we are presumed to be in a cgi-bin directory (or somewhere
# with either 'Options ExecCGI' and/or a 'AddHandler cgi-script .cgi' directive
# We will assume that there is a TclIncludes directory adjacent to the 
# DOCUMENT_ROOT -- that is if the the DOCUMENT_ROOT is '...PATH/WWW', then the 
# Tcl library code is in  '...PATH/TclIncludes'.  We further assume that either 
# the other support packages (md5, snit, uri, and tclxml) are installed under 
# there OR they are installed somewhere else under the standard places 
# (/usr/lib, /usr/share/tcl8.<mumble>, etc.).
#
# If we were started as a Starkit or Starpack, all of the support code is
# embedded in the Starkit or Starpack and there is no need to mess with
# auto_path.

if {![namespace exists ::starkit]} {
  lappend auto_path [file join [file dirname $::env(DOCUMENT_ROOT)] \
			       TclIncludes]
}

# Now load Facebook & cgi code, along with the other support packages.

package require Facebook

namespace eval HelloUser {
  # Namespace containing the HelloUser application code.

  variable AdminEMailAddress myname@my.domain.name;# Admin E-Mail address
  variable APIKEY 123456789abcdef0123456789abcdef0;# Your API KEY
  variable SECRET 0fedcba9876543210fedcba987654321;# Your API Secret
  variable CGI_DebugFlags -off;# Change this to -on for debugging

  variable DOCUMENT_ROOT;#	The document root.
  variable SERVER_NAME;#	The hostname of the server.
  variable SCRIPT_NAME;#	The name of the CGI script.
  variable REQUEST_URI;#	The request URI.
  variable MyName;#		The base name this script was called under.
  #				We can share code for different script
  #				functions by making multiple hard links
  #				under different names.

  # Set up cgi environment settings
  if {[catch {
    set DOCUMENT_ROOT $::env(DOCUMENT_ROOT)
    set SERVER_NAME   $::env(SERVER_NAME)
    set SCRIPT_NAME   $::env(SCRIPT_NAME)
    set REQUEST_URI   $::env(REQUEST_URI)
    } error]} {
    error "$argv0: Not started as a CGI Script!  Opps! Error was: $error"
  }
  set MyName [file rootname [file tail $SCRIPT_NAME]]
  set cb [file dirname $REQUEST_URI]
  if {"$cb" eq "/" || "$cb" eq "."} {set cb {}}
  ::cgi_root http://$SERVER_NAME$cb
  ::cgi_name $MyName
  ::cgi_admin_mail_addr $AdminEMailAddress
  ::cgi_debug $CGI_DebugFlags

  # Start of application code proper.
  # Wrap it in a cgi_eval -- this catches errors and ensures that proper http
  # headers (and html) is sent in the event of an error
  ::cgi_eval {
    ::cgi_input;#	Process CGI inputs

    # Get a Facebook object (grabs Facebook parameters
    variable fb [::Facebook::Facebook %%AUTO%% -api_key $APIKEY -secret $SECRET]

    # Require a frame and require login
    $fb require_frame
    variable UserId [$fb require_login]

    # Send HTTP headers
    ::cgi_http_head
    # Generate some HTML / FBML code.
    ::cgi_division {style="padding: 10px;"} {
      h2 "Hi <fb:name firstnameonly=\"true\" uid=\"$UserId\" useyou=\"false\"/>!"
      br
      if {![$fb added-p]} {
        cgi_put "[url {Put the Hello User application in your profile!} [$fb get_add_url]]"
      } else {
        if {![$fb profile_setFBML resultArray {} $UserId \
	  "Hi <fb:name firstnameonly=\"true\" uid=\"$UserId\" useyou=\"false\"/>!" \
	  {} {} "Hi <fb:name firstnameonly=\"true\" uid=\"$UserId\" useyou=\"false\"/>!"]} {
	  error "profile_setFBML: [$fb getErrorCode] [$fb getErrorMessage]"
	}
      }
    }
  }
}

  
