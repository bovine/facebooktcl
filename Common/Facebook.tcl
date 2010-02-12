#* 
#* ------------------------------------------------------------------
#* Facebook.tcl - This is a port of the Facebook API to Tcl
#* (Manually translated from facebook.php and facebookapi_php5_restlib.php)
#* +---------------------------------------------------------------------------+
#* | Copyright (c) 2004-2009 Facebook, Inc.                                         |
#* | All rights reserved.                                                      |
#* |                                                                           |
#* | Redistribution and use in source and binary forms, with or without        |
#* | modification, are permitted provided that the following conditions        |
#* | are met:                                                                  |
#* |                                                                           |
#* | 1. Redistributions of source code must retain the above copyright         |
#* |    notice, this list of conditions and the following disclaimer.          |
#* | 2. Redistributions in binary form must reproduce the above copyright      |
#* |    notice, this list of conditions and the following disclaimer in the    |
#* |    documentation and/or other materials provided with the distribution.   |
#* |                                                                           |
#* | THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR      |
#* | IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES |
#* | OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.   |
#* | IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,          |
#* | INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT  |
#* | NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, |
#* | DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY     |
#* | THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT       |
#* | (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF  |
#* | THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.         |
#* +---------------------------------------------------------------------------+
#* Created by Robert Heller on Tue Feb 24 18:37:20 2009
#* ------------------------------------------------------------------
#* ------------------------------------------------------------------
#* Contents: In namespace Facebook:
#*		SNIT types (classes): Facebook, FacebookRestClient
#*		SNIT types (Ensemble commands): json, simpleParseXML, 
#*						FacebookAPIErrorCodes
#*		SNIT Macros: facebookCallMethod
#* Externals:
#*		Package provided: Facebook 1.4.2
#*		Packages required: http, md5, snit, xml, cgi
#* ------------------------------------------------------------------
#*  
#*     Facebook API in Tcl Project
#*     Copyright (C) 2009  Robert Heller D/B/A Deepwoods Software
#* 			51 Locke Hill Road
#* 			Wendell, MA 01379-9728
#* 
#*     This library is free software; you can redistribute it and/or 
#*     modify it under the terms of the GNU Library General Public 
#*     License as published by the Free Software Foundation; either 
#*     version 2 of the License, or (at your option) any later version.
#* 
#*     This library is distributed in the hope that it will be useful,
#*     but WITHOUT ANY WARRANTY; without even the implied warranty of
#*     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#*     GNU General Public License for more details.
#* 
#*     You should have received a copy of the GNU Library General Public 
#*     License along with this library; if not, write to the Free Software
#*     Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#* 
#*  
#* 

#@Chapter:Facebook.tcl -- Facebook API in Tcl
#@Label:Facebook.tcl
#$Id: Facebook.tcl 803 2010-02-04 22:15:54Z heller $
# This is a manual translation / port of the Facebook API code contained in
# facebook.php and facebookapi_php5_restlib.php.

package require http;#		http package (comes with the base Tcl system)
package require md5;#		md5  package (comes with tcllib)
package require snit;#		snit package (comes with tcllib)
package require xml;#		xml package  (comes with tclxml)
#				Note: the tclxml package includes a C coded
#				shared library, but also includes a (slower!)
#				pure Tcl coded version, which will be loaded
#				if the shared library fails to load (eg because
#				of a platform mismatch).
if {![namespace exists ::Rivet]} {
    package require cgi;#		Don Libes CGI package (included with this package)
}

namespace eval Facebook {
# All of the Facebook code is contained in the namespace Facebook.
# [index] Facebook!namespace

  snit::type Facebook {
  # Top-level SNIT class: Tcl Facebook apps generally create one of these.
  #
  # <option> -api_key The application's API Key.
  # <option> -secret  The application's Secret.
  # <option> -generate_session_secret Flag to generate a session secret (or not).
  # [index] Facebook::Facebook!snit class type

    typemethod FACEBOOK_API_VALIDATION_ERROR {} {return 1}
    component api_client;# Sub class containing the REST API calls
    component cgi_methods;# Implements cgi/rivet API
    option -api_key -readonly yes -default {};# API key
    option -secret  -readonly yes -default {};# Secret
    option -generate_session_secret -readonly yes -default no \
	   -type snit::boolean;# Flag to generate a session secret (or not).
    # Delegate all additional methods to the Sub class
    delegate method * to api_client except {set_friends_list set_added set_user
					    set_canvas_user}
    # Delegate all additional options to the Sub class as well
    delegate option * to api_client except {-api_key -secret 
					    -generate_session_secret}
    # Class variables
    variable session_expires
    # Session expriation time.
    variable fb_params -array {}
    # Facebook parameters passed in.
    variable user 0
    # Logged in user.
    variable profile_user
    # Profile user.
    variable canvas_user
    # Canvas user.
    variable base_domain {}
    # Base domain.

    constructor {args} {
    # Create a Facebook client like this:
    #
    # set fb [::Facebook::Facebook create name -api_key API-KEY -secret SECRET [-generate_session_secret yes/no]]
    #
    # This will automatically pull in any parameters, validate them against the
    # session signature, and chuck them in the fb_params member variable.
    #
    # <in>  name		      Object name (can be %%AUTO%%).
    # <option> -api_key                 Your Developer API key. 
    #					This option is required.
    # <option> -secret                  Your Developer API secret. 
    #					This option is required.
    # <option> -generate_session_secret Whether to automatically generate a session
    #                                  if the user doesn't have one, but
    #                                  there is an auth token present in the url.
    #
    # [index] Facebook::Facebook!constructor

      # Peel off the two required options first
      set options(-api_key) [from args -api_key {}]
      set options(-secret) [from args -secret {}]
      # Error check -- *must* have these two options!
      if {[string length "$options(-api_key)"] == 0 ||
	  [string length "$options(-secret)"] == 0} {
	error "Facebook: -api_key and -secret are *required* options!"
      }
      if {[catch {package present cgi}]} {
	install cgi_methods using ::Facebook::rivet_methods %%AUTO%%
      } else {
	install cgi_methods using ::Facebook::cgi_api %%AUTO%%
      }
      # install the sub class object, passing it the api_key and secret
      install api_client using ::Facebook::FacebookRestClient %%AUTO%% \
		-api_key "$options(-api_key)" -secret "$options(-secret)" \
		-cgi_methods $cgi_methods
      # Process the remaining configuration options (includes those for the 
      #							Rest Client)
      $self configurelist $args
      # Validate the fb parameters
      $self validate_fb_params
#      puts stderr "*** $type create $self: fb_params contains:"
#      foreach k [array names fb_params] {
#	puts stderr "*** $type create $self: - fb_params($k): $fb_params($k)"
#      }
      # Compute default user
      set defaultUser 0
      if {$user} {
	set defaultUser $user
      } elseif {[info exists profile_user]} {
	set defaultUser $profile_user
      } elseif {[info exists canvas_user]} {
	set defaultUser $canvas_user
      }
      # set the user in the Rest Client
      $api_client set_user $defaultUser
      # Handle cache friends
      if {[info exists fb_params(friends)]} {
	$api_client set_friends_list [split $fb_params(friends) {,}]
      }
      # Handle added flag
      if {[info exists fb_params(added)]} {
	$api_client set_added $fb_params(added)
      }
      # Handle Canvas User
      if {[info exists fb_params(canvas_user)]} {
        $api_client set_canvas_user $fb_params(canvas_user)
      }
#      puts stderr "*** $type create $self: returning..."
    }
    destructor {
# Be sure to delete the Rest Client object when we are deleted.
# [index] Facebook::Facebook!destructor
      catch {$api_client destroy}
      catch {$cgi_methods destroy}
    }

    method validate_fb_params {{resolve_auth_token yes}} {
    #
    # Validates that the parameters passed in were sent from Facebook. It does so
    # by validating that the signature matches one that could only be generated
    # by using your application's secret key.
    #
    # Facebook-provided parameters will come from $_POST, $_GET, or $_COOKIE,
    # in that order. $_POST and $_GET are always more up-to-date than cookies,
    # so we prefer those if they are available.
    # 
    # The Don Libes cgi package processes the POST or GET query data into its
    # _cgi_uservar array and processes cookies into its _cgi_cookie array.
    # (The cgi package only process either the GET query string OR the POST 
    # (stdin).  It does not process both.)
    #
    # For nitty-gritty details of when each of these is used, check out
    # [url] http://wiki.developers.facebook.com/index.php/Verifying_The_Signature
    #
    #
    # <in> bool  resolve_auth_token  convert an auth token into a session
    # <returns> bool True if successful, False if not.
    # [index] validate_fb_params!method

      $cgi_methods import_cookies rawfacebook_cookies
      $cgi_methods import_params  rawfacebook_params
      set status [$self get_valid_fb_params rawfacebook_params [expr {48*3600}] {fb_sig} [myvar fb_params]]
      # Okay, something came in via POST or GET
      if {$status} {
	if {[catch {set fb_params(user)} _user]} {set _user 0}
	if {[catch {set fb_params(profile_user)} profile_user]} {set profile_user 0}
	if {[catch {set fb_params(canvas_user)} canvas_user]} {set canvas_user 0}
	if {[catch {set fb_params(base_domain)} base_domain]} {set base_domain {}}
	if {[info exists fb_params(session_key)]} {
	  set session_key $fb_params(session_key)
	} elseif {[info exists fb_params(profile_session_key)]} {
	  set session_key $fb_params(profile_session_key)
	} else {
	  set session_key {}
	}
	if {[catch {set fb_params(expires)} expires]} {set expires {}}
	$self set_user "$_user" "$session_key" "$expires"
	# if no Facebook parameters were found in the GET or POST variables,
	# then fall back to cookies, which may have cached user information
	# Cookies are also used to receive session data via the Javascript API
      } elseif {[llength [array size rawfacebook_cookies]] > 0 && [$self get_valid_fb_params rawfacebook_cookies 0 "$options(-api_key)" cookies]} {
	set base_domain_cookie "base_domain_$options(-api_key)"
	if {[info exists rawfacebook_cookies($base_domain_cookie)]} {
	  set base_domain $rawfacebook_cookies($base_domain_cookie)
	}
	# use "${options(-api_key)}_" as a prefix for the cookies in case there 
	# are multiple facebook clients on the same domain.
	if {[catch {set cookies(expires)} expires]} {set expires {}}
	$self set_user $cookies(user) $cookies(session_key) $expires
	# finally, if we received no parameters, but the 'auth_token' GET var
	# is present, then we are in the middle of auth handshake,
	# so go ahead and create the session
      } elseif {[info exists rawfacebook_params(auth_token)] && $resolve_auth_token && [$self do_get_session session $rawfacebook_params(auth_token)]} {
	if {$options(-generate_session_secret) && [string length $session(secret)] > 0} {
	  set session_secret $session(secret)
	} else {
	  set session_secret {}
	}
	if {[catch {set session(base_domain)} base_domain]} {set base_domain {}}
	$self set_user $session(uid) $session(session_key) $session(expires) $session_secret
      }

      return [expr {[llength [array names fb_params]] > 0}]
    }

    method promote_session {} {
    # Store a temporary session secret for the current session
    # for use with the JS client library
    #
    # <returns> bool True if successful, False if not.
    # [index] promote_session!method
      if {[$api_client auth_promoteSession resultArray]} {
	set session_secret $resultArray(auth_promoteSession_response)
	if {![$self in_fb_canvas]} {
	  $self set_cookies $user [$api_client cget -session_key] $session_expires $session_secret
	}
	return $session_secret
      } else {
	# API_EC_PARAM means we don't have a logged in user, otherwise who
	# knows what it means, so just throw it.
	if {[$api_client getErrorCode] != [::Facebook::FacebookAPIErrorCodes API_EC_PARAM]} {
	  error "$self promote_session: $api_client auth_promoteSession: [$api_client getErrorCode] [$api_client getErrorMessage]"
	}
	return {}
      }
    }
    method do_get_session {result_var auth_token} {
    # Get the session secret.
    #
    # <in> result_var Name of an array to collect the results in.
    # <in> auth_token The auth token to use.
    # <returns> bool True if successful, False if not.
    # [index] do_get_session!method

      upvar $result_var result
      if {[$api_client auth_getSession result  $auth_token $options(-generate_session_secret)]} {
	return true
      } else {
	# API_EC_PARAM means we don't have a logged in user, otherwise who
	# knows what it means, so just throw it.
	if {[$api_client getErrorCode] != [::Facebook::FacebookAPIErrorCodes API_EC_PARAM]} {
	  error "$self do_get_session: $api_client auth_getSession: [$api_client getErrorCode] [$api_client getErrorMessage]"
	}
	return false
      }
    }
    method expire_session {} {
    # Invalidate the session currently being used, and clear any state 
    # associated with it
    #
    # <returns> bool True if successful, False if not.
    # [index] expire_session!method

      $cgi_methods import_cookies rawfacebook_cookies
      if {[$api_client auth_expireSession resultArray]} {
	if {![$self in_fb_canvas] && [info exists rawfacebook_cookies(${options(-api_key)}_user)]} {
	  foreach name {user session_key expires ss} {
	    $cgi_methods cookie_set "${options(-api_key)}_${name}" "" -minutes 0
	    unset rawfacebook_cookies(${options(-api_key)}_${name})
	  }
	  $cgi_methods cookie_set "${options(-api_key)}" "" -minutes 0
	  unset rawfacebook_cookies($options(-api_key))
	# now, clear the rest of the stored state
	set $user 0
	$api_client set_session_key 0
	return true
	}
      } else {
	return false
      }
    }
    method redirect {url} {
    # Redirect to url.  Passes our URL so we can come back here.
    #
    # <in> url URL to redirect to.
    # [index] redirect!method

#      puts stderr "*** $self redirect $url"
#      puts stderr "*** $self redirect: \[\$self in_fb_canvas\] : [$self in_fb_canvas]"
      if {[$self in_fb_canvas]} {
	puts "<fb:redirect url=\"$url\"/>";# Hmmm...
	return
      } elseif {[regexp {^https?:\/\/([^\/]*\.)?facebook\.com(:\d+)?} "$url"] > 0} {
        $cgi_methods http_head
	puts "<script type=\"text/javascript\">\ntop.location.href = \"$url\";\n</script>"
      } else {
	$cgi_methods location $url
      }
      $cgi_methods exit
    }
    method in_frame {} {
    # Are we in a frame?
    #
    # <returns> True if we are in a canvas or an iframe.
    # [index] in_frame!method

      return [expr {[info exists fb_params(in_canvas)] ||
		    [info exists fb_params(in_iframe)]}]
    }
    method in_fb_canvas {} {
    # Are we in a canvas?
    #
    # <returns> True if we are in a canvas.
    # [index] in_fb_canvas!method

      return [info exists fb_params(in_canvas)]
    }
    method get_loggedin_user {} {
    # Return the logged in user.
    #
    # <returns> The logged in user.
    # [index] get_loggedin_user!method

      return "$user"
    }
    
    method get_canvas_user {} {
    # Return the canvas user.
    #
    # <returns> The canvas user.
    # [index] get_canvas_user!method

      return $canvas_user
    }
    
    method get_profile_user {} {
    # Return the profile user.
    #
    # <returns> The profile user.
    # [index] get_profile_user!method

      return $profile_user
    }
    
    method current_url {} {
    # Return the URL of the current script.
    #
    # <returns> The current URL.
    # [index] current_url!typemethod

      $cgi_methods makeurl_from_env REQUEST_URI
    }
    
    method require_login {} {
    # Make sure we are logged in.
    #
    # <returns> The logged in user.
    # [index] require_login!method

#      puts stderr "*** $self require_login"
      set u [$self get_loggedin_user]
#      puts stderr "*** $self require_login: u = $u"
      if {$u != 0} {
	return $u
      } else {
	$self redirect [$self get_login_url [$self current_url] [$self in_frame]]
      }
    }
    method require_frame {} {
    # Make sure we are in a frame.
    #
    # [index] require_frame!method

      if {![$self in_frame]} {
	$self redirect [$self get_login_url [$self current_url] true]
      }
    }
    typemethod get_facebook_url {{subdomain www}} {
    # Return the Facebook URL.
    #
    # <in> subdomain The sub domain we need.
    # <returns> The proper Facebook URL.
    # [index] get_facebook_url!typemethod

      return "http://${subdomain}.facebook.com"
    }
    method get_add_url {{next {}}} {
    # Get the redirect URL to add this application.
    #
    # <in> next The next URL to go to.
    # <returns> The add URL.
    # [index] get_add_url!method

      if {[string length $next] > 0} {
	set n1 "&next=[$cgi_methods quote_url $next]"
      } else {
	set n1 {}
      }
      return "[$type get_facebook_url]/add.php?api_key=$options(-api_key)$n1"
    }
    method get_login_url {next canvas} {
    # Get the redirect URL to log into this application.
    #
    # <in> next The next URL to go to.
    # <in> canvas Flag indicating if we need to be in a canvas.
    # <returns> The login URL.
    # [index] get_login_url!method

      if {[string length $next] > 0} {
	set n1 "&next=[$cgi_methods quote_url $next]"
      } else {
	set n1 {}
      }
      if {[string length $canvas] > 0} {
	set c1 "&canvas"
      } else {
	set c1 {}
      }
      return "[$type get_facebook_url]/login.php?v=1.0&api_key=$options(-api_key)$n1$c1"
    }
    method set_user {_user session_key {expires {}} {session_secret {}} } {
    # Set the login user.
    #
    # <in> _user The login user.
    # <in> session_key The session key.
    # <in> expires The expiration time.
    # <in> session_secret The session secret.
    # [index] set_user!method

      $cgi_methods import_cookies rawfacebook_cookies
      if {![$self in_fb_canvas] && 
	  (![info exists rawfacebook_cookies(${options(-api_key)}_user)] || 
	   $rawfacebook_cookies(${options(-api_key)}_user) ne $_user)} {
	$self set_cookies $_user $session_key $expires $session_secret
      }
      set user $_user
      $api_client configure -session_key $session_key
      set session_expires $expires
    }
    
    method set_cookies {_user session_key {expires {}} {session_secret {}} } {
    # Set the login user's cookies
    #
    # <in> _user The login user.
    # <in> session_key The session key.
    # <in> expires The expiration time.
    # <in> session_secret The session secret.
    # [index] set_cookies!method

      set cookies(user) $_user
      set cookies(session_key) $session_key
      if {expires ne {}} {set cookies(expires) $expires}
      if {session_secret ne {}} {set cookies(ss) $session_secret}
      foreach name [array names cookies] {
	set val $cookies($name)
	$cgi_methods cookie_set "${options(-api_key)}_${name}" $val -expires [clock format $expires -format {%A, %d-%b-%y %X GMT} -gmt yes]
	set rawfacebook_cookies(${options(-api_key)}_$name) $val
      }
      set sig [$type generate_sig cookies $options(-secret)]
      $cgi_methods cookie_set "${options(-api_key)}" $sig -expires [clock format $expires -format {%A, %d-%b-%y %X GMT} -gmt yes]
      set rawfacebook_cookies($options(-api_key)) $sig
    }

    method get_valid_fb_params {param_array {timeout 0} {namespace fb_sig} {outvar {}} } {
    #
    # Get the signed parameters that were sent from Facebook. Validates the set
    # of parameters against the included signature.
    #
    # Since Facebook sends data to your callback URL via unsecured means, the
    # signature is the only way to make sure that the data actually came from
    # Facebook. So if an app receives a request at the callback URL, it should
    # always verify the signature that comes with against your own secret key.
    # Otherwise, it's possible for someone to spoof a request by
    # pretending to be someone else, i.e.:
    #      www.your-callback-url.com/?fb_user=10101
    #
    # This is done automatically by verify_fb_params.
    #
    # <in>  params_array     a full array of external parameters.
    #                            Presumably _cgi_uservar or _cgi_cookie.
    # <in>  timeout    number of seconds that the args are good for.
    #                            Specifically good for forcing cookies to expire.
    # <in>  namespace  prefix string for the set of parameters we want
    #                            to verify. i.e., fb_sig or fb_post_sig
    #
    # <returns>  assoc the subset of parameters containing the given prefix,
    #                and also matching the signature associated with them.
    #          OR    an empty array if the params do not validate
    # [index] get_valid_fb_params!method

      upvar $param_array params
      upvar $outvar fb_params
      set prefix "${namespace}_"
      set prefix_len [string length $prefix]
      catch {array unset fb_params}
      foreach name [array names params] {
	set val $params($name)
	# pull out only those parameters that match the prefix
	# note that the signature itself ($params[$namespace]) is not in the
	# list
	if {[string first $prefix $name] == 0} {
	  set fb_params([string range $name $prefix_len end]) "$val"
	}
      }
      # validate that the request hasn't expired. this is most likely
      # for params that come from cookies
      if {$timeout && (![info exists fb_params(time)] || [expr {[clock scan now] - $fb_params(time)}] > $timeout) } {
	array unset fb_params
	return false
      }
      # validate that the params match the signature
      if {![info exists params($namespace)] || 
	  ![$self verify_signature fb_params $params($namespace)]} {
	array unset fb_params
#	puts stderr "*** $self get_valid_fb_params: returning false"
	return false
      }
#      puts stderr "*** $self get_valid_fb_params: returning true"
      return true
    }

    method verify_signature {fb_params_var expected_sig} {
    #
    # Validates that a given set of parameters match their signature.
    # Parameters all match a given input prefix, such as "fb_sig".
    #
    # <in> fb_params     an array of all Facebook-sent parameters,
    #                       not including the signature itself
    # <in> expected_sig  the expected result to check against
    #
    # [index] verify_signature!method

      upvar $fb_params_var fb_params
      set generatedSig [$type generate_sig fb_params $options(-secret)]
#      puts stderr "*** $self verify_signature: generatedSig = $generatedSig, expected_sig = $expected_sig"
      set result [string equal -nocase "$generatedSig" "$expected_sig"]
#      puts stderr "*** $self verify_signature: result = $result"
      return $result
    }
    
    typemethod generate_sig {params_array secret} {
    #
    # Generate a signature using the application secret key.
    #
    # The only two entities that know your secret key are you and Facebook,
    # according to the Terms of Service. Since nobody else can generate
    # the signature, you can rely on it to verify that the information
    # came from Facebook.
    #
    # <in> params_array   an array of all Facebook-sent parameters,
    #                        NOT INCLUDING the signature itself
    # <in> secret         your app's secret key
    #
    # <returns> a hash to be checked against the signature provided by Facebook
    # [index] generate_sig!method

      upvar $params_array params
      set str {}
      foreach k [lsort [array names params]] {
	append str "$k=$params($k)"
      }
      append str $secret
#      puts stderr "*** $type generate_sig: str = $str"
      set thesig [string tolower [::md5::md5 -hex "$str"]]
#      puts stderr "*** $type generate_sig: thesig = $thesig"
      return $thesig
    }
    method encode_validationError {summary message} {
      ::Facebook::json encode_object [list \
	errorCode [$type FACEBOOK_API_VALIDATION_ERROR] \
	errorTitle $summary \
	errorMessage $message]
    }
    
    method encode_multiFeedStory {feed next} {

      ::Facebook::json encode_object [list \
	{method} multiFeedStory \
	content [list next $next feed $feed] ]
    }
    method encode_feedStory  {feed next} {

      ::Facebook::json encode_object [list \
	{method} feedStory \
	content [list next $next feed $feed] ]
    }
    
    method create_templatizedFeedStory {title_template {title_data {}} 
					{body_template {}} {body_data {}}
					{body_general {}}
					{image_1 {}} {image_1_link {}}
					{image_2 {}} {image_2_link {}}
					{image_3 {}} {image_3_link {}}
					{image_4 {}} {image_4_link {}} } {

      return [list title_template $title_template \
		   title_data     $title_data \
		   body_template  $body_template \
		   body_data	  $body_data \
		   body_general   $body_general \
		   image_1        $image_1 \
		   image_1_link   $image_1_link \
		   image_2        $image_2 \
		   image_2_link   $image_2_link \
		   image_3        $image_3 \
		   image_3_link   $image_3_link \
		   image_4        $image_4 \
		   image_5_link   $image_4_link]
    					}
  }
  
  # End of code translated from facebook.php
  #----------------------------------------------------------
  snit::type json {
  # JSON encoder ensemble command.
  # This ensemble command encodes Tcl objects into JSON strings.
  #
  # [index] Facebook::json!ensemble command.

    pragma -hastypeinfo    no
    pragma -hastypedestroy no
    pragma -hasinstances   no

    typemethod encode_object {object_nvs} {
    # Encode an assoc list {key1 val1 key2 val2 ... keyn valn} to:
    # {"key1":val1,"key2":val2, ... "keyn":valn}
    #
    # [index] Facebook::json encode_object!command

      set result "{"
      foreach {n v} $object_nvs {
	append result [$type encode_string $n]
	append result {:}
	append result [$type encode_value $v]
	append result {,}
      }
      regsub {,$} "$result" {} result
      append result "}"    
      return $result
    }
    typemethod encode_string {s} {
    # Encode a string: s to: "s" (with quotes and backslashes quoted)
    #
    # [index] Facebook::json encode_string!command

      regsub -all {[\"\\]} "$s" {\\\0} s
      return "\"$s\""
    }
    typemethod encode_list {l} {
    # Encode a list: {v1 v2 ... vn} to: [v1,v2, ... vn]
    #
    # [index] Facebook::json encode_list!command

      set result {[}
      foreach v $l {
	append result [$type encode_value $v]
	append result {,}
      }
      regsub {,$} "$result" {} result
      append result {]}    
      return $result
    }
    typemethod encode_value {v} {
    # Encode whatever.  Tcl has few specific types, so mostly general cases
    #
    # [index] Facebook::json encode_value!command

      # Numbers
      if {[string is double -strict] || [string is integer -strict]} {
	return $v
      # Booleans (Tcl is liberal as to what is a boolean: 
      # 1 and 0, true and false, yes and no are all legal boolean values.
      } elseif {[string is boolean -strict]} {
	if {$v} {
	  return true
	} else {
	  return false
	}
      # Even element lists are *presumed* to be assoc lists (this could be bad)
      } elseif {[llength $v] > 1 && [expr {[llength $v] % 2}] == 0} {
	return [$type encode_object $v]
      # Odd element lists are *presumed* to be vector analogs
      } elseif {[llength $v] > 1 && [expr {[llength $v] % 2}] == 1} {
	return [$type encode_list $v]
      # Anything is presumed to be a string.
      } else {
	return [$type encode_string $v]
      }
    }
  }
  
  snit::type simpleParseXML {
  # Simple XML parser.  Very bare and minimal.
  # Attributes are dropped in the bit bucket.
  # 
  # [index] Facebook::simpleParseXML!ensemble command.

    pragma -hastypeinfo    no
    pragma -hastypedestroy no
    pragma -hasinstances   no
    typecomponent parser
    # Parser object used to parse XML.

    typeconstructor {
    # Type constructor: build the parser object used to parse XML.

      set parser [::xml::parser -elementstartcommand [mytypemethod _EStart] \
				  -elementendcommand [mytypemethod _EEnd] \
				  -characterdatacommand [mytypemethod _Data] \
				  ]
    }
    typevariable data
    typevariable name
    typevariable attlist
    typevariable result -array {}
    typemethod _Error {args} {

    }
    typemethod _EStart {_name  _attlist  args} {
      set name $_name
      set attlist $_attlist
    }
    typemethod _EEnd {_name args} {
      if {[regexp {^[[:space:]]*$} "$data"] > 0} {return}
      if {[catch {set result($_name)}]} {
	set result($_name) $data
      } else {
	lappend result($_name) $data
      }
    }
    typemethod _Data {_data} {
      set data $_data
    }
    typemethod Parse {xml} {
    # Parse an XML string.
    #
    # <in> xml The XML string.
    # <returns> A list suitable as an argument to array set.
    # [index] Facebook::simpleParseXML Parse!command

      array unset result
      $parser parse $xml
      return [array get result]
    }
  }
  
  snit::macro ::Facebook::facebookCallMethod {name apistring args} {
  # Helper macro to define most call_method methods
  #
  # <in> name The method name to use.
  # <in> apistring The Facebook API String.
  # <in> args The argument list.
  # [index] ::Facebook::facebookCallMethod!macro

#    puts stderr "*** ::Facebook::facebookCallMethod $name $apistring $args"
    set paramcode {[list}
    set arglist [list result_var]
    foreach a $args {
      lappend arglist "$a"
      if {[llength $a] > 1} {set a [lindex $a 0]}
      append paramcode " $a \$$a"
    }
    append paramcode {]}
    method $name $arglist " \
      upvar \$result_var result \n\
      return \[\$self call_method result $apistring $paramcode\] \
    "
  }
  
  #*************************
  # Code translated from facebookapi_php5_restlib.php starts here
  #*************************

  snit::type FacebookRestClient {
  # Client API class.  This class contains the API calls and supports the
  # main Facebook class.
  # <option> -api_key The application's API Key.
  # <option> -secret  The application's Secret.
  # <option> -session_key The session key.
  # <option> -cgi_methods The cgi method object
  # [index] Facebook::FacebookRestClient!snit class type

    option -api_key -readonly yes -default {}
    option -secret  -readonly yes -default {}
    option -session_key -default {} 
    option -cgi_methods -readonly yes -default {}
    component cgi_methods;# Implements cgi/rivet API
    # to save making the friends.get api call, this will get prepopulated on
    # canvas pages
    variable friends_list
    variable user
    # to save making the pages.isAppAdded api call, this will get prepopulated
    # on canvas pages
    variable added no
    variable is_user
    # we don't pass friends list to iframes, but we want to make
    # friends_get really simple in the canvas_user (non-logged in) case.
    # So we use the canvas_user as default arg to friends_get
    variable canvas_user
    # (I left out batch processing)
    # variable batch_mode
    # variable batch_queue
    # typemethod BATCH_MODE_DEFAULT {} {return 0}
    # typemethod BATCH_MODE_SERVER_PARALLEL {} {return 0}
    # typemethod BATCH_MODE_SERIAL_ONLY {} {return 2}
    variable call_as_apikey {}
    variable last_call_id
    variable server_addr
    variable error_code 0
    variable error_message {}
    method getErrorCode {} {return $error_code}
    method getErrorMessage {} {return $error_message}

    constructor {args} {
    # Creates the client API object.
    #
    # <in>  name			Object name (can be %%AUTO%%).
    # <option> -api_key		Your Developer API key.
    #				Passed in from the main client class.
    # <option> -secret		Your Developer API secret.
    #				Passed in from the main client class.
    # <option> -session_key If you haven't gotten a session key yet, leave
    #                            this as null and then set it later by using
    #			       the configure method.
    # <option> -cgi_methods    The cgi_methods API component to use.
    #				Passed in from the main client class.
    # [index] Facebook::FacebookRestClient!constructor

      set cgi_methods [from args -cgi_methods];# Set cgi_methods component (not checked!).
      $self configurelist $args
      set last_call_id 0
      set call_as_apikey {}
      set server_addr "[::Facebook::Facebook get_facebook_url api]/restserver.php"
    }

    method set_user {uid} {set user $uid}
    #
    # Set the default user id for methods that allow the caller
    # to pass an uid parameter to identify the target user
    # instead of a session key. This currently applies to
    # the user preferences methods.
    #
    # <in> uid The user id.
    # [index] set_user!method


    method begin_permissions_mode {permissions_apikey} {
      set call_as_apikey $permissions_apikey
    }
    method end_permissions_mode {} {
      set call_as_apikey {}
    }

  #***************
  #* The various (and many!) call_method API functions.  I reorded them in 
  #* alphabetical order.

    ::Facebook::facebookCallMethod admin_getAllocation \
					{facebook.admin.getAllocation} \
					integration_point_name
  #
  # Returns the allocation limit value for a specified integration point name
  # Integration point names are defined in lib/api/karma/constants.php in the
  # limit_map.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 Will contain the integration point allocation value.
  # <in> integration_point_name  Name of an integration point
  #                                        (see developer wiki for list).
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod admin_getAppProperties \
					{facebook.admin.getAppProperties} \
					properties
  #
  # Get the properties that you have set for an app.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 A map from property name to value.
  # <in> properties  List of properties names to fetch
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod admin_getMetrics \
					{facebook.admin.getMetrics} \
					start_time end_time period metrics
  #
  # Returns values for the specified metrics for the current application, in
  # the given time range.  The metrics are collected for fixed-length periods,
  # and the times represent midnight at the end of each period.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 A map of the names and values for those metrics
  # <in> start_time  Unix time for the start of the range.
  # <in> end_time    Unix time for the end of the range.
  # <in> period      Number of seconds in the desired period.
  # <in> metrics     List of metrics to look up.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod admin_getRestrictionInfo \
					{admin.getRestrictionInfo}
  #
  # Gets application restriction info.
  #
  # Applications can restrict themselves to only a limited user demographic
  # based on users' age and/or location or based on static predefined types
  # specified by facebook for specifying diff age restriction for diff
  # locations.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 The age restriction settings for this application.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod admin_setAppProperties \
					{facebook.admin.setAppProperties} \
					properties
  #
  # Set properties for an app.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> properties  A map from property names to values.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod admin_setRestrictionInfo \
					admin.setRestrictionInfo \
					{restriction_str {}}
  #
  # Sets application restriction info.
  #
  # Applications can restrict themselves to only a limited user demographic
  # based on users' age and/or location or based on static predefined types
  # specified by facebook for specifying diff age restriction for diff
  # locations.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> restriction_info  The age restriction settings to set.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod application_getPublicInfo \
					{facebook.application.getPublicInfo} \
				{application_id {}} {application_api_key {}} \
				{application_canvas_name {}}
  #
  # Returns public information for an application (as shown in the application
  # directory) by either application ID, API key, or canvas page name.
  #
  # Exactly one argument must be specified, otherwise it is an error.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> application_id              (Optional) app id.
  # <in> application_api_key      (Optional) api key.
  # <in> application_canvas_name  (Optional) canvas name.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod auth_createToken {facebook.auth.createToken}
  #
  # Creates an authentication token to be used as part of the desktop login
  # flow.  For more information, please see
  # [url] http://wiki.developers.facebook.com/index.php/Auth.createToken
  #
  # <ref> result Name of an array to be filled in the results.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod auth_expireSession \
					{facebook.auth.expireSession}
  #
  # Expires the session that is currently being used.  If this call is
  # successful, no further calls to the API (which require a session) can be
  # made until a valid session is created.
  #
  # <ref> result Name of an array to be filled in the results.
  # <return> bool True if success, false if not.
  #

    method auth_getSession {result_var auth_token
				{generate_session_secret false}} {
  #
  # Returns the session information available after current user logs in.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An assoc array containing session_key, uid.
  # <in> auth_token             The token returned by
  #                                       auth_createToken or passed back to
  #                                       your callback_url.
  # <in> generate_session_secret  whether the session returned should
  #                                       include a session secret.
  # <return> bool True if success, false if not.
  #

      upvar $result_var result
      if {![$self call_method result {facebook.auth.getSession} \
			       [list auth_token $$auth_token \
				     generate_session_secret \
					$generate_session_secret]]} {
	return false
      }
      $self configure -session_key $result(session_key)
      if {[string length $result(secret)] > 0 && !$generate_session_secret} {
	set secret $result(secret)
      }
      return true
    }

    ::Facebook::facebookCallMethod auth_promoteSession \
					{facebook.auth.promoteSession}
  #
  # Generates a session-specific secret. This is for integration with
  # client-side API calls, such as the JS library.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 A session secret for the current promoted session.
  # <return> bool True if success, false if not.
  #
  # <error> API_EC_PARAM_SESSION_KEY API_EC_PARAM_UNKNOWN
  #

    ::Facebook::facebookCallMethod auth_revokeAuthorization \
					{facebook.auth.revokeAuthorization} \
					{uid {}}
  #
  # Revokes the user's agreement to the Facebook Terms of Service for your
  # application.  If you call this method for one of your users, you will no
  # longer be able to make API requests on their behalf until they again
  # authorize your application.  Use with care.  Note that if this method is
  # called without a user parameter, then it will revoke access for the
  # current session's user.
  #
  # <in> uid  (Optional) User to revoke.
  #
  # <ref> result Name of an array to be filled in the results.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod events_cancel {facebook.events.cancel} \
				eid {cancel_message {}}
  #
  # Cancels an event. Only works for events where application is the admin.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> eid                Event id.
  # <in> cancel_message  (Optional) message to send to members of
  #                                the event about why it is cancelled.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod events_create {facebook.events.create} \
				event_info
  #
  # Creates an event on behalf of the user is there is a session, otherwise on
  # behalf of app.  Successful creation guarantees app will be admin.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 The event id.
  # <in> event_info  Json encoded event information.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod events_edit {facebook.events.edit} eid \
				event_info
  #
  # Edits an existing event. Only works for events where application is admin.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> eid                 Event id.
  # <in> event_info  Json encoded event information.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod events_get {facebook.events.get} \
	uid eids start_time end_time rsvp_status
  #
  # Returns membership list data associated with an event.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An assoc array of four membership lists, with keys
  #                `attending', `unsure', `declined', and `not_replied'.
  # <in> eid  Event id.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod events_getMembers \
					{facebook.events.getMembers} eid
  #
  # Returns membership list data associated with an event.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An assoc array of four membership lists, with keys
  #                `attending', `unsure', `declined', and `not_replied'.
  # <in> eid  Event id.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod events_rsvp {facebook.events.rsvp} \
				eid rsvp_status
  #
  # RSVPs the current user to this event.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> eid             Event id.
  # <in> rsvp_status  One of `attending', `unsure', or `declined'.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod fbml_deleteCustomTags \
				{facebook.fbml.getCustomTags} {tag_names {}}
  #
  # Delete custom tags the application has registered. If
  # tag_names is null, all the application's custom tags will be
  # deleted.
  #
  # IMPORTANT: If your application has registered public tags
  # that other applications may be using, don't delete those tags!
  # Doing so can break the FBML ofapplications that are using them.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> tag_names The names of the tags to delete (optinal).
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod fbml_getCustomTags \
				{facebook.fbml.getCustomTags} {app_id {}}
  #
  # Get the custom tags for an application. If app_id
  # is not specified, the calling app's tags are returned.
  # If app_id is different from the id of the calling app,
  # only the app's public tags are returned.
  # The return value is an array of the same type as
  # the tags parameter of fbml_registerCustomTags().
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array containing the custom tag  objects.
  # <in> app_id the application's id (optional)
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod fbml_refreshImgSrc \
					{facebook.fbml.refreshImgSrc} url
  #
  # Fetches and re-caches the image stored at the given URL, for use in images
  # published to non-canvas pages via the API (for example, to user profiles
  # via profile.setFBML, or to News Feed via feed.publishUserAction).
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> url  The absolute URL from which to refresh the image.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod fbml_refreshRefUrl \
					{facebook.fbml.refreshRefUrl} url
  #
  # Fetches and re-caches the content stored at the given URL, for use in an
  # fb:ref FBML tag.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> url  The absolute URL from which to fetch content. This URL
  #                     should be used in a fb:ref FBML tag.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod fbml_registerCustomTags \
				{facebook.fbml.registerCustomTags} tags
  #
  # Register custom tags for the application. Custom tags can be used
  # to extend the set of tags available to applications in FBML
  # markup.
  #
  # Before you call this function,
  # make sure you read the full documentation at
  #
  # [url] http://wiki.developers.facebook.com/index.php/Fbml.RegisterCustomTags
  #
  # IMPORTANT: This function overwrites the values of
  # existing tags if the names match. Use this function with care because
  # it may break the FBML of any application that is using the
  # existing version of the tags.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 The number of tags that were registered.
  # <in> tags An array of tag objects (the full description is on the
  #   wiki page).
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod fbml_setRefHandle \
					{facebook.fbml.setRefHandle} handle fbml
  #
  # Associates a given ``handle'' with FBML markup so that the handle can be
  # used within the fb:ref FBML tag. A handle is unique within an application
  # and allows an application to publish identical FBML to many user profiles
  # and do subsequent updates without having to republish FBML on behalf of
  # each user.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> handle  The handle to associate with the given FBML.
  # <in> fbml    The FBML to associate with the given handle.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod fbml_uploadNativeStrings \
			{facebook.fbml.uploadNativeStrings} native_strings
  #
  # Lets you insert text strings in their native language into the Facebook
  # Translations database so they can be translated.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 Number of strings uploaded.
  # <in> native_strings  An array of maps, where each map has a 'text'
  #                               field and a 'description' field.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod feed_deactivateTemplateBundleByID \
			{facebook.feed.deactivateTemplateBundleByID} \
			template_bundle_id
  #
  # Deactivates a previously registered template bundle.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> template_bundle_id  The template bundle id.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod feed_getAppFriendStories \
					{facebook.feed.getAppFriendStories}
  #
  # For the current user, retrieves stories generated by the user's friends
  # while using this application.  This can be used to easily create a
  # ``News Feed'' like experience.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of feed story objects.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod feed_getRegisteredTemplateBundleByID \
			{facebook.feed.getRegisteredTemplateBundleByID} \
			template_bundle_id
  #
  # Retrieves information about a specified template bundle previously
  # registered by the requesting application.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 The template bundle.
  # <in> string $template_bundle_id  The template bundle id
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod feed_getRegisteredTemplateBundles \
			{facebook.feed.getRegisteredTemplateBundles}
  #
  # Retrieves the full list of active template bundles registered by the
  # requesting application.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of template bundles.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod feed_publishTemplatizedAction \
			{facebook.feed.publishTemplatizedAction} \
			title_template title_data body_template body_data \
			body_general {image_1 {}} {image_1_link {}} \
			{image_2 {}} {image_2_link {}} {image_3 {}} \
			{image_3_link {}} {image_4 {}} {image_4_link {}} \
			{target_ids {}} {page_actor_id {}}
  #
  # This method is deprecated for calls made on behalf of users. This method
  # works only for publishing stories on a Facebook Page that has installed
  # your application. To publish stories to a user's profile, use
  # feed.publishUserAction instead.
  #
  # For more details on this call, please visit the wiki page:
  #
  # [url] http://wiki.developers.facebook.com/index.php/Feed.publishTemplatizedAction
  #

    typemethod STORY_SIZE_ONE_LINE {} {return 1}
    typemethod STORY_SIZE_SHORT {} {return 2}
    typemethod STORY_SIZE_FULL {} {return 4}

    method feed_publishUserAction {result_var template_bundle_id template_data
				   target_ids body_general
				   {story_size {}}} {
  #
  # Publishes a story on behalf of the user owning the session, using the
  # specified template bundle. This method requires an active session key in
  # order to be called.
  #
  # The parameters to this method ($templata_data in particular) are somewhat
  # involved.  It's recommended you visit the wiki for details:
  #
  #  [url] http://wiki.developers.facebook.com/index.php/Feed.publishUserAction
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> template_bundle_id  A template bundle id previously registered.
  # <in> template_data     See wiki article for syntax.
  # <in> target_ids        (Optional) An array of friend uids of the
  #                                 user who shared in this action.
  # <in> body_general     (Optional) Additional markup that extends
  #                                 the body of a short story.
  # <in> story_size          (Optional) A story size (see above).
  #
  # <return> bool True if success, false if not.
  #

      upvar $result_var result
      if {[string length "$story_size"]} {
	set story_size [::Facebook::FacebookRestClient STORY_SIZE_ONE_LINE]
      }
      # allow client to either pass in JSON or an assoc that we JSON for them
      if {[llength $template_data] > 1} {
	set template_data [::Facebook::json encode_object $template_data]
      }
      if {[llength $target_ids] > 1} {
	set target_ids [::Facebook::json encode_list $target_ids]
	set target_ids [string trim $target_ids {[]}]; #we don't want square brackets
      }
      return [$self call_method result {facebook.feed.publishUserAction} [list \
	template_bundle_id $template_bundle_id \
	template_data      $template_data \
	target_ids	   $target_ids \
	body_general	   $body_general \
	story_size         $story_size]]
    }

    method feed_registerTemplateBundle {one_line_story_templates 
					{short_story_templates {}} 
					{full_story_template {}} 
					{action_links {}}} {
  #
  # Registers a template bundle.  Template bundles are somewhat involved, so
  # it's recommended you check out the wiki for more details:
  #
  #  [url] http://wiki.developers.facebook.com/index.php/Feed.registerTemplateBundle
  #
  # <ref> result Name of an array to be filled in the results.
  #		 A template bundle id.
  # <return> bool True if success, false if not.
  #

      set one_line_story_templates [::Facebook::json encode_list $one_line_story_templates]
      if {[llength $short_story_templates] > 0} {
	set short_story_templates [::Facebook::json encode_list $short_story_templates]
      }
      if {[llength $full_story_template] > 0} {
	set full_story_template [::Facebook::json encode_object $full_story_template]
      }
      if {[llength $action_links] > 0} {
	set action_links [::Facebook::json encode_list $action_links]
      }
      return [$self call_method result {feed.registerTemplateBundle} [list \
	one_line_story_templates $one_line_story_templates \
	short_story_templates    $short_story_templates \
	full_story_template      $full_story_template \
	action_links		 $action_links]]
    }

    ::Facebook::facebookCallMethod fql_query {facebook.fql.query} query
  #
  # Makes an FQL query.  This is a generalized way of accessing all the data
  # in the API, as an alternative to most of the other method calls.  More
  # info at 
  # [url] http://developers.facebook.com/documentation.php?v=1.0&doc=fql
  #
  # <ref> result Name of an array to be filled in the results.
  #		 Generalized array representing the results.
  # <in> query  the query to evaluate
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod friends_areFriends \
				{facebook.friends.areFriends} uids1 uids2
  #
  # Returns whether or not pairs of users are friends.
  # Note that the Facebook friend relationship is symmetric.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array with uid1, uid2, and bool if friends, e.g.:
  #   array(0 : array(`uid1' : id_1, `uid2' : id_A, `are_friends' : 1),
  #         1 : array(`uid1' : id_2, `uid2' : id_B, `are_friends' : 0)
  #         ...).
  # <in> uids1  comma-separated list of ids (id_1, id_2,...)
  #                       of some length X.
  # <in> uids2  comma-separated list of ids (id_A, id_B,...)
  #                       of SAME length X.
  #
  # <return> bool True if success, false if not.
  # <error> API_EC_PARAM_USER_ID_LIST
  #

    method friends_get {{flid {}} {uid 0}} {
  #
  # Returns the friends of the current session user.
  #
  # <in> flid  (Optional) Only return friends on this friend list.
  # <in> uid   (Optional) Return friends for this user.
  #
  # <return> A list of friends
  #  Uses a cached list of friends of the current user to 
  #  reduce overhead.
  #

      if {$uid == 0 || $uid = $user} {
        if {[info exists friends_list]} {
	  if {[llength $flid] == 0} {
	    return $friends_list
	  } else {
	    set result {}
	    foreach fid $flid {
	      if {[lsearch $friends_list $fid]} {lappend result $fid}
	    }
	    return $result
	  }
	}
      }
      set params {}
      if {$uid == 0 && [info exists canvas_user]} {set uid $canvas_user}
      if {$uid} {lappend params uid $uid}
      if {[llength $flid] > 0} {lappend params flid $flid}
      if {[$self call_method result {facebook.friends.get} $params]} {
	return $result(uid)
      } else {
	return {}
      }
    }

    ::Facebook::facebookCallMethod friends_getAppUsers \
				{facebook.friends.getAppUsers}
  #
  # Returns the friends of the session user, who are also users
  # of the calling application.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of friends also using the app.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod friends_getLists \
				{facebook.friends.getLists}
  #
  # Returns the set of friend lists for the current session user.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of friend list objects.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod groups_get {facebook.groups.get} uid gids
  #
  # Returns groups according to the filters specified.
  # 
  # <in> uid     (Optional) User associated with groups.  A null
  #                    parameter will default to the session user.
  # <in> gids (Optional) Comma-separated group ids to query. A null
  #                     parameter will get all groups for the user.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of group objects.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod groups_getMembers \
					{facebook.groups.getMembers} gid
  #
  # Returns the membership list of a group.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array with four membership lists, with keys `members',
  #                `admins', `officers', and `not_replied'.
  # <in> gid  Group id
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod marketplace_createListing \
				{facebook.marketplace.createListing} \
				listing_id show_on_profile attrs {uid {}}
  #
  # Create/modify a Marketplace listing for the loggedinuser.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 The listing_id (unchanged if modifying an existing listing).
  # <in> int              listing_id  The id of a listing to be modified, 0
  #                                     for a new listing.
  # <in> show_on_profile          Should we show this listing on the
  #                                     user's profile.
  # <in> listing_attrs           An array of the listing data.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod marketplace_getCategories \
				{facebook.marketplace.getCategories}
  #
  # Get all the marketplace categories.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 A list of category names.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod marketplace_getListings \
				{facebook.marketplace.getListings} \
				listing_ids uids
  #
  # Get listings by either listing_id or user.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 The data for matched listings.
  # <in> listing_ids   An array of listing_ids (optional).
  # <in> uids          An array of user ids (optional).
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod marketplace_getSubCategories \
				{facebook.marketplace.getSubCategories} category
  #
  # Get all the marketplace subcategories for a particular category.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 A list of subcategory names.
  # <in>  category  The category for which we are pulling subcategories.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod marketplace_getCategories \
				{facebook.marketplace.getCategories} 
  #
  # Get all the marketplace categories.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 A list of category names.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod marketplace_getListings \
				{facebook.marketplace.getListings} \
				listing_ids uids
  #
  # Get listings by either listing_id or user.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 The data for matched listings.
  # <in> listing_ids   An array of listing_ids (optional).
  # <in> uids          An array of user ids (optional).
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod marketplace_getSubCategories \
				{facebook.marketplace.getSubCategories} category
  #
  # Get all the marketplace subcategories for a particular category.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 A list of subcategory names.
  # <in>  category  The category for which we are pulling subcategories.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod marketplace_removeListing \
				{facebook.marketplace.removeListing} \
				listing_id {status DEFAULT} {uid {}}
  #
  # Remove a listing from marketplace.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> listing_id  The id of the listing to be removed.
  # <in> status      One of `SUCCESS', `NOT_SUCCESS', or `DEFAULT'.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod marketplace_search \
				{facebook.marketplace.search} \
				category subcategory query
  #
  # Search for Marketplace listings.  All arguments are optional, though at
  # least one must be filled out to retrieve results.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 The data for matched listings.
  # <in> category     The category in which to search (optional).
  # <in> subcategory  The subcategory in which to search (optional).
  # <in> query        A query string (optional).
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod notifications_get \
				{facebook.notifications.get}
  #
  # Returns the outstanding notifications for the session user.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An assoc array of notification count objects for
  #               `messages', `pokes' and `shares', a uid list of
  #               `friend_requests', a gid list of `group_invites',
  #               and an eid list of `event_invites'.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod notifications_send \
				{facebook.notifications.send}
  #
  # Returns the outstanding notifications for the session user.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An assoc array of notification count objects for
  #               `messages', `pokes' and `shares', a uid list of
  #               `friend_requests', a gid list of `group_invites',
  #               and an eid list of `event_invites'.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod notifications_sendEmail \
				{facebook.notifications.sendEmail} \
				recipients subject text fbml
  #
  # Sends an email to the specified user of the application.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 A comma separated list of successful recipients.
  # <in> recipients comma-separated ids of the recipients
  # <in> subject    The subject of the email.
  # <in> text       The (plain text) body of the email.
  # <in> fbml       The fbml markup for an html version of the email.
  #
  # <return> bool True if success, false if not.
  # <error> API_EC_PARAM_USER_ID_LIST
  #


    method pages_getInfo {result_var page_ids fields uid _type} {
  #
  # Returns the requested info fields for the requested set of pages.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of pages.
  # <in> page_ids  A comma-separated list of page ids.
  # <in> fields    A comma-separated list of strings describing the
  #                           info fields desired.
  # <in> uid       (Optional) limit results to pages of which this
  #                          user is a fan.
  # <in> type       Limits results to a particular type of page.
  #
  # <return> bool True if success, false if not.
  #
      upvar $result_var result
      return [$self call_method result {facebook.pages.getInfo} [list \
	page_ids $page_ids fields $fields uid $uid type $_type]]
    }
    
    ::Facebook::facebookCallMethod pages_isAdmin \
				{facebook.pages.isAdmin} page_id {uid {}}
  #
  # Returns true if the given user is an admin for the passed page.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> page_id  The target page id.
  # <in> uid      (Optional) user id (defaults to the logged-in user).
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod pages_isAppAdded \
				{facebook.pages.isAppAdded} page_id
  #
  # Returns whether or not the given page has added the application.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> page_id  target page id
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod pages_isFan \
				{facebook.pages.isFan} page_id {uid {}}
  #
  # Returns true if logged in user is a fan for the passed page.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> page_id The target page id.
  # <in> uid user to compare.  If empty, the logged in user.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod photos_addTag \
				{facebook.photos.addTag} \
				pid tag_uid tag_text x y tags {owner_uid 0}
  #
  # Adds a tag with the given information to a photo. See the wiki for details:
  #
  #  [url] http://wiki.developers.facebook.com/index.php/Photos.addTag
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> pid          The ID of the photo to be tagged.
  # <in> tag_uid      The ID of the user being tagged. You must specify
  #                          either the tag_uid or the tag_text parameter
  #                          (unless tags is specified).
  # <in> tag_text  Some text identifying the person being tagged.
  #                          You must specify either the $tag_uid or $tag_text
  #                          parameter (unless $tags is specified).
  # <in> x          The horizontal position of the tag, as a
  #                          percentage from 0 to 100, from the left of the
  #                          photo.
  # <in> y          The vertical position of the tag, as a percentage
  #                          from 0 to 100, from the top of the photo.
  # <in> tags       (Optional) An array of maps, where each map
  #                          can contain the tag_uid, tag_text, x, and y
  #                          parameters defined above.  If specified, the
  #                          individual arguments are ignored.
  # <in> owner_uid    (Optional)  The user ID of the user whose photo
  #                          you are tagging. If this parameter is not
  #                          specified, then it defaults to the session user.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod photos_createAlbum \
				{facebook.photos.createAlbum} \
				name {description {}} {location {}} \
				{visible {}} {uid 0}
  #
  # Creates and returns a new album owned by the specified user or the current
  # session user.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An album object.
  # <in> name         The name of the album.
  # <in> description  (Optional) A description of the album.
  # <in> location     (Optional) A description of the location.
  # <in> visible      (Optional) A privacy setting for the album.
  #                             One of `friends', `friends-of-friends',
  #                             `networks', or `everyone'.  Default `everyone'.
  # <in> uid             (Optional) User id for creating the album; if
  #                             not specified, the session user is used.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod photos_get \
				{facebook.photos.get} subj_id aid pids
  #
  # Returns photos according to the filters specified.
  #
  # Note that at least one of subj_id, aid or pids needs to be specified, or an
  # error is returned.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of photo objects.
  # <in> subj_id  (Optional) Filter by uid of user tagged in the photos.
  # <in> aid      (Optional) Filter by an album, as returned by
  #                      photos_getAlbums.
  # <in> pids   (Optional) Restrict to a comma-separated list of pids
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod photos_getAlbums \
				{facebook.photos.getAlbums} uid aids
  #
  # Returns the albums created by the given user.
  #
  # Note that at least one of the (uid, aids) parameters must be specified.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of album objects.
  # <in> uid      (Optional) The uid of the user whose albums you want.
  #                       A null will return the albums of the session user.
  # <in> aids  (Optional) A comma-separated list of aids to restricti
  #                       the query.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod photos_getTags \
				{facebook.photos.getTags} pids
  #
  # Returns the tags on all photos specified.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of photo tag objects, which include pid,
  #                subject uid, and two floating-point numbers (xcoord, ycoord)
  #                for tag pixel location.
  # <in> string $pids  A list of pids to query
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod photos_upload \
				{facebook.photos.upload} \
				file {aid {}} {caption {}} {uid {}}
  #
  # Uploads a photo.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of user objects.
  # <in> file     The location of the photo on the local filesystem.
  # <in> aid         (Optional) The album into which to upload the
  #                         photo.
  # <in> caption  (Optional) A caption for the photo.
  # <in> int uid          (Optional) The user ID of the user whose photo you
  #                         are uploading.
  #
  # <return> bool True if success, false if not.
  #

    method profile_getFBML {result_var {uid {}} {_type {}}} {
  #
  # Gets the FBML for the profile box that is currently set for a user's
  # profile (your application set the FBML previously by calling the
  # profile.setFBML method).
  #
  # <ref> result Name of an array to be filled in the results.
  #		 The FBML.
  # <in> uid   (Optional) User id to lookup; defaults to session.
  # <in> type  (Optional) 1 for original style, 2 for profile_main boxes
  #
  # <return> bool True if success, false if not.
  #
      upvar $result_var result
      return [$self call_method result {facebook.profile.getFBML} [list \
	uid $uid type $_type]]
    }

    ::Facebook::facebookCallMethod profile_getInfo \
				{facebook.profile.getInfo} {uid {}}
  #
  # Returns the specified user's application info section for the calling
  # application. These info sections have either been set via a previous
  # profile.setInfo call or by the user editing them directly.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 Info fields for the current user.  See wiki for structure:
  #
  #  [url] http://wiki.developers.facebook.com/index.php/Profile.getInfo
  #
  # <in> uid  (Optional) User id to lookup; defaults to session.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod profile_getInfoOptions \
				{facebook.profile.getInfoOptions} field
  #
  # Returns the options associated with the specified info field for an
  # application info section.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of info options.
  # <in> field  The title of the field
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod profile_setFBML \
				{facebook.profile.setFBML} \
				markup {uid {}} {profile {}} \
				{profile_action {}} {mobile_profile {}} \
				{profile_main {}}
  #
  # Sets the FBML for the profile of the user attached to this session.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 A list of strings describing any compile errors for the
  #                 submitted FBML.
  # <in>   markup           The FBML that describes the profile
  #                                     presence of this app for the user.
  # <in>   uid              The user.
  # <in>   profile          Profile FBML.
  # <in>   profile_action   Profile action FBML (deprecated).
  # <in>   mobile_profile   Mobile profile FBML.
  # <in>   profile_main     Main Tab profile FBML.
  #
  # <return> bool True if success, false if not.
  #

    method profile_setInfo {result_var title _type info_fields {uid {}}} {
  #
  # Configures an application info section that the specified user can install
  # on the Info tab of her profile.  For details on the structure of an info
  # field, please see:
  #
  #  [url] http://wiki.developers.facebook.com/index.php/Profile.setInfo
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> title       Title / header of the info section.
  # <in> type           1 for text-only, 5 for thumbnail views.
  # <in> info_fields  An array of info fields. See wiki for details.
  # <in> uid            (Optional).
  #
  # <return> bool True if success, false if not.
  #
      upvar $result_var result
      return [$self call_method result {facebook.profile.setInfo} [list \
				title $title type $_type \
                                info_fields $info_fields uid $uid]]
    }

    ::Facebook::facebookCallMethod profile_setInfoOptions \
				{facebook.profile.setInfoOptions} field options
  #
  # Specifies the objects for a field for an application info section. These
  # options populate the typeahead for a thumbnail.
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> field   The title of the field.
  # <in> options  An array of items for a thumbnail, including
  #                        `label', `link', and optionally `image',
  #                        `description' and `sublabel'.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod users_getInfo \
				{facebook.users.getInfo} uids fields
  #
  # Returns the requested info fields for the requested set of users.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of user objects.
  # <in> uids    A comma-separated list of user ids.
  # <in> fields  A comma-separated list of info field names desired.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod users_getLoggedInUser \
				{facebook.users.getLoggedInUser}
  #
  # Returns the user corresponding to the current session object.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 The user id.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod users_getStandardInfo \
				{facebook.users.getStandardInfo} uids fields
  #
  # Returns the requested info fields for the requested set of users. A
  # session key must not be specified. Only data about users that have
  # authorized your application will be returned.
  #
  # Check the wiki for fields that can be queried through this API call.
  # Data returned from here should not be used for rendering to application
  # users, use users.getInfo instead, so that proper privacy rules will be
  # applied.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array of user objects.
  # <in> uids    A comma-separated list of user ids
  # <in> fields  A comma-separated list of info field names desired.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod users_hasAppPermission \
				{facebook.users.hasAppPermission} ext_perm {uid {}}
  #
  # Returns 1 if the user has the specified permission, 0 otherwise.
  # [url] http://wiki.developers.facebook.com/index.php/Users.hasAppPermission
  #
  # <ref> result Name of an array to be filled in the results.
  #		 1 or 0.
  # <return> bool True if success, false if not.
  #

#    ::Facebook::facebookCallMethod users_isAppAdded {facebook.users.isAppAdded}

    ::Facebook::facebookCallMethod users_isAppUser \
				{facebook.users.isAppUser} {uid {}}
  #
  # Returns whether or not the user corresponding to the current
  # session object has the give the app basic authorization.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 True if the user has authorized the app.
  # <in> uid     The user id.
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod users_setStatus \
				{facebook.users.setStatus} status {uid {}} \
				{clear false} {status_includes_verb true}
  #
  # Sets the users' current status message. Message does NOT contain the
  # word ``is'' , so make sure to include a verb.
  #
  # Example: setStatus(``is loving the API!'')
  # will produce the status ``Luke is loving the API!''
  #
  # <ref> result Name of an array to be filled in the results.
  # <in> status                Text-only message to set.
  # <in> uid                   User to set for (defaults to the
  #                                      logged-in user).
  # <in> clear                 Whether or not to clear the status,
  #                                      instead of setting it.
  # <in> status_includes_verb  If true, the word ``is'' will NOT be
  #                                      prepended to the status message.
  #
  # <return> bool True if success, false if not.
  #

    ::Facebook::facebookCallMethod video_upload \
				{facebook.video.upload} file {title {}} \
				{description {}}
  #
  # Uploads a video.
  #
  # <ref> result Name of an array to be filled in the results.
  #		 An array with the video's ID, title, description, and a link to view it on Facebook.
  # <in>  file        The location of the video on the local filesystem.
  # <in>  title       (Optional) A title for the video. Titles over 65 characters in length will be truncated.
  # <in>  description (Optional) A description for the video.
  #
  # <return> bool True if success, false if not.
  #
    
    #******* UTILITY FUNCTIONS 

    method set_friends_list {flist} {set friends_list $flist}
    method set_added {flag} {set added $flag}
    method added-p {} {return $added}


    method call_method {result_var method params} {
      upvar $result_var result
      catch {unset result}
      set error_code 0
      if {[string length $call_as_apikey] > 0} {
	lappend params call_as_apikey $call_as_apikey
      }
      set xml [$self post_request $method $params]
      #puts stderr "*** $self call_method: xml = $xml"
      set _result [::Facebook::simpleParseXML Parse $xml]
      #cgi_puts stderr "*** $self call_method: _result = $_result"
      array set result $_result
      if {[info exists result(error_code)]} {
	set error_code $result(error_code)
	set error_message $result(error_msg)
	array unset result
	return false
      } else {
        return true
      }
    }
    method post_request {method params} {
      lappend params method $method
      lappend params session_key $options(-session_key)
      lappend params api_key $options(-api_key)
      set call_id [expr {double([clock seconds])}]
      if {$call_id <= $last_call_id} {
	set call_id [expr {$last_call_id + 0.001}]
      }
      lappend params call_id $call_id
      if {[expr {[lsearch $params v] % 2}] != 0} {
	lappend params v 1.0
      }
      set post_params {}
      #puts stderr "*** $self post_request: params = $params"
      foreach {key val} $params {
	if {[llength $val] > 1} {
	  set val [join $val ,]
	}
        lappend post_params "$key=[$cgi_methods quote_url $val]"
        set param_array($key) $val
	
      }
      #puts stderr "*** $self post_request (after loop): params = $params"
      #puts stderr "*** $self post_request: post_params = $post_params"
      #puts stderr "*** $self post_request: param_array:"
      #foreach k [array names param_array] {
      #	puts stderr "*** $self post_request: param_array($k) = $param_array($k)"
      #}
      lappend post_params "sig=[::Facebook::Facebook generate_sig param_array $options(-secret)]"
      #puts stderr "*** $self post_request (with sig): post_params = $post_params"
      set post_string [join $post_params &]
      set token [::http::geturl $server_addr \
		-headers [list User-Agent "Facebook API Tcl Client [package present Facebook]"] \
		-query $post_string]
      switch [::http::status $token] {
	ok {
	  if {[::http::ncode $token] != 200} {
	    set error [::http::code $token]
	    http::cleanup $token
	    error "Facebook returns HTTP error status: $error"
	  }
	  #puts stderr "*** $self post_request: token = $token"
	  #cgi_parray $token
          set data [::http::data $token]
	  http::cleanup $token
	  return $data
	}
	eof {
	  http::cleanup $token
	  error "Facebook returns EOF!"
	}
        error {
	  set error [::http::code $token]
	  http::cleanup $token
	  error "Error reading from Facebook: $error"
	}
      }
    }
  }
  snit::type FacebookAPIErrorCodes {
    pragma -hastypeinfo    no
    pragma -hastypedestroy no
    pragma -hasinstances   no

    typemethod API_EC_SUCCESS 	{} {
      #Success 	 (all) 
      return 0 	
    }

    # General Errors

    typemethod API_EC_UNKNOWN 	{} {
      #An unknown error occurred	 (all) 
      return 1 	
    }
    typemethod API_EC_SERVICE 	{} {
      #Service temporarily unavailable	 (all) 
      return 2 	
    }
    typemethod API_EC_METHOD 	{} {
      #Unknown method
      return 3 	
    }
    typemethod API_EC_TOO_MANY_CALLS 	{} {
      #Application request limit reached	 (all) 
      return 4 	
    }
    typemethod API_EC_BAD_IP 	{} {
      #Unauthorized source IP address	 (all) 
      return 5 	
    }
    typemethod API_EC_HOST_API 	{} {
      #This method must run on api.facebook.com	 (all) 
      return 6 	
    }
    typemethod API_EC_HOST_UP 	{} {
      #This method must run on api-video.facebook.com
      return 7 	
    }
    typemethod API_EC_SECURE 	{} {
      #This method requires an HTTPS connection
      return 8 	
    }
    typemethod API_EC_RATE 	{} {
      #User is performing too many actions
      return 9 	
    }
    typemethod API_EC_PERMISSION_DENIED 	{} {
      #Application does not have permission for this action
      return 10 	
    }
    typemethod API_EC_DEPRECATED 	{} {
      #This method is deprecated
      return 11 	
    }
    typemethod API_EC_VERSION 	{} {
      #This API version is deprecated
      return 12 	
    }

    # Parameter Errors

    typemethod API_EC_PARAM 	{} {
      #Invalid parameter	 (all) 
      return 100 	
    }
    typemethod API_EC_PARAM_API_KEY 	{} {
      #Invalid API key	 (all) 
      return 101 	
    }
    typemethod API_EC_PARAM_SESSION_KEY 	{} {
      #Session key invalid or no longer valid(all) 
      return 102 	
    }
    typemethod API_EC_PARAM_CALL_ID 	{} {
      #Call_id must be greater than previous
      return 103 	
    }
    typemethod API_EC_PARAM_SIGNATURE 	{} {
      #Incorrect signature	(all) 
      return 104 	
    }
    typemethod API_EC_PARAM_TOO_MANY 	{} {
      #The number of parameters exceeded the maximum for this operation
      return 105 	
    }
    typemethod API_EC_PARAM_USER_ID 	{} {
      #Invalid user id 	photos.addTag
      return 110 	
    }
    typemethod API_EC_PARAM_USER_FIELD 	{} {
      #Invalid user info field
      return 111 	
    }
    typemethod API_EC_PARAM_SOCIAL_FIELD 	{} {
      #Invalid user field
      return 112 	
    }
    typemethod API_EC_PARAM_EMAIL 	{} {
      #Invalid email
      return 113 	
    }
    typemethod API_EC_PARAM_ALBUM_ID 	{} {
      #Invalid album id
      return 120 	
    }
    typemethod API_EC_PARAM_PHOTO_ID 	{} {
      #Invalid photo id
      return 121 	
    }
    typemethod API_EC_PARAM_FEED_PRIORITY 	{} {
      #Invalid feed publication priority
      return 130 	
    }
    typemethod API_EC_PARAM_CATEGORY 	{} {
      #Invalid category
      return 140 	
    }
    typemethod API_EC_PARAM_SUBCATEGORY 	{} {
      #Invalid subcategory
      return 141 	
    }
    typemethod API_EC_PARAM_TITLE 	{} {
      #Invalid title
      return 142 	
    }
    typemethod API_EC_PARAM_DESCRIPTION 	{} {
      #Invalid description
      return 143 	
    }
    typemethod API_EC_PARAM_BAD_JSON 	{} {
      #Malformed JSON string
      return 144 	
    }
    typemethod API_EC_PARAM_BAD_EID 	{} {
      #Invalid eid
      return 150 	
    }
    typemethod API_EC_PARAM_UNKNOWN_CITY 	{} {
      #Unknown city
      return 151 	
    }
    typemethod API_EC_PARAM_BAD_PAGE_TYPE 	{} {
      #Invalid page type
      return 152 	
    }

    # User Permission Errors

    typemethod API_EC_PERMISSION 	{} {
      #Permissions error
      return 200 	
    }
    typemethod API_EC_PERMISSION_USER 	{} {
      #User not visible
      return 210 	
    }
    typemethod API_EC_PERMISSION_ALBUM 	{} {
      #Album or albums not visible
      return 220 	
    }
    typemethod API_EC_PERMISSION_PHOTO 	{} {
      #Photo not visible
      return 221 	
    }
    typemethod API_EC_PERMISSION_MESSAGE 	{} {
      #Permissions disallow message to user
      return 230 	
    }
    typemethod API_EC_PERMISSION_MARKUP_OTHER_USER 	{} {
      #Desktop applications cannot set FBML for other users
      return 240 	
    }
    typemethod API_EC_PERMISSION_STATUS_UPDATE 	{} {
      #Updating status requires the extended permission status_update. 	users.setStatus
      return 250 	
    }
    typemethod API_EC_PERMISSION_PHOTO_UPLOAD 	{} {
      #Modifying existing photos requires the extended permission photo_upload 	photos.upload, photos.addTag
      return 260 	
    }
    typemethod API_EC_PERMISSION_SMS 	{} {
      #Permissions disallow sms to user.
      return 270 	
    }
    typemethod API_EC_PERMISSION_CREATE_LISTING 	{} {
      #Creating and modifying listings requires the extended permission create_listing
      return 280 	
    }
    typemethod API_EC_PERMISSION_CREATE_NOTE 	{} {
      #Managing notes requires the extended permission create_note.
      return 281 	
    }
    typemethod API_EC_PERMISSION_SHARE_ITEM 	{} {
      #Managing shared items requires the extended permission share_item.
      return 282 	
    }
    typemethod API_EC_PERMISSION_EVENT 	{} {
      #Creating and modifying events requires the extended permission create_event
      return 290 	
    }
    typemethod API_EC_PERMISSION_LARGE_FBML_TEMPLATE 	{} {
      #FBML Template isn't owned by your application.
      return 291 	
    }
    typemethod API_EC_PERMISSION_LIVEMESSAGE 	{} {
      #An application is only allowed to send LiveMessages to users who have accepted the TOS for that application.
      return 292 	
    }
    typemethod API_EC_PERMISSION_RSVP_EVENT 	{} {
      #RSVPing to events requires the extended permission create_rsvp
      return 299 	
    }

    # Data Editing Errors

    typemethod API_EC_EDIT 	{} {
      #Edit failure
      return 300 	
    }
    typemethod API_EC_EDIT_USER_DATA 	{} {
      #User data edit failure
      return 310 	
    }
    typemethod API_EC_EDIT_PHOTO 	{} {
      #Photo edit failure
      return 320 	
    }
    typemethod API_EC_EDIT_ALBUM_SIZE 	{} {
      #Album is full
      return 321 	
    }
    typemethod API_EC_EDIT_PHOTO_TAG_SUBJECT 	{} {
      #Invalid photo tag subject
      return 322 	
    }
    typemethod API_EC_EDIT_PHOTO_TAG_PHOTO 	{} {
      #Cannot tag photo already visible on Facebook
      return 323 	
    }
    typemethod API_EC_EDIT_PHOTO_FILE 	{} {
      #Missing or invalid image file
      return 324 	
    }
    typemethod API_EC_EDIT_PHOTO_PENDING_LIMIT 	{} {
      #Too many unapproved photos pending
      return 325 	
    }
    typemethod API_EC_EDIT_PHOTO_TAG_LIMIT 	{} {
      #Too many photo tags pending
      return 326 	
    }
    typemethod API_EC_EDIT_ALBUM_REORDER_PHOTO_NOT_IN_ALBUM 	{} {
      #Input array contains a photo not in the album
      return 327 	
    }
    typemethod API_EC_EDIT_ALBUM_REORDER_TOO_FEW_PHOTOS 	{} {
      #Input array has too few photos
      return 328 	
    }
    typemethod API_EC_MALFORMED_MARKUP 	{} {
      #Template data must be a JSON-encoded dictionary, of the form {`key-1': `value-1', `key-2': `value-2', ...}
      return 329 	
    }
    typemethod API_EC_EDIT_MARKUP 	{} {
      #Failed to set markup
      return 330 	
    }
    typemethod API_EC_EDIT_FEED_TOO_MANY_USER_CALLS 	{} {
      #Feed publication request limit reached
      return 340 	
    }
    typemethod API_EC_EDIT_FEED_TOO_MANY_USER_ACTION_CALLS 	{} {
      #Feed action request limit reached
      return 341 	
    }
    typemethod API_EC_EDIT_FEED_TITLE_LINK 	{} {
      #Feed story title can have at most one href anchor
      return 342 	
    }
    typemethod API_EC_EDIT_FEED_TITLE_LENGTH 	{} {
      #Feed story title is too long
      return 343 	
    }
    typemethod API_EC_EDIT_FEED_TITLE_NAME 	{} {
      #Feed story title can have at most one fb:userlink and must be of the user whose action is being reported
      return 344 	
    }
    typemethod API_EC_EDIT_FEED_TITLE_BLANK 	{} {
      #Feed story title rendered as blank
      return 345 	
    }
    typemethod API_EC_EDIT_FEED_BODY_LENGTH 	{} {
      #Feed story body is too long
      return 346 	
    }
    typemethod API_EC_EDIT_FEED_PHOTO_SRC 	{} {
      #Feed story photo could not be accessed or proxied
      return 347 	
    }
    typemethod API_EC_EDIT_FEED_PHOTO_LINK 	{} {
      #Feed story photo link invalid
      return 348 	
    }
    typemethod API_EC_EDIT_VIDEO_SIZE 	{} {
      #Video file is too large
      return 350 	
    }
    typemethod API_EC_EDIT_VIDEO_INVALID_FILE 	{} {
      #Video file was corrupt or invalid
      return 351 	
    }
    typemethod API_EC_EDIT_VIDEO_INVALID_TYPE 	{} {
      #Video file format is not supported
      return 352 	
    }
    typemethod API_EC_EDIT_FEED_TITLE_ARRAY 	{} {
      #Feed story title_data argument was not a valid JSON-encoded array
      return 360 	
    }
    typemethod API_EC_EDIT_FEED_TITLE_PARAMS 	{} {
      #Feed story title template either missing required parameters, or did not have all parameters defined in title_data array
      return 361 	
    }
    typemethod API_EC_EDIT_FEED_BODY_ARRAY 	{} {
      #Feed story body_data argument was not a valid JSON-encoded array
      return 362 	
    }
    typemethod API_EC_EDIT_FEED_BODY_PARAMS 	{} {
      #Feed story body template either missing required parameters, or did not have all parameters defined in body_data array
      return 363 	
    }
    typemethod API_EC_EDIT_FEED_PHOTO 	{} {
      #Feed story photos could not be retrieved, or bad image links were provided
      return 364 	
    }
    typemethod API_EC_EDIT_FEED_TEMPLATE 	{} {
      #The template for this story does not match any templates registered for this application
      return 365 	
    }
    typemethod API_EC_EDIT_FEED_TARGET 	{} {
      #One or more of the target ids for this story are invalid. They must all be ids of friends of the acting user
      return 366 	
    }
    typemethod API_EC_USERS_CREATE_INVALID_EMAIL 	{} {
      #The email address you provided is not a valid email address
      return 370 	
    }
    typemethod API_EC_USERS_CREATE_EXISTING_EMAIL 	{} {
      #The email address you provided belongs to an existing account
      return 371 	
    }
    typemethod API_EC_USERS_CREATE_BIRTHDAY 	{} {
      #The birthday provided is not valid
      return 372 	
    }
    typemethod API_EC_USERS_CREATE_PASSWORD 	{} {
      #The password provided is too short or weak
      return 373 	
    }
    typemethod API_EC_USERS_REGISTER_INVALID_CREDENTIAL 	{} {
      #The login credential you provided is invalid.
      return 374 	
    }
    typemethod API_EC_USERS_REGISTER_CONF_FAILURE 	{} {
      #Failed to send confirmation message to the specified login credential.
      return 375 	
    }
    typemethod API_EC_USERS_REGISTER_EXISTING 	{} {
      #The login credential you provided belongs to an existing account
      return 376 	
    }
    typemethod API_EC_USERS_REGISTER_DEFAULT_ERROR 	{} {
      #Sorry, we were unable to process your registration.
      return 377 	
    }
    typemethod API_EC_USERS_REGISTER_PASSWORD_BLANK 	{} {
      #Your password cannot be blank. Please try another.
      return 378 	
    }
    typemethod API_EC_USERS_REGISTER_PASSWORD_INVALID_CHARS 	{} {
      #Your password contains invalid characters. Please try another.
      return 379 	
    }
    typemethod API_EC_USERS_REGISTER_PASSWORD_SHORT 	{} {
      #Your password must be at least 6 characters long. Please try another.
      return 380 	
    }
    typemethod API_EC_USERS_REGISTER_PASSWORD_WEAK 	{} {
      #Your password should be more secure. Please try another.
      return 381 	
    }
    typemethod API_EC_USERS_REGISTER_USERNAME_ERROR 	{} {
      #Our automated system will not approve this name.
      return 382 	
    }
    typemethod API_EC_USERS_REGISTER_MISSING_INPUT 	{} {
      #You must fill in all of the fields.
      return 383 	
    }
    typemethod API_EC_USERS_REGISTER_INCOMPLETE_BDAY 	{} {
      #You must indicate your full birthday to register.
      return 384 	
    }
    typemethod API_EC_USERS_REGISTER_INVALID_EMAIL 	{} {
      #Please enter a valid email address.
      return 385 	
    }
    typemethod API_EC_USERS_REGISTER_EMAIL_DISABLED 	{} {
      #The email address you entered has been disabled. Please contact disabled@facebook.com with any questions.
      return 386 	
    }
    typemethod API_EC_USERS_REGISTER_ADD_USER_FAILED 	{} {
      #There was an error with your registration. Please try registering again.
      return 387 	
    }
    typemethod API_EC_USERS_REGISTER_NO_GENDER 	{} {
      #Please select either Male or Female.
      return 388 	
    }

    # Authentication Errors

    typemethod API_EC_AUTH_EMAIL 	{} {
      #Invalid email address
      return 400 	
    }
    typemethod API_EC_AUTH_LOGIN 	{} {
      #Invalid username or password
      return 401 	
    }
    typemethod API_EC_AUTH_SIG 	{} {
      #Invalid application auth sig
      return 402 	
    }
    typemethod API_EC_AUTH_TIME 	{} {
      #Invalid timestamp for authentication
      return 403 	
    }

    # Session Errors

    typemethod API_EC_SESSION_METHOD 	{} {
      #Session key specified cannot be used to call this method
      return 451 	
    }
    typemethod API_EC_SESSION_REQUIRED 	{} {
      #A session key is required for calling this method
      return 453 	
    }
    typemethod API_EC_SESSION_REQUIRED_FOR_SECRET 	{} {
      #A session key must be specified when request is signed with a session secret
      return 454 	
    }
    typemethod API_EC_SESSION_CANNOT_USE_SESSION_SECRET 	{} {
      #A session secret is not permitted to be used with this type of session key
      return 455 	
    }

    # Application Messaging Errors

    typemethod API_EC_MESG_BANNED 	{} {
      #Message contains banned content
      return 500 	
    }
    typemethod API_EC_MESG_NO_BODY 	{} {
      #Missing message body
      return 501 	
    }
    typemethod API_EC_MESG_TOO_LONG 	{} {
      #Message is too long
      return 502 	
    }
    typemethod API_EC_MESG_RATE 	{} {
      #User has sent too many messages
      return 503 	
    }
    typemethod API_EC_MESG_INVALID_THREAD 	{} {
      #Invalid reply thread id
      return 504 	
    }
    typemethod API_EC_MESG_INVALID_RECIP 	{} {
      #Invalid message recipient
      return 505 	
    }
    typemethod API_EC_POKE_INVALID_RECIP 	{} {
      #Invalid poke recipient
      return 510 	
    }
    typemethod API_EC_POKE_OUTSTANDING 	{} {
      #There is a poke already outstanding
      return 511 	
    }
    typemethod API_EC_POKE_RATE 	{} {
      #User is poking too fast
      return 512 	
    }

    # FQL Errors

    typemethod FQL_EC_UNKNOWN_ERROR 	{} {
      #An unknown error occurred in FQL 	fql.query
      return 600 	
    }
    typemethod FQL_EC_PARSER_ERROR 	{} {
      #Error while parsing FQL statement 	fql.query
      return 601 	
    }
    typemethod FQL_EC_UNKNOWN_FIELD 	{} {
      #The field you requested does not exist 	fql.query
      return 602 	
    }
    typemethod FQL_EC_UNKNOWN_TABLE 	{} {
      #The table you requested does not exist 	fql.query
      return 603 	
    }
    typemethod FQL_EC_NO_INDEX 	{} {
      #Your statement is not indexable 	fql.query
      return 604 	
    }
    typemethod FQL_EC_UNKNOWN_FUNCTION 	{} {
      #The function you called does not exist 	fql.query
      return 605 	
    }
    typemethod FQL_EC_INVALID_PARAM 	{} {
      #Wrong number of arguments passed into the function 	fql.query
      return 606 	
    }
    typemethod FQL_EC_INVALID_FIELD 	{} {
      #FQL field specified is invalid in this context. 	fql.query*
      return 607 	
    }
    typemethod FQL_EC_INVALID_SESSION 	{} {
      #An invalid session was specified 	fql.query
      return 608 	
    }

    # Ref Errors

    typemethod API_EC_REF_SET_FAILED 	{} {
      #Unknown failure in storing ref data. Please try again.
      return 700 	
    }

    # Application Integration Errors

    typemethod API_EC_FB_APP_UNKNOWN_ERROR 	{} {
      #Unknown Facebook application integration failure.
      return 750 	
    }
    typemethod API_EC_FB_APP_FETCH_FAILED 	{} {
      #Fetch from remote site failed.
      return 751 	
    }
    typemethod API_EC_FB_APP_NO_DATA 	{} {
      #Application returned no data. This may be expected or represent a connectivity error.
      return 752 	
    }
    typemethod API_EC_FB_APP_NO_PERMISSIONS 	{} {
      #Application returned user had invalid permissions to complete the operation.
      return 753 	
    }
    typemethod API_EC_FB_APP_TAG_MISSING 	{} {
      #Application returned data, but no matching tag found. This may be expected.
      return 754 	
    }
    typemethod API_EC_FB_APP_DB_FAILURE 	{} {
      #The database for this object failed.
      return 755 	
    }

    # Data Store API Errors

    typemethod API_EC_DATA_UNKNOWN_ERROR 	{} {
      #Unknown data store API error
      return 800 	
    }
    typemethod API_EC_DATA_INVALID_OPERATION 	{} {
      #Invalid operation
      return 801 	
    }
    typemethod API_EC_DATA_QUOTA_EXCEEDED 	{} {
      #Data store allowable quota was exceeded
      return 802 	
    }
    typemethod API_EC_DATA_OBJECT_NOT_FOUND 	{} {
      #Specified object cannot be found
      return 803 	
    }
    typemethod API_EC_DATA_OBJECT_ALREADY_EXISTS 	{} {
      #Specified object already exists
      return 804 	
    }
    typemethod API_EC_DATA_DATABASE_ERROR 	{} {
      #A database error occurred. Please try again
      return 805 	
    }
    typemethod API_EC_DATA_CREATE_TEMPLATE_ERROR 	{} {
      #Unable to add FBML template to template database. Please try again.
      return 806 	
    }
    typemethod API_EC_DATA_TEMPLATE_EXISTS_ERROR 	{} {
      #No active template bundle with that ID or handle exists.
      return 807 	
    }
    typemethod API_EC_DATA_TEMPLATE_HANDLE_TOO_LONG 	{} {
      #Template bundle handles must contain less than or equal to 32 characters.
      return 808 	
    }
    typemethod API_EC_DATA_TEMPLATE_HANDLE_ALREADY_IN_USE 	{} {
      #Template bundle handle already identifies a previously registered template bundle, and handles can not be reused.
      return 809 	
    }
    typemethod API_EC_DATA_TOO_MANY_TEMPLATE_BUNDLES 	{} {
      #Application has too many active template bundles, and some must be deactivated before new ones can be registered.
      return 810 	
    }
    typemethod API_EC_DATA_MALFORMED_ACTION_LINK 	{} {
      #One of more of the supplied action links was improperly formatted.
      return 811 	
    }
    typemethod API_EC_DATA_TEMPLATE_USES_RESERVED_TOKEN 	{} {
      #One …or more of your templates is using a token reserved by Facebook, such as {*mp3*} or {*video*}.
      return 812 	
    }

    # Mobile/SMS Errors

    typemethod API_EC_SMS_INVALID_SESSION 	{} {
      #Invalid sms session.
      return 850 	
    }
    typemethod API_EC_SMS_MSG_LEN 	{} {
      #Invalid sms message length.
      return 851 	
    }
    typemethod API_EC_SMS_USER_QUOTA 	{} {
      #Over user daily sms quota.
      return 852 	
    }
    typemethod API_EC_SMS_USER_ASLEEP 	{} {
      #Unable to send sms to user at this time.
      return 853 	
    }
    typemethod API_EC_SMS_APP_QUOTA 	{} {
      #Over application daily sms quota/rate limit.
      return 854 	
    }
    typemethod API_EC_SMS_NOT_REGISTERED 	{} {
      #User is not registered for Facebook Mobile Texts
      return 855 	
    }
    typemethod API_EC_SMS_NOTIFICATIONS_OFF 	{} {
      #User has SMS notifications turned off
      return 856 	
    }
    typemethod API_EC_SMS_CARRIER_DISABLE 	{} {
      #SMS application disallowed by mobile operator
      return 857 	
    }

    # Application Information Errors

    typemethod API_EC_NO_SUCH_APP 	{} {
      #No such application exists.
      return 900 	
    }

    # Batch API Errors

    typemethod API_BATCH_TOO_MANY_ITEMS 	{} {
      #Each batch API can not contain more than 20 items
      return 950 	
    }
    typemethod API_EC_BATCH_ALREADY_STARTED 	{} {
      #begin_batch already called, please make sure to call end_batch first.
      return 951 	
    }
    typemethod API_EC_BATCH_NOT_STARTED 	{} {
      #end_batch called before begin_batch.
      return 952 	
    }
    typemethod API_EC_BATCH_METHOD_NOT_ALLOWED_IN_BATCH_MODE 	{} {
      #This method is not allowed in batch mode.
      return 953 	
    }

    # Events API Errors

    typemethod API_EC_EVENT_INVALID_TIME 	{} {
      #Invalid time for an event.
      return 1000 	
    }

    # Info Section Errors

    typemethod API_EC_INFO_NO_INFORMATION 	{} {
      #No information has been set for this user
      return 1050 	
    }
    typemethod API_EC_INFO_SET_FAILED 	{} {
      #Setting info failed. Check the formatting of your info fields.
      return 1051 	
    }

    # LiveMessage Errors

    typemethod API_EC_LIVEMESSAGE_SEND_FAILED 	{} {
      #An error occurred while sending the LiveMessage.
      return 1100 	
    }
    typemethod API_EC_LIVEMESSAGE_EVENT_NAME_TOO_LONG 	{} {
      #The event_name parameter must be no longer than 128 bytes.
      return 1101 	
    }
    typemethod API_EC_LIVEMESSAGE_MESSAGE_TOO_LONG 	{} {
      #The message parameter must be no longer than 1024 bytes.
      return 1102 	
    }

    # Chat Errors

    typemethod API_EC_CHAT_SEND_FAILED	{} {
      #An error occurred while sending the message.
      return 1200 	
    }

    # Facebook Page Errors

    typemethod API_EC_PAGES_CREATE 	{} {
      #You have created too many pages
      return 1201 	
    }

    # Facebook Links Errors

    typemethod API_EC_SHARE_BAD_URL 	{} {
      #The url you supplied is invalid
      return 1500 	
    }


    # Facebook Notes Errors

    typemethod API_EC_NOTE_CANNOT_MODIFY 	{} {
      #The user does not have permission to modify this note.
      return 1600 	
    }

    # Comment Errors

    typemethod API_EC_COMMENTS_UNKNOWN 	{} {
      #An unknown error has occurred.
      return 1700 	
    }
    typemethod API_EC_COMMENTS_POST_TOO_LONG 	{} {
      #The specified post was too long.
      return 1701 	
    }
    typemethod API_EC_COMMENTS_DB_DOWN 	{} {
      #The comments database is down.
      return 1702 	
    }
    typemethod API_EC_COMMENTS_INVALID_XID 	{} {
      #The specified xid is not valid. xids can only contain letters, numbers, and underscores
      return 1703 	
    }
    typemethod API_EC_COMMENTS_INVALID_UID 	{} {
      #The specified user is not a user of this application
      return 1704 	
    }
    typemethod API_EC_COMMENTS_INVALID_POST 	{} {
      #There was an error during posting. 
      return 1705 	
    }
  }
  
  snit::type rivet_methods {
    # Rivet based implementation of cgi_methods
    method import_cookies {arrayVar} {
      upvar $arrayVar array
      load_cookies array
    }
    method import_params {arrayVar} {
      upvar $arrayVar array
      array set array [var all]
    }
    method cookie_set {name value args} {
      eval [list cookie set $name $value] $args
    }
    method http_head {} {
    }
    method location {url} {
      headers redirect $url
    }
    method exit {} {
      ::exit
    }
    method makeurl_from_env {var} {
      return [makeurl [env $var]]
    }
    method quote_url {text} {
    }
  }
  snit::type cgi_api {
    # Don Libes implementation of cgi_methods
    method import_cookies {arrayVar} {
      upvar $arrayVar array
      array set array [array get ::_cgi_cookie]
    }
    method import_params {arrayVar} {
      upvar $arrayVar array
      array set array [array get ::_cgi_uservar]
    }
    method cookie_set {name value args} {
      set doUnset no
      set minutes [from args -minutes -1]
      if {$minutes == 0} {
	set expires now
	set doUnset yes
      } elseif {$minutes > 0} {
	set expires [clock format [clock scan "now + $minutes minutes"] -format {%A, %d-%b-%y %X GMT} -gmt yes]
      } else {
	set expires [from args -expires {}]
      }
      ::cgi_cookie_set "$name=$value" expires=$expires
      if {$doUnset} {
	unset ::_cgi_cookie($name)
      } else {
	set ::_cgi_cookie($name) $value
      }
    }
    method http_head {} {
      ::cgi_http_head
    }
    method location {url} {
      ::cgi_location $url
    }
    method exit {} {
      ::cgi_exit
    }
    method makeurl_from_env {var} {
      global env
      return "http://$env(SERVER_NAME)$env($var)"
    }
    method quote_url {text} {
      return [::cgi_quote_url $text]
    }
  }

}

package provide Facebook 1.4.2
