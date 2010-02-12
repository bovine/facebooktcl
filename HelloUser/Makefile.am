EXTRA_DIST = HelloUser.tcl

HelloUserSCRIPTS = 

HelloUserLibSCRIPTS = $(top_srcdir)/Common/Facebook.tcl \
			$(top_srcdir)/Common/cgi.tcl

bin_SCRIPTS = HelloUser.cgi

CLEANFILES = HelloUser.kit $(bin_SCRIPTS)

HelloUser.cgi: HelloUser.tcl $(HelloUserSCRIPTS) $(HelloUserLibSCRIPTS)
	-rm -rf HelloUser.vfs
	$(TCLKIT) $(SDX) qwrap $(srcdir)/HelloUser.tcl
	$(TCLKIT) $(SDX) unwrap HelloUser.kit
	$(TCLKIT) $(top_srcdir)/BuildScripts/AddKitDir.kit HelloUser \
		lib $(SNITLIB)
	$(TCLKIT) $(top_srcdir)/BuildScripts/AddKitDir.kit HelloUser \
		lib $(MD5LIB)
	$(TCLKIT) $(top_srcdir)/BuildScripts/AddKitDir.kit HelloUser \
		lib $(URILIB)
	$(TCLKIT) $(top_srcdir)/BuildScripts/AddKitDir.kit HelloUser \
		lib $(TCLXMLLIB)
	$(TCLKIT) $(top_srcdir)/BuildScripts/AddKitFile.kit HelloUser \
		lib/Common $(HelloUserLibSCRIPTS)
	$(TCLKIT) $(top_srcdir)/BuildScripts/MakePkgIndex.kit HelloUser \
		Common
	$(TCLKIT) $(SDX) wrap HelloUser${EXEEXT} -runtime $(TCLKITRUN)
	-mv HelloUser${EXEEXT} HelloUser.cgi
	-rm -rf HelloUser.vfs  HelloUser.kit
	

