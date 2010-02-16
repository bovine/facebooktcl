AC_INIT(FacebookTcl,1.6.3)
AC_CONFIG_SRCDIR(Common/Facebook.tcl)
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([BuildScripts/Makefile \
		Doc/Makefile Doc/Internals/Makefile Doc/Support/Makefile \
		Common/Makefile \
		HelloUser/Makefile \
		Makefile])
if test "x${prefix}" = "xNONE"; then
    prefix=/usr/local
fi
if test "x${exec_prefix}" = "xNONE"; then
    exec_prefix="${prefix}"
fi

BUILD_DIR=`pwd`
TOP_DIR=${BUILD_DIR}

AC_SUBST(TOP_DIR)
AC_SUBST(BUILD_DIR)

AC_PATH_PROGS(TCLSH,tclsh8.5 tclsh8.4 tclsh,/bin/true,$PATH:/usr/local/bin)

TCL_AUTO_PATH=`echo 'puts $auto_path'|${TCLSH}`

AC_MSG_CHECKING(snit dir) 
SNITLIB= 
dirs=${TCL_AUTO_PATH} 
for i in $dirs ; do 
  subdirs="$i/snit $i/tcllib*/snit"
  for j in $subdirs ; do
    if test -d "$j" -a -f "$j/pkgIndex.tcl"; then
      SNITLIB=`cd $j; pwd`
    fi
  done
done
AC_ARG_WITH(snitlib, [  --with-snitlib=DIR          use snit from DIR], SNITLIB=$withval,)
if test -d $SNITLIB; then
   AC_MSG_RESULT([using snit library in $SNITLIB])
else
   AC_MSG_ERROR(snit library directory $SNITLIB doesn't exist)
fi
AC_SUBST(SNITLIB)

AC_MSG_CHECKING(md5 dir) 
MD5LIB= 
dirs=${TCL_AUTO_PATH} 
for i in $dirs ; do 
  subdirs="$i/md5 $i/tcllib*/md5"
  for j in $subdirs ; do
    if test -d "$j" -a -f "$j/pkgIndex.tcl"; then
      MD5LIB=`cd $j; pwd`
    fi
  done
done
AC_ARG_WITH(md5lib, [  --with-md5lib=DIR          use md5 from DIR], MD5LIB=$withval,)
if test -d $MD5LIB; then
   AC_MSG_RESULT([using md5 library in $MD5LIB])
else
   AC_MSG_ERROR(md5 library directory $MD5LIB doesn't exist)
fi
AC_SUBST(MD5LIB)

AC_MSG_CHECKING(uri dir) 
URILIB= 
dirs=${TCL_AUTO_PATH} 
for i in $dirs ; do 
  subdirs="$i/uri $i/tcllib*/uri"
  for j in $subdirs ; do
    if test -d "$j" -a -f "$j/pkgIndex.tcl"; then
      URILIB=`cd $j; pwd`
    fi
  done
done
AC_ARG_WITH(urilib, [  --with-urilib=DIR          use uri from DIR], URILIB=$withval,)
if test -d $URILIB; then
   AC_MSG_RESULT([using uri library in $URILIB])
else
   AC_MSG_ERROR(uri library directory $URILIB doesn't exist)
fi
AC_SUBST(URILIB)

AC_MSG_CHECKING(tclxml dir) 
TCLXMLLIB= 
dirs=${TCL_AUTO_PATH} 
for i in $dirs ; do 
  subdirs="$i/Tclxml* $i/tclxml*"
  for j in $subdirs ; do
    if test -d "$j" -a -f "$j/pkgIndex.tcl"; then
      TCLXMLLIB=`cd $j; pwd`
    fi
  done
done
AC_ARG_WITH(tclxmllib, [  --with-tclxmllib=DIR          use tclxml from DIR], TCLXMLLIB=$withval,)
if test -d $TCLXMLLIB; then
   AC_MSG_RESULT([using tclxml library in $TCLXMLLIB])
else
   AC_MSG_ERROR(tclxml library directory $TCLXMLLIB doesn't exist)
fi
AC_SUBST(TCLXMLLIB)


AC_PATH_PROGS(SDX,sdx.kit sdx)
AC_PATH_PROGS(TCLKIT,tclkit)
TCLKITRUN="${TCL_EXEC_PREFIX}/bin/tclkit$EXEEXT"
AC_ARG_WITH(tclkitrun, [  --with-tclkitrun=filename     use tclkit runtime in fi
lename], TCLKITRUN=$withval,)
if test -x $TCLKITRUN;  then
   AC_MSG_RESULT([using tclkit runtime $TCLKITRUN])
else
   AC_MSG_ERROR([Can't find tclkit, please use --with-tclkitrun to set the tclki
t])
fi
AC_SUBST(TCLKITRUN)

AC_PATH_PROG(PDFLATEX,pdflatex,/bin/true)
AC_PATH_PROGS(HTLATEX,[htlatex htlatex.sh],/bin/true)
AC_PATH_PROG(MAKEINDEX,makeindex,/bin/true)

AC_OUTPUT


