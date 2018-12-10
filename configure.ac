dnl Process this file with autoconf to produce a configure script.

dnl ------------------------------------------------------------
dnl $Id: configure.in,v 1.17 2012-02-27 19:03:15 cvswrite Exp $
dnl If you're trying to create a new configure test, try
dnl
dnl 	http://autogen.sourceforge.net/conftest.html
dnl ------------------------------------------------------------

# ------------------------------------------------------------
# Initialization
# ------------------------------------------------------------
AC_INIT([shtunnel], [0.1.13])
AC_CONFIG_SRCDIR([src/shtunnel.c])
AM_INIT_AUTOMAKE

AC_PREREQ(2.53)
AC_REVISION($Revision: 1.17 $)

AM_CONFIG_HEADER(src/config.h)

# ------------------------------------------------------------
# Host-specific configuration
# ------------------------------------------------------------
AC_CANONICAL_HOST
AC_GNU_SOURCE

# ------------------------------------------------------------
# Checks for programs.
# ------------------------------------------------------------
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O

# ------------------------------------------------------------
# Checks for libraries.
# ------------------------------------------------------------
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(openpty, util)
old_LIBS="$LIBS"
AC_SEARCH_LIBS(cuse_lowlevel_teardown, fuse, AC_DEFINE(HAVE_CUSE, 1, [Define to 1 if CUSE is supported.]))
LIBS="$old_LIBS"

# ------------------------------------------------------------
# Checks for header files.
# ------------------------------------------------------------
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([unistd.h errno.h signal.h paths.h rpc/types.h sys/stat.h \
	sys/select.h sys/socket.h netinet/in.h netinet/tcp.h arpa/inet.h \
	sys/bsdtty.h ttyent.h pty.h utmp.h utmpx.h util.h libutil.h \
	sys/strtio.h sys/stropts.h])

# ------------------------------------------------------------
# Checks for typedefs and structures
# ------------------------------------------------------------

# SunOS4 and debian do not define in_addr_t
AC_CHECK_TYPE([in_addr_t], ,[
  AC_MSG_CHECKING([for in_addr_t equivalent])
  AC_CACHE_VAL([curl_cv_in_addr_t_equiv],
  [
     curl_cv_in_addr_t_equiv=
     for t in "unsigned long" int size_t unsigned long; do
        AC_TRY_COMPILE([
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
        ],[
           $t data = inet_addr ("1.2.3.4");
        ],[
           curl_cv_in_addr_t_equiv="$t"
           break
        ])
     done

     if test "x$curl_cv_in_addr_t_equiv" = x; then
        AC_MSG_ERROR([Cannot find a type to use in place of in_addr_t])
     fi
  ])
  AC_MSG_RESULT($curl_cv_in_addr_t_equiv)
  AC_DEFINE_UNQUOTED(in_addr_t, $curl_cv_in_addr_t_equiv,
		     [type to use in place of in_addr_t if not defined])],
  [#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif])

# ---- Solaris needs -DBSD_COMP to get FIONBIO defined ----
AC_MSG_CHECKING(is FIONBIO defined)
AC_EGREP_CPP(yes,
[#include <sys/ioctl.h>
#ifdef FIONBIO
 yes
#endif
],
    AC_MSG_RESULT(yes),
    [ AC_EGREP_CPP(yes,
[#define BSD_COMP
#include <sys/ioctl.h>
#ifdef FIONBIO
 yes
#endif
],
    AC_DEFINE(BSD_COMP, 1, [Define to 1 if you need BSD_COMP defined to get FIONBIO defined.]) AC_MSG_RESULT(need -DBSD_COMP),
    AC_MSG_RESULT(no))
    ])

# ------------------------------------------------------------
# Checks for compiler characteristics.
# ------------------------------------------------------------
AC_C_BIGENDIAN
AC_C_CONST

# ------------------------------------------------------------
# Checks for library functions.
# ------------------------------------------------------------
AC_CHECK_FUNCS([vsnprintf getpwuid openpty _getpty getresuid getresgid])

# ------------------------------------------------------------
# Checks for library variables.
# ------------------------------------------------------------

# ------------------------------------------------------------
# Compile time options
# ------------------------------------------------------------
AC_MSG_RESULT(checking compile-time options)

AC_ARG_ENABLE(debug,
	AC_HELP_STRING([--disable-debug], [disable assert and other things]),
	[use_debug=$enableval], [use_debug=yes])
  
if test "$use_debug" = "yes" ; then
	AC_MSG_NOTICE(debug enabled)	
	CPPFLAGS="$CPPFLAGS -DDEBUG=1"
else
	AC_MSG_NOTICE(debug disabled)	
	CPPFLAGS="$CPPFLAGS -DNDEBUG=1"
fi

# enable some warning for gcc
if test "$ac_compiler_gnu" = "yes" ; then
	CPPFLAGS="$CPPFLAGS -Wall -Wstrict-prototypes -Wmissing-prototypes -Wno-long-long"
fi

if pkg-config --cflags --libs fuse > /dev/null 2> /dev/null; then
	CLASSIFIER_CFLAGS=$(pkg-config --cflags fuse)
	CLASSIFIER_LDADD=$(pkg-config --libs fuse)
	AC_SUBST(CLASSIFIER_CFLAGS)
	AC_SUBST(CLASSIFIER_LDADD)
fi

AC_CHECK_FILE("/dev/ptmx",[AC_DEFINE(HAVE_DEV_PTMX, 1, [Define if you have /dev/ptmx])])
AC_CHECK_FILE("/dev/ptc", [AC_DEFINE(HAVE_DEV_PTS_AND_PTC, 1, [Define if you have /dev/ptc])])


AC_MSG_RESULT(done)
# ------------------------------------------------------------
# Final output
# ------------------------------------------------------------
AC_OUTPUT(Makefile src/Makefile)
