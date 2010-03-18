#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([SEDUCE], [0.0.2], [glynos@storm.cs.unipi.gr])
AC_CONFIG_SRCDIR([sensor/data.h])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for header files.

AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h inttypes.h limits.h malloc.h netdb.h netinet/in.h stddef.h stdlib.h string.h strings.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([alarm gethostbyname gettimeofday inet_ntoa memset munmap regcomp select socket strdup strerror strtol])

#  *** HANDLE HARD DEPENDENCIES *** 

## math library

AC_SEARCH_LIBS([random], [m],, AC_MSG_ERROR([missing math library]))
LIBM_LIBS="-lm"
AC_SUBST(LIBM_LIBS)

## posix thread library

AC_SEARCH_LIBS(pthread_create, pthread,, AC_MSG_ERROR([missing pthread library]))
AC_CHECK_HEADER(pthread.h,, AC_MSG_ERROR([pthread.h header file needed but not found]))
LIBPTHREAD_LIBS="-lpthread"
AC_SUBST(LIBPTHREAD_LIBS)

## glib 2.0 library

AC_SEARCH_LIBS(g_hash_table_new_full, glib-2.0,, AC_MSG_ERROR([missing glib library]))
# does AC_SUBST for GLIB_CFLAGS and GLIB_LIBS internally
AM_PATH_GLIB_2_0(2.0.0,,,gthread)
if test "$GLIB_LIBS" = ""; then
   AC_MSG_ERROR("GLIB 2.0 or later is required to build $PACKAGE_NAME")
fi

## confuse library 

AC_SEARCH_LIBS(cfg_set_validate_func, confuse,, AC_MSG_ERROR([missing confuse library]))
PKG_CHECK_MODULES(LIBCONFUSE, libconfuse,, 
 AC_MSG_ERROR("libconfuse is required to build $PACKAGE_NAME"))
AC_SUBST(LIBCONFUSE_CFLAGS)
AC_SUBST(LIBCONFUSE_LIBS)

## nids library

LIBNIDS_DEPENDENCIES="-lpcap -lgthread-2.0 -lnsl -lnet"
AC_SEARCH_LIBS(nids_register_udp, nids,, AC_MSG_ERROR(
 [libnids (or some dependency of it) is missing. Check config.log for errors.]),
 $LIBNIDS_DEPENDENCIES)
AC_CHECK_HEADER(nids.h,, AC_MSG_ERROR([nids.h header file needed but not found]))
LIBNIDS_LIBS="-lnids $LIBNIDS_DEPENDENCIES"
AC_SUBST(LIBNIDS_LIBS)

## prelude library

AC_SEARCH_LIBS(prelude_client_send_idmef, prelude,, AC_MSG_ERROR([missing prelude library]))
AC_CHECK_HEADERS(libprelude/prelude.h,, AC_MSG_ERROR([libprelude.h header file needed but not found!]))
LIBPRELUDE_CFLAGS=`libprelude-config --cflags`
LIBPRELUDE_LIBS=`libprelude-config --libs`
AC_SUBST(LIBPRELUDE_CFLAGS)
AC_SUBST(LIBPRELUDE_LIBS)

AC_ARG_WITH(config-dir,
  [  --with-config-dir=DIR   Directory for config files],
sysconfdir="${withval}", sysconfdir="${sysconfdir}/seduce")

# *** AND NOW FOR THE SOFT DEPS ***

## our patched libqemu implementation (on by default)

use_qemu="yes"
AC_ARG_ENABLE(qemu,
 [AS_HELP_STRING([--enable-qemu],
   [Enable QEMU-based detection engine [on]])],
   [use_qemu=$enableval])

if test "$use_qemu" = "yes"; then
  AM_CONDITIONAL(HAVE_QEMU, true)
  AC_DEFINE(HAVE_QEMU, [1], [QEMU detection engine])
  QEMU_CFLAGS="-Ilibqemu-0.9.0/ -Ilibqemu-0.9.0/linux-user/ -Ilibqemu-0.9.0/target-i386/ -Ilibqemu-0.9.0/i386-linux-user/ -Ilibqemu-0.9.0/fpu/ -Ilibqemu-0.9.0/linux-user/i386/"
  QEMU_LIBS="libqemu-0.9.0/i386-linux-user/libqemu.a -lm" 
  AC_SUBST(QEMU_CFLAGS)
  AC_SUBST(QEMU_LIBS) 
  AC_CONFIG_SUBDIRS([agent/libqemu-0.9.0])
else
  AM_CONDITIONAL(HAVE_QEMU, false)
fi

## libemu library (autodetected)

AC_ARG_WITH(libemu,
  [AS_HELP_STRING([--with-libemu],[Specify non-standard library path for libemu])],
  [alt_libemu_path="$withval"],
  [alt_libemu_path=default])

AC_ARG_ENABLE(libemu,
 [AS_HELP_STRING([--enable-libemu],
    [Enable libemu-based detection engine [auto]])],
 [use_libemu=$enableval],
 [use_libemu=auto])

PKG_CHECK_MODULES(LIBEMU, libemu, 
		  [detected_libemu=yes],
		  [detected_libemu=no])

case "$use_libemu" in
  "yes") if test "$detected_libemu" = "no" ; then
  		AC_MSG_ERROR([libemu not found])
	 fi ;;
 "auto") if test "$detected_libemu" = "no" ; then
 		use_libemu="no"
	 else
	 	use_libemu="yes"
  	 fi;;
esac

if test "$use_libemu" = "yes" ; then
  AM_CONDITIONAL(HAVE_LIBEMU, true)
  AC_DEFINE(HAVE_LIBEMU, [1], [libemu detection engine])
  AC_SUBST(LIBEMU_CFLAGS)
  AC_SUBST(LIBEMU_LIBS)
  if test "$alt_libemu_path" != "default" ; then
    LIBEMU_LDFLAGS="-L$alt_libemu_path $LIBEMU_LDFLAGS"
  fi
  AC_SUBST(LIBEMU_LDFLAGS)
else
  AM_CONDITIONAL(HAVE_LIBEMU, false)
fi

## fnord nop detector (off by default) 

use_fnord="no"
AC_ARG_ENABLE(fnord,
 [AS_HELP_STRING([--enable-fnord],
   [Enable fnord-like nop detection engine [off]])],
 [use_fnord=$enableval])

if test "$use_fnord" = "yes" ; then
  AM_CONDITIONAL(HAVE_FNORD, true)
  AC_DEFINE(HAVE_FNORD, [1], [fnord detection engine])
else
  AM_CONDITIONAL(HAVE_FNORD, false)
fi

## dummy detection engine (off by default) 

use_dummy="no"
AC_ARG_ENABLE(dummy,
  [AS_HELP_STRING([--enable-dummy],
    [Enable dummy detection engine [off]])],
  [use_dummy=$enableval])

if test "$use_dummy" = "yes" ; then
  AM_CONDITIONAL(HAVE_DUMMY, true)
  AC_DEFINE(HAVE_DUMMY, [1], [dummy detection engine])
else
  AM_CONDITIONAL(HAVE_DUMMY, false)
fi

AC_CONFIG_FILES([Makefile
                 sensor/Makefile
		 agent/Makefile])
AC_OUTPUT
