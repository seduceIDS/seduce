#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([SEDUCE], [0.0.3], [dimitris@census-labs.com])
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
  [AS_HELP_STRING([  --with-config-dir=DIR],
    [Directory for config files])],
  sysconfdir="${withval}", sysconfdir="${sysconfdir}/seduce")

# *** AND NOW FOR THE SOFT DEPS ***

## our patched libqemu implementation (off by default)

use_qemu="no"
AC_ARG_ENABLE(qemu,
 [AS_HELP_STRING([--enable-qemu],
   [Enable older QEMU-based detection engine, requires a 2010 build system :) [off]])],
   [use_qemu=$enableval])

if test "$use_qemu" = "yes"; then
  AM_CONDITIONAL(HAVE_QEMU, true)
  AC_DEFINE(HAVE_QEMU, [1], [QEMU detection engine])
  QEMU_DIR="qemu-0.12.4"
  QEMU_CFLAGS="-I${QEMU_DIR}/ -I${QEMU_DIR}/linux-user/ -I${QEMU_DIR}/target-i386/ -I${QEMU_DIR}/i386-linux-user/ -I${QEMU_DIR}/fpu/ -I${QEMU_DIR}/linux-user/i386/"
  QEMU_LIBS="${QEMU_DIR}/i386-linux-user/libqemu.a ${QEMU_DIR}/libuser/libuser.a -lm -lrt" 
  AC_SUBST(QEMU_CFLAGS)
  AC_SUBST(QEMU_LIBS)
  AC_CONFIG_SUBDIRS([agent/qemu-0.12.4])
else
  AM_CONDITIONAL(HAVE_QEMU, false)
fi

# Unicorn-based emulation, on by default

use_unicorn="yes"
AC_ARG_ENABLE(unicorn,
 [AS_HELP_STRING([--enable-unicorn],
   [Enable Unicorn-based detection engine [on]])],
   [use_unicorn=$enableval])

if test "$use_unicorn" = "yes"; then
  PKG_PROG_PKG_CONFIG([0.29])
  AC_CHECK_PROG(CMAKE,[cmake],[cmake],[no])
  test "$CMAKE" == "no" && AC_MSG_ERROR([Required program 'cmake' not found.])
  AM_CONDITIONAL(HAVE_UNICORN, true)
  AC_DEFINE(HAVE_UNICORN, [1], [Unicorn detection engine])
  UNICORN_DIR="unicorn"
  UNICORN_CFLAGS="-I./${UNICORN_DIR}/include"
  UNICORN_STATIC_LIB="./${UNICORN_DIR}/build/libunicorn.a"
  UNICORN_LIBS="${UNICORN_STATIC_LIB} -lpthread -lm -lrt" 
  AC_SUBST(UNICORN_CFLAGS)
  AC_SUBST(UNICORN_STATIC_LIB)
  AC_SUBST(UNICORN_LIBS)
#  AC_CONFIG_SUBDIRS([agent/unicorn])
else
  AM_CONDITIONAL(HAVE_UNICORN, false)
fi

## embedded libemu library detector (off by default)

use_libemu="no"
AC_ARG_ENABLE(libemu,
 [AS_HELP_STRING([--enable-libemu],
    [Enable libemu-based detection engine [off]])],
 [use_libemu=$enableval])

if test "$use_libemu" = "yes" ; then
  AM_CONDITIONAL(HAVE_LIBEMU, true)
  AC_DEFINE(HAVE_LIBEMU, [1], [libemu detection engine])
  LIBEMU_CFLAGS="-I./libemu/include"
  LIBEMU_STATIC_LIB="./libemu/src/.libs/libemu.a"
  LIBEMU_LIBS="${LIBEMU_STATIC_LIB}"
  AC_SUBST(LIBEMU_CFLAGS)
  AC_SUBST(LIBEMU_STATIC_LIB)
  AC_SUBST(LIBEMU_LIBS)
  AX_SUBDIRS_CONFIGURE([agent/libemu], [--disable-debug], [], [], [])
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

## pyopty2 detection engine (off by default)

use_pyopty2="no"
AC_ARG_ENABLE(pyopty2,
  [AS_HELP_STRING([--enable-pyopty2],
    [Enable pyopty2 detection engine [off]])],
  [use_pyopty2=$enableval])

if test "$use_pyopty2" = "yes" ; then
  AC_CHECK_PROG(PYTHON_CONFIG, [python-config], here, absent)

  if test "$PYTHON_CONFIG" = "here" ; then
    LIBPYTHON_CFLAGS=`python-config --cflags`
    LIBPYTHON_LIBS=`python-config --libs`
    # yes, this is ugly but it's how you specify which include-dirs
    # will be used during the conftest build process
    CPPFLAGS=`python-config --includes`
  else
    AC_MSG_ERROR([python-config not found!])
  fi

  AM_PATH_PYTHON(2.5.0,, 
    AC_MSG_ERROR([Python interpreter not found or too old (must be of version 2.5.x)]))
  AC_SEARCH_LIBS(PyImport_Import, python2.5,, 
    AC_MSG_ERROR([missing python2.5 library]))
  AC_CHECK_HEADER(Python.h,, 
    AC_MSG_ERROR([Python.h header file needed but not found]))

  AM_CONDITIONAL(HAVE_PYOPTY2, true)
  AC_DEFINE(HAVE_PYOPTY2, [1], [pyopty2 detection engine])
  AC_SUBST(LIBPYTHON_CFLAGS)
  AC_SUBST(LIBPYTHON_LIBS)
  # reset it back to normal
  CPPFLAGS=
else
  AM_CONDITIONAL(HAVE_PYOPTY2, false)
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

# reset LIBS, because it has automatically appended
# all libs discovered by AC_SEARCH_LIBS
# This results in adding unrelated libs to executables
LIBS=

AC_CONFIG_FILES([Makefile
                 sensor/Makefile
		 agent/Makefile
		 doc/Makefile])
AC_OUTPUT
