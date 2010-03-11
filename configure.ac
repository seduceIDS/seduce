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

# Checks for libraries.

# These are the top-level libraries we link to
AC_SEARCH_LIBS([random], [m],, AC_MSG_ERROR([missing math library]))
AC_SEARCH_LIBS(pthread_create, pthread,, AC_MSG_ERROR([missing pthread library]))
AC_SEARCH_LIBS(g_hash_table_new_full, glib-2.0,, AC_MSG_ERROR([missing glib library]))
AC_SEARCH_LIBS(cfg_set_validate_func, confuse,, AC_MSG_ERROR([missing confuse library]))
AC_SEARCH_LIBS(nids_register_udp, nids,, AC_MSG_ERROR([missing nids library]))
AC_SEARCH_LIBS(prelude_client_send_idmef, prelude,, AC_MSG_ERROR([missing prelude library]))

# Checks for header files.

AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h inttypes.h limits.h malloc.h netdb.h netinet/in.h stddef.h stdlib.h string.h strings.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

# check for glib - does AC_SUBST for GLIB_CFLAGS and GLIB_LIBS internally
AM_PATH_GLIB_2_0(2.0.0,,,gthread)
if test "$GLIB_LIBS" = ""; then
   AC_MSG_ERROR("GLIB 2.0 or later is required to build SEDUCE")
fi

# check for libconfuse
PKG_CHECK_MODULES(LIBCONFUSE, libconfuse,, AC_MSG_ERROR("libconfuse is required to build $PACKAGE_NAME"))
AC_SUBST(LIBCONFUSE_CFLAGS)
AC_SUBST(LIBCONFUSE_LIBS)

AC_CHECK_HEADER(nids.h,, AC_MSG_ERROR([nids.h header file needed but not found]))
LIBNIDS_LIBS="-lnids -lpcap -lgthread-2.0 -lnsl"
AC_SUBST(LIBNIDS_LIBS) 

AC_CHECK_HEADER(pthread.h,, AC_MSG_ERROR([pthread.h header file needed but not found]))
LIBPTHREAD_LIBS="-lpthread"
AC_SUBST(LIBPTHREAD_LIBS)

LIBM_LIBS="-lm"
AC_SUBST(LIBM_LIBS)

AC_CHECK_HEADERS(libprelude/prelude.h,, AC_MSG_ERROR([libprelude.h header file needed but not found!]))
LIBPRELUDE_CFLAGS=`libprelude-config --cflags`
LIBPRELUDE_LIBS=`libprelude-config --libs`
AC_SUBST(LIBPRELUDE_CFLAGS)
AC_SUBST(LIBPRELUDE_LIBS)

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

AC_ARG_WITH(config-dir,
  [ --with-config-dir=DIR      Directory for config files],
sysconfdir="${withval}", sysconfdir="${sysconfdir}/seduce")

AC_CONFIG_FILES([Makefile
                 sensor/Makefile])
## AC_CONFIG_SUBDIRS([agent/libqemu-0.9.0])
AC_OUTPUT
