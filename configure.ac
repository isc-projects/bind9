# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

#
# Defining the version in m4 requires a bit of dancing around,
# so the strings are properly concatenated, as you can't use
# a shell variable in AC_INIT()
#
m4_define([bind_VERSION_MAJOR], 9)dnl
m4_define([bind_VERSION_MINOR], 17)dnl
m4_define([bind_VERSION_PATCH], 1)dnl
m4_define([bind_VERSION_EXTRA], -dev)dnl
m4_define([bind_DESCRIPTION], [(Development Release)])dnl
m4_define([bind_SRCID], [m4_esyscmd_s([if test -f srcid; then cat srcid; else git rev-parse --short HEAD 2>/dev/null; fi])])dnl
m4_define([bind_PKG_VERSION], [[bind_VERSION_MAJOR.bind_VERSION_MINOR.bind_VERSION_PATCH]bind_VERSION_EXTRA])dnl

#
# Autoconf initialization
#
AC_INIT([BIND], bind_PKG_VERSION, [info@isc.org], [], [https://www.isc.org/downloads/])
AC_PREREQ(2.60)

AC_DEFINE([PACKAGE_VERSION_MAJOR], ["][bind_VERSION_MAJOR]["], [BIND 9 Major part of the version])
AC_DEFINE([PACKAGE_VERSION_MINOR], ["][bind_VERSION_MINOR]["], [BIND 9 Minor part of the version])
AC_DEFINE([PACKAGE_VERSION_PATCH], ["][bind_VERSION_PATCH]["], [BIND 9 Patch part of the version])
AC_DEFINE([PACKAGE_VERSION_EXTRA], ["][bind_VERSION_EXTRA]["], [BIND 9 Extra part of the version])
AC_DEFINE([PACKAGE_DESCRIPTION], [m4_ifnblank(bind_DESCRIPTION, [" ]bind_DESCRIPTION["], [])], [An extra string to print after PACKAGE_STRING])
AC_DEFINE([PACKAGE_SRCID], ["][bind_SRCID]["], [A short hash from git])

# This value should be increased whenever changing the structure of
# any object that will appear in a type 'map' master file (which
# contains a working memory image of an RBT database), as loading 
# an incorrect memory image produces an inconsistent and probably
# nonfunctional database.  These structures include but are not
# necessarily limited to dns_masterrawheader, rbtdb_file_header,
# rbt_file_header, dns_rbtdb, dns_rbt, dns_rbtnode, rdatasetheader.
#
# Err on the side of caution: if anything in the RBTDB is changed,
# bump the value.  Making map files unreadable protects the system
# from instability; it's a feature not a bug.
#
# Whenever releasing a new major release of BIND9, set this value
# back to 1.0 when releasing the first alpha.  Map files are *never*
# compatible across major releases.
AC_DEFINE([MAPAPI], ["2.0"], [BIND 9 MAPAPI Version])

bind_CONFIGARGS="${ac_configure_args:-default}"
AC_DEFINE_UNQUOTED([PACKAGE_CONFIGARGS], ["$bind_CONFIGARGS"], [Either 'defaults' or used ./configure options])

AC_DEFINE([PACKAGE_BUILDER], ["make"], [make or Visual Studio])

AC_CONFIG_SRCDIR([bin/named/main.c])
AM_INIT_AUTOMAKE([foreign subdir-objects dist-xz -Wall -Werror])
AM_SILENT_RULES([yes])
AM_EXTRA_RECURSIVE_TARGETS([test unit doc])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

#
# Enable maintainer mode by default, but allow to disable it in the CI
#
AM_MAINTAINER_MODE([enable])

# Set the library versions
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html

AX_BIND9_LIB_VERSION([bind9])
AX_BIND9_LIB_VERSION([dns])
AX_BIND9_LIB_VERSION([irs])
AX_BIND9_LIB_VERSION([isc])
AX_BIND9_LIB_VERSION([isccc])
AX_BIND9_LIB_VERSION([isccfg])
AX_BIND9_LIB_VERSION([ns])

#
# Enable system extensions to C and POSIX
#
AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_HOST

#
# Compiler compatibility flags
#
AC_PROG_CC_C99
AC_PROG_CPP_WERROR

#
# Find the machine's endian flavor.
#
AC_C_BIGENDIAN

#
# Enable large file support
#
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO

# Enable RFC 3542 APIs on macOS
AC_DEFINE([__APPLE_USE_RFC_3542], [1], [Select RFC3542 IPv6 API on macOS])

AC_PROG_MAKE_SET

# Checks for programs.
m4_ifdef([AM_PROG_AR], [AM_PROG_AR]) # call AM_PROG_AR only if available

AC_PROG_LIBTOOL
AS_IF([test -z "$LIBTOOL"],
      [AC_MSG_ERROR([The libtool script could not be found.])])
AC_PROG_INSTALL
AC_PROG_LN_S
AX_POSIX_SHELL
AC_PROG_MKDIR_P

# Initialize libtool
LT_INIT([dlopen])

LT_CONFIG_LTDL_DIR([libltdl])
LTDL_INIT([recursive])
AC_CONFIG_FILES([libltdl/Makefile])

#
# Set the default CFLAGS and CPPFLAGS
#
STD_CFLAGS="-Wall -Wextra -Wwrite-strings -Wcast-qual -Wpointer-arith -Wno-missing-field-initializers -Wformat -Wshadow"

# These should be always errors
STD_CFLAGS="$STD_CFLAGS -Werror=implicit-function-declaration -Werror=missing-prototypes -Werror=format-security -Werror=parentheses -Werror=implicit -Werror=strict-prototypes"

# Fortify the sources by default
STD_CPPFLAGS="-D_FORTIFY_SOURCE=2"

#
# Additional compiler settings.
#
AX_CHECK_COMPILE_FLAG([-fno-strict-aliasing],
		      [STD_CFLAGS="$STD_CFLAGS -fno-strict-aliasing"])
# Clang only issues a warning so use -Werror to force a error.
AX_CHECK_COMPILE_FLAG([-Werror -fno-delete-null-pointer-checks],
		      [STD_CFLAGS="$STD_CFLAGS -fno-delete-null-pointer-checks"])
AX_CHECK_COMPILE_FLAG([-fdiagnostics-show-option],
		      [STD_CFLAGS="$STD_CFLAGS -fdiagnostics-show-option"])

#
# Change defaults for developers if not explicity set.
# Needs to be before the option is tested.
#
AC_ARG_ENABLE([developer],
	      [AS_HELP_STRING([--enable-developer],
			      [enable developer build settings])])

AS_IF([test "$enable_developer" = "yes"],
      [STD_CPPFLAGS="$STD_CPPFLAGS -DISC_MEM_DEFAULTFILL=1 -DISC_LIST_CHECKINIT=1"
       test "${enable_fixed_rrset+set}" = set || enable_fixed_rrset=yes
       test "${enable_querytrace+set}" = set || enable_querytrace=yes
       test "${with_cmocka+set}" = set || with_cmocka=yes
       test "${with_dlz_filesystem+set}" = set || with_dlz_filesystem=yes
       test "${with_zlib+set}" = set || with_zlib=yes
       test "${enable_warn_error+set}" = set || enable_warn_error=yes
       ])

AC_SUBST([STD_CFLAGS])
AC_SUBST([STD_CPPFLAGS])

AC_ARG_ENABLE([warn_error],
	      [AS_HELP_STRING([--enable-warn-error],
			      [turn on -Werror when compiling])],
	      [],[enable_warn_error=no])
AS_IF([test "$enable_warn_error" = "yes"],
      [STD_CFLAGS="$STD_CFLAGS -Werror"])

#
# Use pkg-config
#

PKG_PROG_PKG_CONFIG
AS_IF([test -z "$PKG_CONFIG"],
      [AC_MSG_ERROR([The pkg-config script could not be found or is too old.])])

AC_ARG_ENABLE(buffer_useinline,
	      AS_HELP_STRING([--enable-buffer-useinline],
		             [define ISC_BUFFER_USEINLINE when compiling
				[default=yes]]),
	      if test yes = "${enable}"
	      then
		      AC_DEFINE([ISC_BUFFER_USEINLINE], [1],
			        [Define if you want to use inline buffers])
	      fi,
	      AC_DEFINE([ISC_BUFFER_USEINLINE], [1]))

AC_ARG_ENABLE([fuzzing],
	      [AS_HELP_STRING([--enable-fuzzing=<afl|libfuzzer>],
			      [Enable fuzzing using American Fuzzy Lop or libFuzzer (default=no)])],
	      [],
	      [enable_fuzzing=no])

AC_MSG_CHECKING([whether to enable fuzzing mode])
AS_CASE([$enable_fuzzing],
	[no],[AC_MSG_RESULT([no])],
	[afl],[
	  AC_MSG_RESULT([using AFL])
	  AC_DEFINE([ENABLE_AFL], [1],
		    [Define to enable American Fuzzy Lop test harness])
	  CFLAGS="$CFLAGS -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1"
	  LIBS="$LIBS -lpthread"],
	[libfuzzer],[
	  AC_MSG_RESULT([using libFuzzer])
	  CFLAGS="$CFLAGS -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1 -fsanitize=fuzzer,address,undefined"
	  LDFLAGS="$LDFLAGS -fsanitize=fuzzer,address,undefined"],
	[*],[AC_MSG_ERROR([You need to explicitly select the fuzzer])])

AS_IF([test "$enable_fuzzing" = "afl"],
      [AC_MSG_CHECKING("for AFL enabled compiler")
       AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
					  [#ifndef __AFL_COMPILER
					   #error AFL compiler required
					   #endif
					  ])],
			 [AC_MSG_RESULT([yes])],
			 [AC_MSG_ERROR([set CC=afl-<gcc|clang> when --enable-fuzzing=afl is used])])
      ])

AC_ARG_ENABLE(mutex_atomics,
	      AS_HELP_STRING([--enable-mutex-atomics],
		             [emulate atomics by mutex-locked variables, useful for debugging
				[default=no]]),
	      [],
	      [enable_mutex_atomics=no])

AC_MSG_CHECKING([whether to emulate atomics with mutexes])
case "$enable_mutex_atomics" in
yes)
        AC_MSG_RESULT(yes)
        AC_DEFINE(ISC_MUTEX_ATOMICS, 1, [Define to emulate atomic variables with mutexes.])
        ;;
no)
        AC_MSG_RESULT(no)
        ;;
*)
        AC_MSG_ERROR("--enable-mutex-atomics requires yes or no")
        ;;
esac

#
# Perl is optional; it is used only by some of the system test scripts.
#
AC_PATH_PROGS([PERL], [perl5 perl])
AC_SUBST([PERL])
AM_CONDITIONAL([HAVE_PERL], [test -n "$PERL"])

AX_PERL_MODULE([Digest::HMAC])
AM_CONDITIONAL([HAVE_PERLMOD_DIGEST_HMAC],
	       [test "$HAVE_PERLMOD_DIGEST__HMAC" = "yes"])

AX_PERL_MODULE([File::Fetch])
AM_CONDITIONAL([HAVE_PERLMOD_FILE_FETCH],
	       [test "$HAVE_PERLMOD_FILE__FETCH" = "yes"])

AX_PERL_MODULE([Net::DNS])
AM_CONDITIONAL([HAVE_PERLMOD_NET_DNS],
	       [test "$HAVE_PERLMOD_NET__DNS" = "yes"])

AX_PERL_MODULE([Net::DNS::Nameserver])
AM_CONDITIONAL([HAVE_PERLMOD_NET_DNS_NAMESERVER],
	       [test "$HAVE_PERLMOD_NET__DNS__NAMESERVER" = "yes"])

AX_PERL_MODULE([Time::HiRes])
AM_CONDITIONAL([HAVE_PERLMOD_TIME_HIRES],
	       [test "$HAVE_PERLMOD_TIME__HIRES" = "yes"])

#
# Python is optional, it is used only by some of the system test scripts.
#
AM_PATH_PYTHON([3.4], [], [:])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != ":"])

AC_PATH_PROGS([PYTEST], [pytest-3 py.test-3 pytest pytest-pypy], [])
AS_IF([test -z "$PYTEST"],
      [AC_MSG_WARN([pytest not found, some system tests will be skipped])])
AC_SUBST([PYTEST])
AM_CONDITIONAL([HAVE_PYTEST], [test -n "$PYTEST"])

AX_PYTHON_MODULE([dns])
AM_CONDITIONAL([HAVE_PYMOD_DNS], [test "$HAVE_PYMOD_DNS" = "yes"])

#
# xsltproc is optional, it is used only by system test scripts.
#
AC_PATH_PROG([XSLTPROC], [xsltproc])

#
# Using Solaris linker with gcc on Solaris breaks Thread Local Storage
#
AS_CASE([$host],
	[*-solaris*],[
	    AS_IF([test "$GCC" = "yes"],
		  [LDFLAGS="$LDFLAGS -zrelax=transtls"
		   AC_MSG_WARN([When using GNU C Compiler on Solaris, -zrelax=transtls linker flag is used to fix bug in Thread Local Storage])
		  ])
	])

AC_HEADER_STDC

AC_CHECK_HEADERS([fcntl.h regex.h sys/time.h unistd.h sys/mman.h sys/sockio.h sys/select.h sys/param.h sys/sysctl.h net/if6.h sys/socket.h net/route.h linux/netlink.h linux/rtnetlink.h], [], [],
		 [$ac_includes_default
		  #ifdef HAVE_SYS_PARAM_H
		  # include <sys/param.h>
		  #endif
		  #ifdef HAVE_SYS_SOCKET_H
		  # include <sys/socket.h>
		  #endif
		 ])

#
# Check for thread local storage
#
AC_CHECK_HEADERS([threads.h])
AX_TLS([AS_IF([test "$ac_cv_tls" != "thread_local"],
	      [AC_DEFINE_UNQUOTED([thread_local], [$ac_cv_tls], [Define if the compiler uses a different keyword than thread_local for TLS variables])])],
       [AC_MSG_ERROR([Thread Local Storage support required, update your toolchain to build BIND 9])])

AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_C_FLEXIBLE_ARRAY_MEMBER

#
# Check for yield support on ARM processors
#
AS_CASE([$host],
	[arm*],
	[AC_MSG_CHECKING([for yield instruction support])
	 AC_COMPILE_IFELSE(
	     [AC_LANG_PROGRAM([[]],
			     [[__asm__ __volatile__ ("yield")]])],
	     [AC_MSG_RESULT([yes])
	      AC_DEFINE([HAVE_ARM_YIELD], [1],
			[define if the ARM yield instruction is available])],
	     [AC_MSG_RESULT([no])])])

#
# Check for pause support on SPARC processors
#
AS_CASE([$host],
	[sparc*],
	[AC_MSG_CHECKING([for pause instruction support])
	 AC_COMPILE_IFELSE(
	     [AC_LANG_PROGRAM([[]],
			     [[__asm__ __volatile__ ("pause")]])],
	     [AC_MSG_RESULT([yes])
	      AC_DEFINE([HAVE_SPARC_PAUSE], [1],
			[define if the SPARC pause instruction is available])],
	     [AC_MSG_RESULT([no])])])

AC_CHECK_FUNCS([sysctlbyname])

#
# Check for the existence of mmap to enable the fast format zones
#
AC_CHECK_FUNCS(mmap)

#
# Older versions of HP/UX don't define seteuid() and setegid()
#
AC_CHECK_FUNCS([seteuid setresuid])
AC_CHECK_FUNCS([setegid setresgid])

AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINTPTR_T

AC_HEADER_TIME

#
# check for uname library routine
#
AC_MSG_CHECKING([for uname])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
     [[#include <sys/utsname.h>
       #include <stdio.h>
      ]],
     [[
       struct utsname uts;
       uname(&uts);
       printf("running on %s %s %s for %s\n",
	      uts.sysname, uts.release, uts.version, uts.machine);
     ]])],
  [AC_MSG_RESULT(yes)
   AC_DEFINE([HAVE_UNAME], [1], [define if uname is available])
  ],
  [AC_MSG_RESULT(no)
   AC_MSG_WARN([uname is not correctly supported])
  ])

#
# check for GCC noreturn attribute
#
AX_GCC_FUNC_ATTRIBUTE([noreturn])

#
# check if we have kqueue
#
AC_ARG_ENABLE([kqueue],
	      [AS_HELP_STRING([--enable-kqueue],
			      [use BSD kqueue when available [default=yes]])],
	      [], enable_kqueue="yes")

AS_IF([test "$enable_kqueue" = "yes"],
      [AC_CHECK_FUNCS([kqueue])])

#
# check if we have epoll.  Linux kernel 2.4 has epoll_create() which fails,
# so we need to try running the code, not just test its existence.
#
AC_ARG_ENABLE([epoll],
	      [AS_HELP_STRING([--enable-epoll],
			      [use Linux epoll when available [default=auto]])],
	      [], [enable_epoll="yes"])

AS_IF([test "$enable_epoll" = "yes"],
      [AC_CHECK_FUNCS([epoll_create1])])

#
# check if we support /dev/poll
#
AC_ARG_ENABLE([devpoll],
	      [AS_HELP_STRING([--enable-devpoll],
			      [use /dev/poll when available [default=yes]])],
	      [], [enable_devpoll="yes"])
AS_IF([test "$enable_devpoll" = "yes"],
      [AC_CHECK_HEADERS([sys/devpoll.h devpoll.h])])

#
# GeoIP support?
#
# Should be on by default if libmaxminddb exists.
#
AC_ARG_ENABLE([geoip],
	      [AS_HELP_STRING([--disable-geoip],
			      [support GeoIP2 geolocation ACLs if available [default=yes]])],
	      [], [enable_geoip="yes"])

AC_ARG_WITH([maxminddb],
	    [AS_HELP_STRING([--with-maxminddb=PATH],
			    [Build with MaxMind GeoIP2 support (auto|yes|no|path) [default=auto]])],
	    [], [with_maxminddb="auto"])

AS_IF([test "$enable_geoip" = "yes"],
      [AS_CASE([$with_maxminddb],
	       [no],[AC_MSG_ERROR([Use '--disable-geoip' to disable the GeoIP])],
	       [auto],[PKG_CHECK_MODULES([MAXMINDDB], [libmaxminddb],
					 [AC_DEFINE([HAVE_GEOIP2], [1], [Build with GeoIP2 support])
					  PKG_CHECK_VAR([MAXMINDDB_PREFIX], [libmaxminddb], [prefix], [], [AC_MSG_ERROR([libmaxminddb prefix not found in pkg-config; set MAXMINDDB_PREFIX in the environment])])
					 ],[:])],
	       [yes],[PKG_CHECK_MODULES([MAXMINDDB], [libmaxminddb],
					[AC_DEFINE([HAVE_GEOIP2], [1], [Build with GeoIP2 support])
					 PKG_CHECK_VAR([MAXMINDDB_PREFIX], [libmaxminddb], [prefix], [], [AC_MSG_ERROR([libmaxminddb prefix not found in pkg-config; set MAXMINDDB_PREFIX in the environment])])
					])],
	       [ # default
		   AX_SAVE_FLAGS([maxminddb])
		   MAXMINDDB_CFLAGS="-I$with_maxminddb/include"
		   MAXMINDDB_LIBS="-L$with_maxminddb/lib"
		   CFLAGS="$CFLAGS $MAXMINDDB_CFLAGS"
		   LIBS="$LIBS $MAXMINDDB_LIBS"
		   AC_SEARCH_LIBS([MMDB_open], [maxminddb],
				  [AC_DEFINE([HAVE_GEOIP2], [1], [Build with GeoIP2 support])
				   MAXMINDDB_LIBS="$MAXMINDDB_LIBS $ac_cv_search_mmdb_open"
				   AC_MSG_NOTICE([GeoIP2 default database path set to $with_maxminddb/share/GeoIP])
				   AS_VAR_COPY([MAXMINDDB_PREFIX], [$with_maxminddb])
				  ],
				  [AC_MSG_ERROR([GeoIP2 requested, but libmaxminddb not found])])
		   AX_RESTORE_FLAGS([maxminddb])
	       ])
       AC_ARG_VAR([MAXMINDDB_PREFIX], [value of prefix for MAXMINDDB, overriding pkg-config])
])

AM_CONDITIONAL([HAVE_GEOIP2], [test -n "$MAXMINDDB_LIBS"])

AC_SUBST([MAXMINDDB_CFLAGS])
AC_SUBST([MAXMINDDB_LIBS])

AX_PTHREAD

LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

AC_CHECK_FUNCS([pthread_attr_getstacksize pthread_attr_setstacksize])

AC_ARG_WITH([locktype],
	    AS_HELP_STRING([--with-locktype=ARG],
			   [Specify mutex lock type
			    (adaptive or standard)]),
	    [], [with_locktype="adaptive"])

AS_CASE([$with_locktype],
	[adaptive],[
	  AC_MSG_CHECKING([for PTHREAD_MUTEX_ADAPTIVE_NP])
	  AC_COMPILE_IFELSE(
	    [AC_LANG_PROGRAM(
	       [[
		 #ifndef _GNU_SOURCE
		 #define _GNU_SOURCE
		 #endif
		 #include <pthread.h>
	       ]],
	       [[
		 return (PTHREAD_MUTEX_ADAPTIVE_NP);
	       ]]
	     )],
	    [AC_MSG_RESULT([using adaptive lock type])
	     AC_DEFINE([HAVE_PTHREAD_MUTEX_ADAPTIVE_NP], 1,
		       [Support for PTHREAD_MUTEX_ADAPTIVE_NP]) ],
	    [AC_MSG_RESULT([using standard lock type])]
	  )],
	[standard],[AC_MSG_RESULT([using standard lock type])],
	[AC_MSG_ERROR([You must specify "adaptive" or "standard" for --with-locktype.])]
       )

AC_CHECK_HEADERS([sched.h])

AC_SEARCH_LIBS([sched_yield],[rt])
AC_CHECK_FUNCS([sched_yield pthread_yield pthread_yield_np])

AC_CHECK_HEADERS([sys/cpuset.h])
AC_CHECK_HEADERS([sys/procset.h])
AC_CHECK_FUNCS([pthread_setaffinity_np cpuset_setaffinity processor_bind sched_setaffinity])

# Look for functions relating to thread naming
AC_CHECK_FUNCS([pthread_setname_np pthread_set_name_np])
AC_CHECK_HEADERS([pthread_np.h], [], [], [#include <pthread.h>])

# libuv
AC_MSG_CHECKING([for libuv])
PKG_CHECK_MODULES([LIBUV], [libuv >= 1.0.0], [],
		  [AC_MSG_ERROR([libuv not found])])
AX_SAVE_FLAGS([libuv])

CFLAGS="$CFLAGS $LIBUV_CFLAGS"
LIBS="$LIBS $LIBUV_LIBS"

# Those functions are only provided in newer versions of libuv, we'll be emulating them
# for now
AC_CHECK_FUNCS([uv_handle_get_data uv_handle_set_data uv_import])
AX_RESTORE_FLAGS([libuv])

#
# flockfile is usually provided by pthreads
#
AC_CHECK_FUNCS([flockfile getc_unlocked])

#
# Look for sysconf to allow detection of the number of processors.
#
AC_CHECK_FUNCS([sysconf])

#
# Do we want to use pthread rwlock?
#
AC_ARG_ENABLE([pthread_rwlock],
	      [AS_HELP_STRING([--enable-pthread-rwlock],
			      [use pthread rwlock instead of internal rwlock implementation])],
	      [], [enable_pthread_rwlock=no])

AS_IF([test "$enable_pthread_rwlock" = "yes"],
      [AC_CHECK_FUNCS([pthread_rwlock_rdlock], [],
		      [AC_MSG_ERROR([pthread_rwlock_rdlock requested but not found])])
       AC_DEFINE([USE_PTHREAD_RWLOCK],[1],[Define if you want to use pthread rwlock implementation])
      ])

CRYPTO=OpenSSL

#
# OpenSSL/LibreSSL is mandatory
#
PKG_CHECK_MODULES([OPENSSL], [libcrypto], [],
		  [AX_CHECK_OPENSSL([:],[AC_MSG_FAILURE([OpenSSL/LibreSSL not found])])])

AX_SAVE_FLAGS([openssl])

CFLAGS="$CFLAGS $OPENSSL_CFLAGS"
LIBS="$LIBS $OPENSSL_LIBS"

AC_MSG_CHECKING([for OpenSSL >= 1.0.0 or LibreSSL])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <openssl/opensslv.h>]],
		     [[#if !defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x1000000fL)
		       #error OpenSSL >= 1.0.0 or LibreSSL required
		       #endif
		      ]])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_FAILURE([not found])])

#
# Check for functions added in OpenSSL or LibreSSL
#

AC_CHECK_FUNCS([CRYPTO_zalloc])
AC_CHECK_FUNCS([EVP_CIPHER_CTX_new EVP_CIPHER_CTX_free])
AC_CHECK_FUNCS([EVP_MD_CTX_new EVP_MD_CTX_free EVP_MD_CTX_reset])
AC_CHECK_FUNCS([HMAC_CTX_new HMAC_CTX_free HMAC_CTX_reset HMAC_CTX_get_md])

#
# Check for algorithm support in OpenSSL
#

AC_CHECK_FUNCS([ECDSA_sign ECDSA_verify], [:],
	       [AC_MSG_FAILURE([ECDSA support in OpenSSL is mandatory.])])

AC_MSG_CHECKING([for ECDSA P-256 support])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <openssl/evp.h>
		       #include <openssl/ec.h>]],
		     [[EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);]])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_FAILURE([not found.  ECDSA P-256 support in OpenSSL is mandatory.])])

AC_MSG_CHECKING([for ECDSA P-384 support])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <openssl/evp.h>
		       #include <openssl/ec.h>]],
		     [[EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp384r1);]])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_FAILURE([not found.  ECDSA P-384 support in OpenSSL is mandatory.])])

AC_MSG_CHECKING([for Ed25519 support])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <openssl/evp.h>
		       #include <openssl/ec.h>]],
		     [[EC_KEY *key = EC_KEY_new_by_curve_name(NID_ED25519);]])],
    [AC_DEFINE([HAVE_OPENSSL_ED25519], [1], [define if OpenSSL supports Ed25519])
     AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])])

AC_MSG_CHECKING([for Ed448 support])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <openssl/evp.h>
		       #include <openssl/ec.h>]],
		     [[EC_KEY *key = EC_KEY_new_by_curve_name(NID_ED448);]])],
    [AC_DEFINE([HAVE_OPENSSL_ED448], [1], [define if OpenSSL supports Ed448])
     AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])])

AC_MSG_CHECKING([for SipHash support])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <openssl/evp.h>
		       #include <openssl/opensslv.h>]],
		     [[#if OPENSSL_VERSION_NUMBER < 0x10101010L
		       #error OpenSSL >= 1.1.1a required for working SipHash initialization
		       #endif
		       EVP_PKEY *key = EVP_PKEY_new_raw_private_key(
			   EVP_PKEY_SIPHASH, NULL, NULL, 0);]])],
    [AC_DEFINE([HAVE_OPENSSL_SIPHASH], [1], [define if OpenSSL supports SipHash])
     AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])])

#
# Check for OpenSSL SHA-1 support
#
AC_CHECK_FUNCS([EVP_sha1], [:],
	       [AC_MSG_FAILURE([SHA-1 support in OpenSSL is mandatory.])])

#
# Check for OpenSSL SHA-2 support
#
AC_CHECK_FUNCS([EVP_sha224 EVP_sha256 EVP_sha384 EVP_sha512], [:],
	       [AC_MSG_FAILURE([SHA-2 support in OpenSSL is mandatory.])])

#
# Check for OpenSSL AES support
#
AC_CHECK_FUNCS([EVP_aes_128_ecb EVP_aes_192_ecb EVP_aes_256_ecb], [:],
	       [AC_MSG_FAILURE([AES support in OpenSSL is mandatory.])])

#
# Check for OpenSSL 1.1.x/LibreSSL functions
#
AC_CHECK_FUNCS([DH_get0_key ECDSA_SIG_get0 RSA_set0_key])

#
# Check whether FIPS mode is available and whether we should enable it
#
AC_ARG_ENABLE([fips-mode],
	      [AS_HELP_STRING([--enable-fips-mode],
			      [enable FIPS mode in OpenSSL library [default=no]])],
	      [], [enable_fips_mode="no"])

AC_MSG_CHECKING([whether to enable FIPS mode in OpenSSL library])
AS_CASE([$enable_fips_mode],
	[yes], [AC_MSG_RESULT([yes])
		AC_CHECK_FUNCS([FIPS_mode],
			       [], [AC_MSG_FAILURE([OpenSSL FIPS mode requested but not available.])])],
	[no], [AC_MSG_RESULT([no])])

AX_RESTORE_FLAGS([openssl])

AC_SUBST([OPENSSL_CFLAGS])
AC_SUBST([OPENSSL_LIBS])

#
# was --enable-native-pkcs11 specified?
#
AC_ARG_ENABLE([native-pkcs11],
	      AS_HELP_STRING([--enable-native-pkcs11],
			     [use native PKCS11 for public-key crypto [default=no]]),
	      [:], [enable_native_pkcs11="no"])

AC_MSG_CHECKING([for PKCS11 for Public-Key Cryptography])
AS_CASE([$enable_native_pkcs11],
	[no],[AC_MSG_RESULT([no])],
	[yes],[CRYPTO=pkcs11
	       AC_MSG_RESULT([yes])
	       AC_CHECK_FUNCS([getpassphrase])
	      ])
AM_CONDITIONAL([HAVE_PKCS11], [test "$CRYPTO" = "pkcs11"])

AC_SUBST([CRYPTO])
AS_CASE([$CRYPTO],
	[pkcs11],[AC_DEFINE([USE_PKCS11], [1], [define if PKCS11 is used for Public-Key Cryptography])],
	[AC_DEFINE([USE_OPENSSL], [1], [define if OpenSSL is used for Public-Key Cryptography])])

#
# was --with-pkcs11 specified?
#
AC_ARG_WITH([pkcs11],
	    [AS_HELP_STRING([--with-pkcs11[=PATH]],
			    [Build with PKCS11 support [no|path] (PATH is for the PKCS11 provider)])],
	    [:], [with_pkcs11="undefined"])

AS_CASE([$with_pkcs11],
	[yes|auto],[AC_MSG_ERROR([--with-pkcs11 needs explicit path to the PKCS11 library])],
	[no|undefined],[with_pkcs11="undefined"])
AC_DEFINE_UNQUOTED([PK11_LIB_LOCATION], ["$with_pkcs11"], [define the default PKCS11 library path])

AC_CHECK_FUNCS([clock_gettime])

AC_ARG_WITH([gssapi],
	    [AS_HELP_STRING([--with-gssapi=[PATH|[/path/]krb5-config]],
			   [Specify path for system-supplied GSSAPI
				[default=auto]])],
	    [], [with_gssapi="auto"])

KRB5_CONFIG=
AS_CASE([$with_gssapi],
	[no],[AC_MSG_CHECKING([for GSSAPI support])
	      AC_MSG_RESULT([no])],
	[yes],[AC_PATH_PROG([KRB5_CONFIG], [krb5-config])
	       AS_IF([test -z "$KRB5_CONFIG"],
		     [AC_MSG_ERROR([krb5-config required but not found])])],
	[auto],[AC_PATH_PROG([KRB5_CONFIG], [krb5-config])],
	[*krb5-config*],[KRB5_CONFIG="$with_gssapi"],
	[AC_MSG_ERROR([--with-gssapi requires yes|no|auto|/path/to/krb5-config])])

GSSAPI_CFLAGS=
GSSAPI_LIBS=
KRB5_CFLAGS=
KRB5_LIBS=
AS_IF([test -n "$KRB5_CONFIG"],
      [AC_MSG_CHECKING([for gssapi libraries])
       AX_SAVE_FLAGS([gssapi])
       GSSAPI_CFLAGS=`"$KRB5_CONFIG" --cflags gssapi`
       GSSAPI_LIBS=`"$KRB5_CONFIG" --libs gssapi`
       CFLAGS="$CFLAGS $GSSAPI_CFLAGS"
       LIBS="$LIBS $GSSAPI_LIBS"
       AC_MSG_RESULT([$GSSAPI_CFLAGS $GSSAPI_LIBS])
       AC_CHECK_HEADERS([gssapi/gssapi.h], [],
			[AC_CHECK_HEADERS([gssapi.h], [],
					  [AC_MSG_ERROR([neither gssapi/gssapi.h nor gssapi.h found])])])
       AC_CHECK_HEADERS([gssapi/gssapi_krb5.h],
			[AC_CHECK_HEADERS([gssapi_krb5.h], []
					  [AC_MSG_ERROR([neither gssapi/gssapi_krb5.h nor gssapi_krb5.h found])])])
       AC_CHECK_FUNCS([gss_acquire_cred],[],
		      [AC_MSG_ERROR([linking with $GSSAPI_LIBS does not work])])
       AX_RESTORE_FLAGS([gssapi])

       AC_MSG_CHECKING([for krb5 libraries])
       AX_SAVE_FLAGS([krb5])
       KRB5_CFLAGS=`"$KRB5_CONFIG" --cflags krb5`
       KRB5_LIBS=`$KRB5_CONFIG --libs krb5`
       CFLAGS="$CFLAGS $KRB5_CFLAGS"
       LIBS="$CFLAGS $KRB5_LIBS"
       AC_MSG_RESULT([$KRB5_CFLAGS $KRB5_LIBS])
       AC_CHECK_HEADERS([krb5/krb5.h], [],
			[AC_CHECK_HEADERS([krb5.h], [],
					  [AC_MSG_ERROR([neither krb5/krb5.h nor krb5 found])])])
       AC_CHECK_FUNCS([krb5_init_context], [],
		      [AC_MSG_ERROR([linking with $KRB5_LIBS failed])])
       AX_RESTORE_FLAGS([krb5])

       AC_DEFINE([HAVE_GSSAPI], [1], [Define to 1 if you have the Kerberos Framework available])
       # kludge to silence compiler warnings which recommend use of GSS.framework on macOS
       AS_CASE([$host],[*-darwin*],[CFLAGS="$CFLAGS -Wno-deprecated-declarations"])])
AM_CONDITIONAL([HAVE_GSSAPI], [test -n "$GSSAPI_LIBS"])
AC_SUBST([GSSAPI_CFLAGS])
AC_SUBST([GSSAPI_LIBS])
AC_SUBST([KRB5_CFLAGS])
AC_SUBST([KRB5_LIBS])

#
# was --with-lmdb specified?
#

AC_ARG_WITH([lmdb],
	    [AS_HELP_STRING([--with-lmdb=@<:@PATH@:>@],
			    [use LMDB library @<:@default=auto@:>@, optionally specify the prefix for lmdb library])],
	    [:],
	    [with_lmdb="auto"])

ac_lib_lmdb_found=no
AS_CASE([$with_lmdb],
	[no],[],
	[auto|yes], [PKG_CHECK_MODULES([LMDB], [lmdb],
				       [ac_lib_lmdb_found=yes],
				       [for ac_lib_lmdb_path in /usr /usr/local /opt /opt/local; do
						AX_LIB_LMDB([$ac_lib_lmdb_path],
							    [ac_lib_lmdb_found=yes
							     break])
					done
				       ])],
	[AX_LIB_LMDB([$with_lmdb],[ac_lib_lmdb_found=yes])])

# don't fail when in automatic mode
AS_IF([test "$with_lmdb" = "auto" && test "$ac_lib_lmdb_found" = "no"],
      [with_lmdb=no])

# hard fail when LMDB requested, but not found
AS_IF([test "$with_lmdb" != "no" && test "$ac_lib_lmdb_found" != "yes"],
      [AC_MSG_ERROR([LMDB requested, but not found])])

AS_IF([test "$ac_lib_lmdb_found" = "yes"],
      [AC_DEFINE([HAVE_LMDB], [1], [Use lmdb library])])

AC_SUBST([LMDB_CFLAGS])
AC_SUBST([LMDB_LIBS])
AM_CONDITIONAL([HAVE_LMDB], [test -n "$LMDB_LIBS"])

#
# was --with-libxml2 specified?
#
AC_ARG_WITH([libxml2],
	    [AS_HELP_STRING([--with-libxml2],
			    [build with libxml2 library [yes|no|auto] (default is auto)])],
	    [], [with_libxml2="auto"])

AS_CASE([$with_libxml2],
	[no],[],
	[auto],[PKG_CHECK_MODULES([LIBXML2], [libxml-2.0 >= 2.6.0],
				  [AC_DEFINE([HAVE_LIBXML2], [1], [Use libxml2 library])],
				  [:])],
	[yes],[PKG_CHECK_MODULES([LIBXML2], [libxml-2.0 >= 2.6.0],
				 [AC_DEFINE([HAVE_LIBXML2], [1], [Use libxml2 library])])],
	[AC_MSG_ERROR([Specifying libxml2 installation path is not supported, adjust PKG_CONFIG_PATH instead])])

AM_CONDITIONAL([HAVE_LIBXML2], [test -n "$LIBXML2_LIBS"])

#
# was --with-json-c specified?
#
AC_ARG_WITH([json-c],
	    [AS_HELP_STRING([--with-json-c],
			    [build with json-c library [yes|no|detect] (default is detect)])],
	    [], [with_json_c="detect"])

AS_CASE([$with_json_c],
	[no],[],
	[detect],[PKG_CHECK_MODULES([JSON_C], [json-c >= 0.11],
				    [AC_DEFINE([HAVE_JSON_C], [1], [Use json-c library])],
				    [:])],
	[yes],[PKG_CHECK_MODULES([JSON_C], [json-c >= 0.11],
				 [AC_DEFINE([HAVE_JSON_C], [1], [Use json-c library])])],
	[AC_MSG_ERROR([Specifying json-c installation path is not supported, adjust PKG_CONFIG_PATH instead])]
       )

AM_CONDITIONAL([HAVE_JSON_C], [test -n "$JSON_C_LIBS"])

AC_SUBST([JSON_C_CFLAGS])
AC_SUBST([JSON_C_LIBS])

#
# was --with-zlib specified?
#
AC_ARG_WITH([zlib],
	    [AS_HELP_STRING([--with-zlib],
			    [build with zlib for HTTP compression
			     [default=yes]])],
	    [], with_zlib="auto")

AS_CASE([$with_zlib],
       [no],[],
       [auto],[PKG_CHECK_MODULES([ZLIB], [zlib],
                                 [AC_DEFINE([HAVE_ZLIB], [1], [Use zlib library])],
                                 [:])],
       [yes],[PKG_CHECK_MODULES([ZLIB], [zlib],
                                [AC_DEFINE([HAVE_ZLIB], [1], [Use zlib library])])],
       [AC_MSG_ERROR([Specifying zlib installation path is not supported, adjust PKG_CONFIG_PATH instead])])
AC_SUBST([ZLIB_CFLAGS])
AC_SUBST([ZLIB_LIBS])

#
# Google/Great Performance Tools CPU Profiler
#
AC_MSG_CHECKING(whether to use gperftools profiler)
AC_ARG_WITH(gperftools-profiler,
	    AS_HELP_STRING([--with-gperftools-profiler],
			   [use gperftools CPU profiler]),
	    use_profiler="$withval", use_profiler="no")

case $use_profiler in
	yes)
		AC_MSG_RESULT(yes)
		AC_DEFINE([HAVE_GPERFTOOLS_PROFILER], 1,
		[Define to use gperftools CPU profiler.])
		LIBS="$LIBS -lprofiler"
		;;
	*)
		AC_MSG_RESULT(no)
		;;
esac

#
# Check if the system supports glibc-compatible backtrace() function.
#
AC_CHECK_HEADERS([execinfo.h],
		 [AC_SEARCH_LIBS([backtrace], [execinfo],
				 [AC_CHECK_FUNCS([backtrace backtrace_symbols])])])

AM_CONDITIONAL([HAVE_BACKTRACE], [test "$ac_cv_func_backtrace" = "yes"])

#
# We do the IPv6 compilation checking after libtool so that we can put
# the right suffix on the files.
#
AC_MSG_CHECKING([for IPv6 structures])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
     [[
       #include <sys/types.h>
       #include <sys/socket.h>
       #include <netinet/in.h>
     ]],
     [[
       struct sockaddr_in6 sin6;
       struct in6_addr in6;
       struct in6_pktinfo in6_pi;
       struct sockaddr_storage storage;
       in6 = in6addr_any;
       in6 = in6addr_loopback;
       sin6.sin6_scope_id = 0;
       return (0);
     ]])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_FAILURE([IPv6 support is mandatory])])

#
# Allow forcibly disabling TCP Fast Open support as autodetection might yield
# confusing results on some systems (e.g. FreeBSD; see set_tcp_fastopen()
# comment in lib/isc/unix/socket.c).
#

AC_ARG_ENABLE([tcp_fastopen],
	      [AS_HELP_STRING([--disable-tcp-fastopen],
			      [disable TCP Fast Open support [default=yes]])],
	      [], [enable_tcp_fastopen="yes"])

AS_IF([test "$enable_tcp_fastopen" = "yes"],
      [AC_DEFINE([ENABLE_TCP_FASTOPEN], [1], [define if you want TCP_FASTOPEN enabled if available])])

#
# Check for some other useful functions that are not ever-present.
#
AC_CHECK_FUNCS([strlcpy strlcat])

AC_SUBST(READLINE_LIB)
AC_ARG_WITH(readline,
	    AS_HELP_STRING([--with-readline[=LIBSPEC]],
			   [specify readline library [default auto]]),
	    use_readline="$withval", use_readline="auto")
case "$use_readline" in
no)	;;
*)
	saved_LIBS="$LIBS"
	case "$use_readline" in
	yes|auto) try_readline="-ledit"; or_readline="-lreadline" ;;
	*) try_readline="$use_readline"
	esac
	for readline in "$try_readline" $or_readline
	do
		LIBS="$readline"
		AC_MSG_NOTICE(checking for readline with $readline)
		AC_CHECK_FUNCS(readline)
		if test "yes" = "$ac_cv_func_readline"
		then
			READLINE_LIB="$readline"
			break
		fi
		for lib in -lterminfo -ltermcap -lncurses -lcurses
		do
			AC_MSG_NOTICE(checking for readline with $readline $lib)
			unset ac_cv_func_readline
			LIBS="$readline $lib"
			AC_CHECK_FUNCS(readline)
			if test "yes" = "$ac_cv_func_readline"
			then
				READLINE_LIB="$readline $lib"
				break
			fi
		done
		if test "yes" = "$ac_cv_func_readline"
		then
			break
		fi
	done
	if test "auto" != "$use_readline" &&
	   test "X$READLINE_LIB" = "X"
	then
		AC_MSG_ERROR([The readline library was not found.])
	fi
	LIBS="$saved_LIBS"
	;;
esac
if test "yes" = "$ac_cv_func_readline"
then
	case "$READLINE_LIB" in
	*edit*)
		AC_CHECK_HEADERS(editline/readline.h)
		AC_CHECK_HEADERS(edit/readline/readline.h)
		AC_CHECK_HEADERS(edit/readline/history.h)
		;;
	esac
	AC_CHECK_HEADERS(readline/readline.h)
	AC_CHECK_HEADERS(readline/history.h)
fi

#
# Security Stuff
#
# Note it is very recommended to *not* disable chroot(),
# this is only because chroot() was made obsolete by Posix.
AC_ARG_ENABLE(chroot, AS_HELP_STRING([--disable-chroot], [disable chroot]))
case "$enable_chroot" in
	yes|'')
		AC_CHECK_FUNCS(chroot)
		;;
	no)
		;;
esac

LIBCAP_LIBS=""
AC_MSG_CHECKING([whether to enable Linux capabilities])
AC_ARG_ENABLE([linux-caps],
	      [AS_HELP_STRING([--disable-linux-caps],
			      [disable Linux capabilities])],
	      [],
	      [AS_CASE([$host],
		       [*-linux*],[enable_linux_caps=yes],
		       [enable_linux_caps=no])])

AS_IF([test "$enable_linux_caps" = "yes"],
      [AC_MSG_RESULT([yes])
       AC_CHECK_HEADERS([sys/capability.h],
			[],
			[AC_MSG_ERROR(m4_normalize([sys/capability.h header is required for Linux capabilities support.
						    Either install libcap or use --disable-linux-caps.]))])
       AX_SAVE_FLAGS([cap])
       AC_SEARCH_LIBS([cap_set_proc], [cap],
		      [LIBCAP_LIBS="$ac_cv_search_cap_set_proc"],
		      [AC_MSG_ERROR(m4_normalize([libcap is required for Linux capabilities support.
						  Either install libcap or use --disable-linux-caps.]))])
       AX_RESTORE_FLAGS([cap])],
      [AC_MSG_RESULT([no])])
AC_SUBST([LIBCAP_LIBS])

case "$host" in
*-solaris*)
	AC_DEFINE(NEED_SECURE_DIRECTORY, 1,
		  [Define if connect does not honour the permission on the UNIX domain socket.])
	;;
esac

#
# Time Zone Stuff
#
AC_CHECK_FUNCS([tzset])

AC_MSG_CHECKING(for optarg declaration)
AC_TRY_COMPILE([
#include <unistd.h>
],
[optarg = 0;],
[AC_MSG_RESULT(yes)],
[AC_MSG_RESULT(no)
GEN_NEED_OPTARG="-DNEED_OPTARG=1"
AC_DEFINE(NEED_OPTARG, 1, [Defined if extern char *optarg is not declared.])])

#
# Check for nanoseconds in file stats
#
AC_MSG_CHECKING([for st_mtim.tv_nsec])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
     [[#include <sys/fcntl.h>]],
     [[struct stat s;
       return(s.st_mtim.tv_nsec);
      ]])],
   [AC_DEFINE([HAVE_STAT_NSEC], [1], [define if struct stat has st_mtim.tv_nsec field])])

#
# Check for if_nametoindex() for IPv6 scoped addresses support
#
AC_CHECK_FUNCS([if_nametoindex])

AC_CHECK_FUNCS(nanosleep usleep explicit_bzero)

ISC_ATOMIC_LIBS=""
AC_CHECK_HEADERS(
  [stdatomic.h],
  [AC_MSG_CHECKING([for memory model aware atomic operations])
   AC_COMPILE_IFELSE(
     [AC_LANG_PROGRAM(
	[[#include <stdatomic.h>]],
	[[atomic_int_fast32_t val = 0; atomic_fetch_add_explicit(&val, 1, memory_order_relaxed);]]
      )],
     [AC_MSG_RESULT([stdatomic.h])
      AC_MSG_CHECKING([whether -latomic is needed for 64-bit stdatomic.h functions])
      AC_LINK_IFELSE(
	[AC_LANG_PROGRAM(
	   [[#include <stdatomic.h>]],
	   [[atomic_int_fast64_t val = 0; atomic_fetch_add_explicit(&val, 1, memory_order_relaxed);]]
	 )],
	[AC_MSG_RESULT([no])],
	[ISC_ATOMIC_LIBS="-latomic"
	 AX_SAVE_FLAGS([atomic])
	 LIBS="$LIBS $ISC_ATOMIC_LIBS"
	 AC_LINK_IFELSE(
	   [AC_LANG_PROGRAM(
	      [[#include <stdatomic.h>]],
	      [[atomic_int_fast64_t val = 0; atomic_fetch_add_explicit(&val, 1, memory_order_relaxed);]]
	    )],
	   [AC_MSG_RESULT([yes])],
	   [AC_MSG_FAILURE([libatomic needed, but linking with -latomic failed, please fix your toolchain.])])
	 AX_RESTORE_FLAGS([atomic])
	])
     ],
     [AC_MSG_FAILURE([stdatomic.h header found, but compilation failed, please fix your toolchain.])]
   )],
  [AC_MSG_CHECKING([for memory model aware atomic operations])
   AC_COMPILE_IFELSE(
     [AC_LANG_PROGRAM(
	[[#include <inttypes.h>]],
	[[int32_t val = 0; __atomic_fetch_add(&val, 1, __ATOMIC_RELAXED);]]
      )],
     [AC_MSG_RESULT([__atomic builtins])
      AC_DEFINE([HAVE___ATOMIC], [1], [define if __atomic builtins are not available])
      AC_MSG_CHECKING([whether -latomic is needed for 64-bit __atomic builtins])
      AC_LINK_IFELSE(
	[AC_LANG_PROGRAM(
	   [[#include <inttypes.h>]],
	   [[int64_t val = 0; __atomic_fetch_add(&val, 1, __ATOMIC_RELAXED);]]
	 )],
	[AC_MSG_RESULT([no])],
	[ISC_ATOMIC_LIBS="-latomic"
	 AX_SAVE_FLAGS([atomic])
	 LIBS="$LIBS $ISC_ATOMIC_LIBS"
	 AC_LINK_IFELSE(
	   [AC_LANG_PROGRAM(
	      [[#include <inttypes.h>]],
	      [[int64_t val = 0; __atomic_fetch_add(&val, 1, __ATOMIC_RELAXED);]]
	    )],
	   [AC_MSG_RESULT([yes])],
	   [AC_MSG_FAILURE([libatomic needed, but linking with -latomic failed, please fix your toolchain.])])
	 AX_RESTORE_FLAGS([atomic])
	])
     ],
     [AC_MSG_RESULT([__sync builtins])
     ])
  ])
LIBS="$LIBS $ISC_ATOMIC_LIBS"

AC_CHECK_HEADERS([stdalign.h])

AC_CHECK_HEADERS([uchar.h])

#
# Check for __builtin_unreachable
#
AC_MSG_CHECKING([compiler support for __builtin_unreachable()])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
     [[]],
     [[__builtin_unreachable();]]
   )],
  [AC_MSG_RESULT([yes])
   AC_DEFINE([HAVE_BUILTIN_UNREACHABLE], [1], [define if the compiler supports __builtin_unreachable().])
  ],
  [AC_MSG_RESULT([no])
  ])

#
# Check for __builtin_expect
#
AC_MSG_CHECKING([compiler support for __builtin_expect])
AC_TRY_LINK(, [
	return (__builtin_expect(1, 1) ? 1 : 0);
], [
	have_builtin_expect=yes
	AC_MSG_RESULT(yes)
], [
	have_builtin_expect=no
	AC_MSG_RESULT(no)
])
if test "yes" = "$have_builtin_expect"; then
	AC_DEFINE(HAVE_BUILTIN_EXPECT, 1, [Define to 1 if the compiler supports __builtin_expect.])
fi

#
# Check for __builtin_clz
#
AC_MSG_CHECKING([compiler support for __builtin_clz])
AC_TRY_LINK(, [
	return (__builtin_clz(0xff) == 24 ? 1 : 0);
], [
	have_builtin_clz=yes
	AC_MSG_RESULT(yes)
], [
	have_builtin_clz=no
	AC_MSG_RESULT(no)
])
if test "yes" = "$have_builtin_clz"; then
	AC_DEFINE(HAVE_BUILTIN_CLZ, 1, [Define to 1 if the compiler supports __builtin_clz.])
fi

#
# Activate "rrset-order fixed" or not?
#
AC_ARG_ENABLE([fixed-rrset],
	      [AS_HELP_STRING([--enable-fixed-rrset],
			      [enable fixed rrset ordering [default=no]])],
	      [], [enable_fixed_rrset="no"])
AS_IF([test "$enable_fixed_rrset" = "yes"],
      [AC_DEFINE([DNS_RDATASET_FIXED], [1],
		 [Define to enable "rrset-order fixed" syntax.])])

#
# Activate dnstap?
#
AC_ARG_ENABLE([dnstap],
	      [AS_HELP_STRING([--enable-dnstap],
			      [enable dnstap support
			       (requires fstrm, protobuf-c)])],
	      [], [enable_dnstap=no])

AS_IF([test "$enable_dnstap" != "no"],
      [PKG_CHECK_MODULES([DNSTAP], [libfstrm libprotobuf-c], [],
			 [AC_MSG_FAILURE([Required libraries (fstrm, protobuf-c) were not found, please install them.])])
       AC_PATH_PROG([FSTRM_CAPTURE], [fstrm_capture])
       AC_PATH_PROG([PROTOC_C], [protoc-c])
       AS_IF([test -z "$PROTOC_C"],
	     [AC_MSG_ERROR([protoc-c compiler not found])])
       AC_DEFINE([HAVE_DNSTAP], 1, [Define to 1 to enable dnstap support])
      ])

AC_SUBST([DNSTAP_CFLAGS])
AC_SUBST([DNSTAP_LIBS])
AM_CONDITIONAL([HAVE_DNSTAP], [test "$enable_dnstap" != "no"])
#
# The following sections deal with tools used for formatting
# the documentation.  They are all optional, unless you are
# a developer editing the documentation source.
#

#
# Look for sphinx-build
#
AC_ARG_VAR([SPHINX_BUILD], [path to sphinx-build binary used to build the documentation])
AC_PATH_PROG([SPHINX_BUILD], [sphinx-build], [:])
AM_CONDITIONAL([HAVE_SPHINX_BUILD], [test "$SPHINX_BUILD" != ":"])

AC_PATH_PROG([XELATEX], [xelatex], [:])
AC_PATH_PROG([LATEXMK], [latexmk], [:])
AM_CONDITIONAL([HAVE_XELATEX], [test "$XELATEX" != ":" && test "$LATEXMK" != ":"])

#
# Pull release date from CHANGES file last modification date
# for reproducible builds
#
release_date=`date -r CHANGES +%Y-%m-%d`
AC_SUBST([RELEASE_DATE], $release_date)

#
# Look for Doxygen
#
AC_PATH_PROGS([DOXYGEN], [doxygen])

AC_CONFIG_FILES([doc/doxygen/doxygen-input-filter],
		[chmod +x doc/doxygen/doxygen-input-filter])

#
# Look for curl
#

AC_PATH_PROG(CURL, curl, curl)
AC_SUBST(CURL)

#
# IDN support using libidn2
#

LIBIDN2_CFLAGS=
LIBIDN2_LDFLAGS=
LIBIDN2_LIBS=
AC_ARG_WITH([libidn2],
	    [AS_HELP_STRING([--with-libidn2[=PATH]], [enable IDN support using GNU libidn2 [yes|no(default)|path]])],
	    [with_libidn2="$withval"], [with_libidn2="no"])
AS_CASE([$with_libidn2],
	[yes],	[PKG_CHECK_MODULES([LIBIDN2], [libidn2],
				   [AC_DEFINE([HAVE_LIBIDN2], [1], [Define if libidn2 was found])])],
	[no],	[],
	[*],	[AX_SAVE_FLAGS([libidn2])
		 LIBIDN2_CFLAGS="-I$with_libidn2/include"
		 LIBIDN2_LDFLAGS="-L$with_libidn2/lib"
		 CFLAGS="$LIBIDN2_CFLAGS $CFLAGS"
		 CPPFLAGS="$LIBIDN2_CFLAGS $CPPFLAGS"
		 LDFLAGS="$LIBIDN2_LDFLAGS $LDFLAGS"
		 AC_CHECK_HEADERS([idn2.h],
				  [],
				  [AC_MSG_ERROR([idn2.h not found])])
		 AC_SEARCH_LIBS([idn2_to_ascii_lz], [idn2],
				[LIBIDN2_LIBS="$ac_cv_search_idn2_to_ascii_lz"
				 AC_DEFINE([HAVE_LIBIDN2], [1], [Define if libidn2 was found])],
				[AC_MSG_ERROR([libidn2 requested, but not found])])
		AX_RESTORE_FLAGS([libidn2])])
AC_SUBST([LIBIDN2_CFLAGS])
AC_SUBST([LIBIDN2_LDFLAGS])
AC_SUBST([LIBIDN2_LIBS])

#
# Check whether to build with cmocka unit testing framework
#

AC_ARG_WITH([cmocka],
	    [AS_HELP_STRING([--with-cmocka=detect],[enable CMocka based tests (default is detect)])],
	    [],[with_cmocka=detect])

AS_CASE([$with_cmocka],
	[no],[],
	[detect],[PKG_CHECK_MODULES([CMOCKA], [cmocka >= 1.0.0],
				    [AC_DEFINE([HAVE_CMOCKA], [1], [Use CMocka])
				     with_cmocka=yes],[with_cmocka=no])],
	[yes],[PKG_CHECK_MODULES([CMOCKA], [cmocka >= 1.0.0],
				 [AC_DEFINE([HAVE_CMOCKA], [1], [Use CMocka])])],
	[AC_MSG_ERROR([Use PKG_CONFIG_PATH to specify path to CMocka library])]
       )
AC_SUBST([CMOCKA_CFLAGS])
AC_SUBST([CMOCKA_LIBS])

AM_CONDITIONAL([HAVE_CMOCKA], [test "$with_cmocka" = "yes"])

#
# Check for -Wl,--wrap= support
#

LD_WRAP_TESTS=false
AC_MSG_CHECKING([for linker support for --wrap option])
AX_SAVE_FLAGS([wrap])
LDFLAGS="-Wl,-wrap,exit"
AC_RUN_IFELSE(
    [AC_LANG_PROGRAM([[#include <stdlib.h>
		       void __real_exit (int status);
		       void __wrap_exit (int status) { __real_exit (status); }
		      ]],
		     [[exit (1);]])],
    [LD_WRAP_TESTS=true
     AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])])
AX_RESTORE_FLAGS([wrap])

AM_CONDITIONAL([HAVE_LD_WRAP], [test "$LD_WRAP_TESTS" = "true"])

WRAP_INTERPOSE=
AC_MSG_CHECKING([for linker support for '-z interpose' option])
AX_SAVE_FLAGS([interpose])
LDFLAGS="-Wl,-z,interpose"
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([],[])],
    [WRAP_INTERPOSE="-Wl,-z,interpose"
     AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])])
AX_RESTORE_FLAGS([interpose])

AC_SUBST([WRAP_INTERPOSE])

WRAP_NAME=''
AS_CASE([$host],[*-darwin*],[WRAP_NAME='${WRAP_NAME}'])
AC_SUBST([WRAP_NAME])

#
# Check for i18n
#
AC_CHECK_HEADERS(locale.h)
AC_CHECK_FUNCS(setlocale)

#
# was --with-tuning specified?
#
AC_ARG_WITH([tuning],
	    AS_HELP_STRING([--with-tuning=ARG],
			   [Specify server tuning (default or small)]),
	    [],[with_tuning=no])

AS_CASE([$with_tuning],
	[small],[AC_MSG_NOTICE(using small system tuning)],
	[AC_DEFINE(TUNE_LARGE, 1, [Define to use default system tuning.])
	 AC_MSG_NOTICE(using default system tuning)])

#
# was --enable-querytrace specified?
#
AC_ARG_ENABLE(querytrace,
	      AS_HELP_STRING([--enable-querytrace],
			     [enable very verbose query trace logging
				[default=no]]),
	      enable_querytrace="$enableval", enable_querytrace="no")

AC_MSG_CHECKING([whether to enable query trace logging])
case "$enable_querytrace" in
yes)
	AC_MSG_RESULT(yes)
	AC_DEFINE(WANT_QUERYTRACE, 1, [Define to enable very verbose query trace logging.])
	;;
no)
	AC_MSG_RESULT(no)
	;;
*)
	AC_MSG_ERROR("--enable-querytrace requires yes or no")
	;;
esac

#
# Was --disable-auto-validation specified?
#
validation_default=auto
AC_ARG_ENABLE(auto-validation,
	      AS_HELP_STRING([--enable-auto-validation],
			     [turn on DNSSEC validation by default, using the IANA root key [default=yes]]),
	      [:],[enable_auto_validation=yes])
AS_IF([test "$enable_auto_validation" = "no"],[validation_default=yes])
AC_DEFINE_UNQUOTED([VALIDATION_DEFAULT], ["$validation_default"], [the default value of dnssec-validation option])

#
# Configure any DLZ drivers.
#
# If config.dlz.in selects one or more DLZ drivers, it will set
# CONTRIB_DLZ to a non-empty value, which will be our clue to
# build DLZ drivers in contrib.
#
# This section has to come after the libtool stuff because it needs to
# know how to name the driver object files.
#

CONTRIB_DLZ=""
DLZ_DRIVER_INCLUDES=""
DLZ_DRIVER_LIBS=""
DLZ_DRIVER_SRCS=""
DLZ_DRIVER_OBJS=""
DLZ_SYSTEM_TEST=""
DLZ_DRIVER_MYSQL_INCLUDES=""
DLZ_DRIVER_MYSQL_LIBS=""

#
#
# Response policy rewriting using DNS Response Policy Service (DNSRPS)
# interface.
#
# DNSRPS can be compiled into BIND everywhere with a reasonably
# modern C compiler.  It is enabled on systems with dlopen() and librpz.so.
#
dnsrps_avail=yes
AC_MSG_CHECKING([for librpz __attribute__s])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
     [[]],
     [[
       extern void f(char *p __attribute__((unused)), ...)
       __attribute__((format(printf,1,2))) __attribute__((__noreturn__));
     ]])],
  [
    librpz_have_attr=yes
    AC_DEFINE([LIBRPZ_HAVE_ATTR], [1], [have __attribute__s used in librpz.h])
    AC_MSG_RESULT([yes])
  ],[
    librpz_have_attr=no
    AC_MSG_RESULT([no])
  ])

AC_ARG_ENABLE([dnsrps-dl],
	      [AS_HELP_STRING([--enable-dnsrps-dl],
			      [DNS Response Policy Service delayed link
			       [default=$librpz_dl]])],
	      [enable_librpz_dl="$enableval"], [enable_librpz_dl="$with_dlopen"])

AS_IF([test "$enable_librpz_dl" = "yes" -a "$with_dlopen" = "no"],
      [AC_MSG_ERROR([DNS Response Policy Service delayed link requires dlopen to be enabled])])

AC_ARG_WITH([dnsrps-libname],
	    [AS_HELP_STRING([--with-dnsrps-libname],
			    [DNSRPS provider library name (librpz.so)])],
	    [librpz_name="$withval"], [librpz_name="librpz.so"])
AC_ARG_WITH([dnsrps-dir],
	    [AS_HELP_STRING([--with-dnsrps-dir],
			    [path to DNSRPS provider library])],
	    [librpz_path="$withval/$librpz_name"], [librpz_path="$librpz_name"])
AC_DEFINE_UNQUOTED([DNSRPS_LIBRPZ_PATH], ["$librpz_path"],
		   [dnsrps $librpz_name])
AS_IF([test "$enable_librpz_dl" = "yes"],
      [
	dnsrps_lib_open=2
      ],[
	dnsrps_lib_open=1
	# Add librpz.so to linked libraries if we are not using dlopen()
	AC_SEARCH_LIBS([librpz_client_create], [rpz], [],
		[dnsrps_lib_open=0
		 dnsrps_avail=no])
      ])
AC_DEFINE_UNQUOTED([DNSRPS_LIB_OPEN], [$dnsrps_lib_open],
		   [0=no DNSRPS  1=static link  2=dlopen()])

AC_ARG_ENABLE([dnsrps],
	      AS_HELP_STRING([--enable-dnsrps],
			     [enable DNS Response Policy Service API]),
	      [enable_dnsrps=$enableval], [enable_dnsrps=no])

AS_IF([test "$enable_dnsrps" != "no"],[
	AS_IF([test "$dnsrps_avail" != "yes"],
	      [AC_MSG_ERROR([dlopen and librpz.so needed for DNSRPS])])
	AS_IF([test "$dnsrps_lib_open" = "0"],
	      [AC_MSG_ERROR([dlopen and librpz.so needed for DNSRPS])])
	AC_DEFINE([USE_DNSRPS], [1], [Enable DNS Response Policy Service API])
      ])

# FIXME BEGIN
#sinclude(contrib/dlz/config.dlz.in)
# AC_MSG_CHECKING(contributed DLZ drivers)
#
# if test -n "$CONTRIB_DLZ"
# then
# 	AC_MSG_RESULT(yes)
# 	DLZ_DRIVER_RULES=contrib/dlz/drivers/rules
# 	AC_CONFIG_FILES([$DLZ_DRIVER_RULES
# 		contrib/dlz/modules/mysql/Makefile
# 		contrib/dlz/modules/mysqldyn/Makefile])
# else
# 	AC_MSG_RESULT(no)
# 	DLZ_DRIVER_RULES=/dev/null
# fi
#
# AC_SUBST(CONTRIB_DLZ)
# AC_SUBST(DLZ_DRIVER_INCLUDES)
# AC_SUBST(DLZ_DRIVER_LIBS)
# AC_SUBST(DLZ_DRIVER_SRCS)
# AC_SUBST(DLZ_DRIVER_OBJS)
# AC_SUBST(DLZ_SYSTEM_TEST)
# AC_SUBST(DLZ_DRIVER_MYSQL_INCLUDES)
# AC_SUBST(DLZ_DRIVER_MYSQL_LIBS)
# AC_SUBST_FILE(DLZ_DRIVER_RULES)
# this ensures the configure summary report comes out right
test -z "$with_dlz_bdb" && with_dlz_bdb=no
test -z "$with_dlz_ldap" && with_dlz_ldap=no
test -z "$with_dlz_mysql" && with_dlz_mysql=no
test -z "$with_dlz_odbc" && with_dlz_odbc=no
test -z "$with_dlz_postgres" && with_dlz_postgres=no
test -z "$with_dlz_filesystem" && with_dlz_filesystem=no
test -z "$with_dlz_stub" && with_dlz_stub=no
# FIXME END

AC_CHECK_HEADERS([glob.h])

#
# Files to configure.  These are listed here because we used to
# specify them as arguments to AC_OUTPUT.
#

# Top

AC_CONFIG_FILES([Makefile])

# Binaries

AC_CONFIG_FILES([bin/Makefile
		 bin/named/Makefile
		 bin/rndc/Makefile
		 bin/dig/Makefile
		 bin/delv/Makefile
		 bin/dnssec/Makefile
		 bin/tools/Makefile
		 bin/nsupdate/Makefile
		 bin/check/Makefile
		 bin/confgen/Makefile
		 bin/pkcs11/Makefile
		 bin/plugins/Makefile])

# Libraries

AC_CONFIG_FILES([lib/Makefile
		 lib/isc/Makefile
		 lib/dns/Makefile
		 lib/ns/Makefile
		 lib/irs/Makefile
		 lib/isccfg/Makefile
		 lib/isccc/Makefile
		 lib/bind9/Makefile
		 lib/samples/Makefile])

# Documentation

AC_CONFIG_FILES([doc/Makefile
		 doc/arm/Makefile
		 doc/man/Makefile
		 doc/misc/Makefile])

# Generated headers

AC_CONFIG_FILES([lib/isc/include/isc/platform.h])

# Unit Tests

AC_CONFIG_FILES([lib/isc/tests/Makefile
		 lib/dns/tests/Makefile
		 lib/ns/tests/Makefile
		 lib/irs/tests/Makefile
		 lib/isccc/tests/Makefile
		 lib/isccfg/tests/Makefile])

# System Tests

AC_CONFIG_FILES([bin/tests/Makefile
		 bin/tests/system/Makefile
		 bin/tests/system/conf.sh
		 bin/tests/system/dyndb/driver/Makefile
		 bin/tests/system/dlzexternal/driver/Makefile])

AC_CONFIG_FILES([bin/tests/system/ifconfig.sh],
		[chmod +x bin/tests/system/ifconfig.sh])
AC_CONFIG_FILES([bin/tests/system/run.sh],
		[chmod +x bin/tests/system/run.sh])
AC_CONFIG_FILES([bin/tests/system/start.sh],
		[chmod +x bin/tests/system/start.sh])
AC_CONFIG_FILES([bin/tests/system/stop.sh],
		[chmod +x bin/tests/system/stop.sh])

# Misc

AC_CONFIG_FILES([util/check-make-install])

#
# Do it
#

AC_OUTPUT

AC_ARG_ENABLE(full-report,
	      AS_HELP_STRING([--enable-full-report],
			     [report values of all configure options]))

report() {
    echo "==============================================================================="
    echo "Configuration summary:"
    echo "-------------------------------------------------------------------------------"
    echo "Optional features enabled:"
    if test "yes" = "$enable_full_report" -o "standard" = "$with_locktype"; then
	echo "    Mutex lock type: $with_locktype"
    fi
    test "small" = "$with_tuning" && echo "    Small-system tuning (--with-tuning)"
    test "no" = "$enable_dnstap" || \
	    echo "    Allow 'dnstap' packet logging (--enable-dnstap)"
    test -z "$MAXMINDDB_LIBS" || echo "    GeoIP2 access control (--enable-geoip)"
    test -z "$GSSAPI_LIBS" || echo "    GSS-API (--with-gssapi)"

    # these lines are only printed if run with --enable-full-report
    if test "yes" = "$enable_full_report"; then
	test -z "$PYTHON" || echo "    Python tools (--with-python)"
	test -z "$LIBXML2_LIBS" || echo "    XML statistics (--with-libxml2)"
	test -z "$JSON_C_LIBS" || echo "    JSON statistics (--with-json-c): $JSON_C_CFLAGS $JSON_C_LIBS"
	test -z "$ZLIB_LIBS" || echo "    HTTP zlib compression (--with-zlib)"
	test -z "$LMDB_LIBS" || echo "    LMDB database to store configuration for 'addzone' zones (--with-lmdb)"
	test -z "$LIBIDN2_LIBS" || echo "    IDN support (--with-libidn2)"
    fi

    test "yes" = "$enable_dnsrps" && \
	echo "    DNS Response Policy Service interface (--enable-dnsrps)"
    test "yes" = "$enable_fixed_rrset" && \
	echo "    Allow 'fixed' rrset-order (--enable-fixed-rrset)"
    test "yes" = "$enable_querytrace" && \
	echo "    Very verbose query trace logging (--enable-querytrace)"
    test -z "$HAVE_CMOCKA" || echo "    CMocka Unit Testing Framework (--with-cmocka)"

    test "auto" = "$validation_default" && echo "    DNSSEC validation active by default (--enable-auto-validation)"

    test "$CRYPTO" = "pkcs11" && (
	echo "    Using PKCS#11 for Public-Key Cryptography (--with-native-pkcs11)"
	echo "    PKCS#11 module (--with-pkcs11): $with_pkcs11"
    )

    echo "    Dynamically loadable zone (DLZ) drivers:"
    test "no" = "$with_dlz_bdb" || \
	echo "        Berkeley DB (--with-dlz-bdb)"
    test "no" = "$with_dlz_ldap" || \
	echo "        LDAP (--with-dlz-ldap)"
    test "no" = "$with_dlz_mysql" || \
	echo "        MySQL (--with-dlz-mysql)"
    test "no" = "$with_dlz_odbc" || \
	echo "        ODBC (--with-dlz-odbc)"
    test "no" = "$with_dlz_postgres" || \
	echo "        Postgres (--with-dlz-postgres)"
    test "no" = "$with_dlz_filesystem" || \
	echo "        Filesystem (--with-dlz-filesystem)"
    test "no" = "$with_dlz_stub" || \
	echo "        Stub (--with-dlz-stub)"
    test "$with_dlz_bdb $with_dlz_ldap $with_dlz_mysql $with_dlz_odbc $with_dlz_postgres $with_dlz_filesystem $with_dlz_stub" = "no no no no no no no" && \
            echo "        None"

    echo "-------------------------------------------------------------------------------"

    echo "Features disabled or unavailable on this platform:"
    test "small" = "$with_tuning" || echo "    Small-system tuning (--with-tuning)"

    test "no" = "$enable_dnstap" && \
	    echo "    Allow 'dnstap' packet logging (--enable-dnstap)"
    test -z "$MAXMINDDB_LIBS" && echo "    GeoIP2 access control (--enable-geoip)"
    test -z "$GSSAPI_LIBS" && echo "    GSS-API (--with-gssapi)"

    test "no" = "$enable_dnsrps" && \
	echo "    DNS Response Policy Service interface (--enable-dnsrps)"

    test "yes" = "$enable_fixed_rrset" || \
	echo "    Allow 'fixed' rrset-order (--enable-fixed-rrset)"

    test "yes" = "$validation_default" && echo "    DNSSEC validation requires configuration (--enable-auto-validation)"

    test "$CRYPTO" = "pkcs11" || (
	echo "    Using PKCS#11 for Public-Key Cryptography (--with-native-pkcs11)"
    )

    test "yes" = "$enable_querytrace" || \
	echo "    Very verbose query trace logging (--enable-querytrace)"

    test "no" = "$with_cmocka" && echo "    CMocka Unit Testing Framework (--with-cmocka)"

    test -z "$PYTHON" && echo "    Python tools (--with-python)"
    test -z "$LIBXML2_LIBS" && echo "    XML statistics (--with-libxml2)"
    test -z "$JSON_C_LIBS" && echo "    JSON statistics (--with-json-c)"
    test -z "$ZLIB_LIBS" && echo "    HTTP zlib compression (--with-zlib)"
    test -z "$LMDB_LIBS" && echo "    LMDB database to store configuration for 'addzone' zones (--with-lmdb)"
    test -z "$LIBIDN2_LIBS" && echo "    IDN support (--with-libidn2)"

    echo "-------------------------------------------------------------------------------"
    echo "Configured paths:"
    echo "    prefix: $prefix"
    echo "    sysconfdir: $sysconfdir"
    echo "    localstatedir: $localstatedir"
    echo "-------------------------------------------------------------------------------"
    echo "Compiler: $CC"
    $CC --version 2>&1 | sed 's/^/    /'
    echo "CFLAGS: $STD_CFLAGS $CFLAGS"
    echo "CPPFLAGS: $STD_CPPFLAGS $CPPFLAGS"
    echo "LDFLAGS: $LDFLAGS"

    if test "X$ac_unrecognized_opts" != "X"; then
        echo "-------------------------------------------------------------------------------"
	echo "Unrecognized options:"
	echo "    $ac_unrecognized_opts"
    fi

    if test "yes" != "$enable_full_report"; then
	echo "-------------------------------------------------------------------------------"
	echo "For more detail, use --enable-full-report."
    fi
    echo "==============================================================================="
}

if test "yes" != "$silent"; then
	report
fi

# Tell Emacs to edit this file in shell mode.
# Local Variables:
# mode: sh
# End:
