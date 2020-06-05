include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=				\
	-I$(srcdir)/unix/include	\
	-I$(top_builddir)/include	\
	$(LIBISC_CFLAGS)		\
	$(LIBDNS_CFLAGS)		\
	$(LIBNS_CFLAGS)			\
	$(LIBISCCC_CFLAGS)		\
	$(LIBISCCFG_CFLAGS)		\
	$(LIBBIND9_CFLAGS)		\
	$(LIBLTDL_CFLAGS)		\
	$(OPENSSL_CFLAGS)		\
	$(LIBCAP_CFLAGS)		\
	$(LMDB_CFLAGS)			\
	$(MAXMINDDB_CFLAGS)		\
	$(DNSTAP_CFLAGS)		\
	$(ZLIB_CFLAGS)

if HAVE_JSON_C
AM_CPPFLAGS +=				\
	$(JSON_C_CFLAGS)
endif HAVE_JSON_C

if HAVE_LIBXML2
AM_CPPFLAGS +=				\
	$(LIBXML2_CFLAGS)
endif HAVE_LIBXML2

AM_CPPFLAGS +=						\
	-DNAMED_LOCALSTATEDIR=\"${localstatedir}\"	\
	-DNAMED_SYSCONFDIR=\"${sysconfdir}\"

sbin_PROGRAMS = named

nodist_named_SOURCES = xsl.c
BUILT_SOURCES = xsl.c
CLEANFILES = xsl.c

EXTRA_DIST = bind9.xsl

xsl.c: bind9.xsl Makefile
	(echo 'const char xslmsg[] =' &&	\
	 $(SED)	-e 's,\",\\\",g'		\
		-e 's,^,\",'			\
		-e 's,$$,\",' &&		\
	 echo ";")				\
	< "${srcdir}/bind9.xsl" > $@

named_SOURCES =				\
	builtin.c			\
	config.c			\
	control.c			\
	controlconf.c			\
	fuzz.c				\
	log.c				\
	logconf.c			\
	main.c				\
	server.c			\
	statschannel.c			\
	tkeyconf.c			\
	tsigconf.c			\
	zoneconf.c			\
	unix/dlz_dlopen_driver.c	\
	unix/os.c			\
	include/dlz/dlz_dlopen_driver.h	\
	include/named/builtin.h		\
	include/named/config.h		\
	include/named/control.h		\
	include/named/fuzz.h		\
	include/named/geoip.h		\
	include/named/globals.h		\
	include/named/log.h		\
	include/named/logconf.h		\
	include/named/main.h		\
	include/named/server.h		\
	include/named/smf_globals.h	\
	include/named/statschannel.h	\
	include/named/tkeyconf.h	\
	include/named/tsigconf.h	\
	include/named/types.h		\
	include/named/zoneconf.h	\
	unix/include/named/os.h		\
	xsl_p.h

if HAVE_GEOIP2
AM_CPPFLAGS +=					\
	-DMAXMINDDB_PREFIX=\"@MAXMINDDB_PREFIX@\"
named_SOURCES +=	\
	geoip.c
endif

named_LDADD =					\
	$(LIBISC_LIBS)				\
	$(LIBDNS_LIBS)				\
	$(LIBNS_LIBS)				\
	$(LIBISCCC_LIBS)			\
	$(LIBISCCFG_LIBS)			\
	$(LIBBIND9_LIBS)			\
	$(OPENSSL_LIBS)				\
	$(LIBCAP_LIBS)				\
	$(LMDB_LIBS)				\
	$(MAXMINDDB_LIBS)			\
	$(DNSTAP_LIBS)				\
	$(LIBXML2_LIBS)				\
	$(ZLIB_LIBS)

if HAVE_JSON_C
named_LDADD +=					\
	$(JSON_C_LIBS)
endif HAVE_JSON_C

MAINTAINERCLEANFILES =				\
	named.conf.rst
