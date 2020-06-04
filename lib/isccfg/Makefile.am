include $(top_srcdir)/Makefile.top

lib_LTLIBRARIES = libisccfg.la

libisccfg_ladir = $(includedir)/isccfg
libisccfg_la_HEADERS =			\
	include/isccfg/aclconf.h	\
	include/isccfg/cfg.h		\
	include/isccfg/dnsconf.h	\
	include/isccfg/grammar.h	\
	include/isccfg/kaspconf.h	\
	include/isccfg/log.h		\
	include/isccfg/namedconf.h

libisccfg_la_SOURCES =			\
	$(libisccfg_la_HEADERS)		\
	aclconf.c			\
	dnsconf.c			\
	kaspconf.c			\
	log.c				\
	namedconf.c			\
	parser.c

libisccfg_la_CPPFLAGS =			\
	$(AM_CPPFLAGS)			\
	$(LIBISCCFG_CFLAGS)		\
	$(LIBISC_CFLAGS)		\
	$(LIBDNS_CFLAGS)

libisccfg_la_LIBADD =	\
	$(LIBISC_LIBS)	\
	$(LIBDNS_LIBS)

libisccfg_la_LDFLAGS =		\
	$(libisccfg_VERSION_INFO)

if HAVE_CMOCKA
SUBDIRS = tests
endif

EXTRA_DIST = api
