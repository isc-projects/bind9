include $(top_srcdir)/Makefile.top

lib_LTLIBRARIES = libirs.la

libirs_ladir = $(includedir)/irs
libirs_la_HEADERS =		\
	include/irs/context.h	\
	include/irs/dnsconf.h	\
	include/irs/netdb.h	\
	include/irs/resconf.h	\
	include/irs/types.h

libirs_la_SOURCES =		\
	$(libirs_la_HEADERS)	\
	context.c		\
	dnsconf.c		\
	gai_strerror.c		\
	getaddrinfo.c		\
	getnameinfo.c		\
	resconf.c

libirs_la_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBISCCFG_CFLAGS)	\
	$(LIBIRS_CFLAGS)

libirs_la_LIBADD =		\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LIBISCCFG_LIBS)

libirs_la_LDFLAGS =		\
	$(libirs_VERSION_INFO)


if HAVE_CMOCKA
SUBDIRS = tests
endif
