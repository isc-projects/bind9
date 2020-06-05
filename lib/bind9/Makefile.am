include $(top_srcdir)/Makefile.top

lib_LTLIBRARIES = libbind9.la

libbind9_ladir = $(includedir)/bind9
libbind9_la_HEADERS =			\
	include/bind9/check.h		\
	include/bind9/getaddresses.h

libbind9_la_SOURCES =		\
	$(libbind9_la_HEADERS)	\
	check.c			\
	getaddresses.c

libbind9_la_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBISCCFG_CFLAGS)	\
	$(LIBNS_CFLAGS)		\
	$(LIBBIND9_CFLAGS)

libbind9_la_LIBADD =		\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LIBNS_LIBS)		\
	$(LIBISCCFG_LIBS)

libbind9_la_LDFLAGS =		\
	$(libbind9_VERSION_INFO)

EXTRA_DIST = api
