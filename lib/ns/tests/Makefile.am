include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBNS_CFLAGS)

LDADD +=			\
	libnstest.la		\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LIBNS_LIBS)

check_LTLIBRARIES = libnstest.la
libnstest_la_SOURCES =			\
	../../isc/test.c		\
	../../isc/include/isc/test.h	\
	../../dns/test.c		\
	../../dns/include/dns/test.h	\
	../../ns/test.c			\
	../../ns/include/ns/test.h

check_PROGRAMS =		\
	listenlist_test		\
	notify_test		\
	plugin_test		\
	query_test

EXTRA_DIST = testdata

include $(top_srcdir)/Makefile.tests
