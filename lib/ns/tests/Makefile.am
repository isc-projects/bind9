include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.tests

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
libnstest_la_SOURCES =		\
	nstest.c 		\
	nstest.h

check_PROGRAMS =		\
	listenlist_test		\
	notify_test		\
	plugin_test		\
	query_test

TESTS = $(check_PROGRAMS)

unit-local: check

EXTRA_DIST = testdata

LOG_COMPILER = $(builddir)/../../unit-test-driver.sh
