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
libnstest_la_SOURCES = nstest.c nstest.h
check_PROGRAMS =		\
	listenlist_test		\
	plugin_test

TESTS = $(check_PROGRAMS)

if HAVE_LD_WRAP

check_PROGRAMS +=	\
	notify_test	\
	query_test

notify_test_SOURCES =	\
	notify_test.c	\
	wrap.c

notify_test_LDFLAGS =			\
	$(LDFLAGS)			\
	-Wl,--wrap=isc_nmhandle_unref

query_test_SOURCES =	\
	query_test.c	\
	wrap.c

query_test_LDFLAGS =			\
	$(LDFLAGS)			\
	-Wl,--wrap=isc_nmhandle_unref

endif

unit-local: check

LOG_COMPILER = $(builddir)/../../unit-test-driver.sh
