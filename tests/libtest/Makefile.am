include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBNS_CFLAGS)		\
	$(LIBUV_CFLAGS)		\
	-I$(top_srcdir)/lib/isc

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LIBNS_LIBS)

check_LTLIBRARIES = libtest.la

noinst_libtest_ladir = ..
noinst_libtest_la_HEADERS =		\
	../include/tests/dns.h		\
	../include/tests/isc.h		\
	../include/tests/ns.h
libtest_la_SOURCES =			\
	$(noinst_libtest_la_HEADERS)	\
	dns.c				\
	isc.c				\
	ns.c

include $(top_srcdir)/Makefile.tests
