include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBISCCFG_CFLAGS)

LDADD +=			\
	libisccfgtest.la		\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LIBISCCFG_LIBS)

check_LTLIBRARIES = libisccfgtest.la
libisccfgtest_la_SOURCES =			\
	../../isc/test.c		\
	../../isc/include/isc/test.h

check_PROGRAMS =		\
	duration_test		\
	parser_test

include $(top_srcdir)/Makefile.tests
