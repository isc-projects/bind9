include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBNS_CFLAGS)		\
	-I$(top_srcdir)/lib/isc	\
	-I$(top_srcdir)/lib/dns

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LIBNS_LIBS)

check_PROGRAMS =		\
	listenlist_test		\
	notify_test		\
	plugin_test		\
	query_test

EXTRA_DIST = testdata

include $(top_srcdir)/Makefile.tests
