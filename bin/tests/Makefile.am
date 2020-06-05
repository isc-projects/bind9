include $(top_srcdir)/Makefile.top

SUBDIRS = system

noinst_PROGRAMS = wire_test

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)

LDADD =				\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)

EXTRA_DIST = prepare-softhsm2.sh
