include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBISCCC_CFLAGS)

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBISCCC_LIBS)

check_PROGRAMS =		\
	result_test

include $(top_srcdir)/Makefile.tests
