include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.tests

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBISCCC_CFLAGS)

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBISCCC_LIBS)

check_PROGRAMS =	\
	result_test

TESTS = $(check_PROGRAMS)

unit-local: check

LOG_COMPILER = $(builddir)/../../unit-test-driver.sh
