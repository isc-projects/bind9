include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.tests

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBIRS_CFLAGS)

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBIRS_LIBS)

check_PROGRAMS = \
	resconf_test

TESTS = $(check_PROGRAMS)

unit-local: check

LOG_COMPILER = $(builddir)/../../unit-test-driver.sh
