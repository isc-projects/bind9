include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=				\
	$(LIBISC_CFLAGS)		\
	$(LIBDNS_CFLAGS)		\
	-DFUZZDIR=\"$(abs_srcdir)\"

AM_LDFLAGS =				\
	$(FUZZ_LDFLAGS)

LDADD =					\
	libfuzzmain.la			\
	$(LIBISC_LIBS)			\
	$(LIBDNS_LIBS)

check_LTLIBRARIES = libfuzzmain.la
libfuzzmain_la_SOURCES =		\
	main.c

check_PROGRAMS =			\
	dns_name_fromtext_target	\
	dns_rdata_fromwire_text		\
	isc_lex_getmastertoken		\
	isc_lex_gettoken

EXTRA_DIST =				\
	dns_name_fromtext_target.in	\
	dns_rdata_fromwire_text.in	\
	isc_lex_getmastertoken.in	\
	isc_lex_gettoken.in

TESTS = $(check_PROGRAMS)

if HAVE_FUZZ_LOG_COMPILER
LOG_COMPILER = $(srcdir)/$(FUZZ_LOG_COMPILER)
AM_LOG_FLAGS = $(srcdir)
endif HAVE_FUZZ_LOG_COMPILER

unit-local: check
