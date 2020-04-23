include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.tests

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)

LDADD +=			\
	libisctest.la		\
	$(LIBISC_LIBS)

noinst_LTLIBRARIES = libisctest.la
libisctest_la_SOURCES = isctest.c isctest.h

check_PROGRAMS =	\
	aes_test	\
	buffer_test	\
	counter_test	\
	crc64_test	\
	errno_test	\
	file_test	\
	hash_test	\
	heap_test	\
	hmac_test	\
	ht_test		\
	lex_test	\
	md_test		\
	mem_test	\
	netaddr_test	\
	parse_test	\
	pool_test	\
	quota_test	\
	radix_test	\
	random_test	\
	regex_test	\
	result_test	\
	safe_test	\
	sockaddr_test	\
	socket_test	\
	symtab_test	\
	task_test	\
	taskpool_test	\
	time_test	\
	timer_test

TESTS = $(check_PROGRAMS)

hmac_test_CPPFLAGS =	\
	$(AM_CPPFLAGS)	\
	$(OPENSSL_CFLAGS)

hmac_test_LDADD =	\
	$(LDADD)	\
	$(OPENSSL_LIBS)

md_test_CPPFLAGS =	\
	$(AM_CPPFLAGS)	\
	$(OPENSSL_CFLAGS)

md_test_LDADD =		\
	$(LDADD)	\
	$(OPENSSL_LIBS)

random_test_LDADD =	\
	$(LDADD)	\
	-lm

unit-local: check
