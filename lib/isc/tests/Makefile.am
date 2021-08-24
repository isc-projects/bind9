include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)

LDADD +=			\
	libisctest.la		\
	$(LIBISC_LIBS)

check_LTLIBRARIES = libisctest.la
libisctest_la_SOURCES =		\
	../socket_p.h		\
	isctest.c		\
	isctest.h		\
	uv_wrap.h

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
	netmgr_test	\
	parse_test	\
	pool_test	\
	quota_test	\
	radix_test	\
	random_test	\
	regex_test	\
	result_test	\
	safe_test	\
	siphash_test	\
	sockaddr_test	\
	socket_test	\
	stats_test	\
	symtab_test	\
	task_test	\
	taskpool_test	\
	time_test	\
	timer_test

if HAVE_LIBNGHTTP2
check_PROGRAMS +=	\
	doh_test

doh_test_CPPFLAGS =	\
	$(AM_CPPFLAGS)	\
	$(LIBUV_CFLAGS)	\
	$(LIBNGHTTP2_CFLAGS)	\
	$(OPENSSL_CFLAGS)

doh_test_LDADD =	\
	$(LDADD)	\
	$(LIBNGHTTP2_LIBS)	\
	$(LIBUV_LIBS)
endif HAVE_LIBNGHTTP2

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

netmgr_test_CPPFLAGS =	\
	$(AM_CPPFLAGS)	\
	$(LIBUV_CFLAGS)	\
	$(OPENSSL_CFLAGS)

netmgr_test_LDADD =	\
	$(LDADD)	\
	$(LIBUV_LIBS)

EXTRA_DIST = testdata

include $(top_srcdir)/Makefile.tests
