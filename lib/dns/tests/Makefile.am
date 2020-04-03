include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.tests

AM_CPPFLAGS +=				\
	$(LIBISC_CFLAGS)		\
	$(LIBDNS_CFLAGS)		\
	$(KRB5_CFLAGS)			\
	-DSRCDIR=\"$(abs_srcdir)\"	\
	-DBUILDDIR=\"$(abs_builddir)\"

LDADD +=			\
	libdnstest.la		\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)

check_LTLIBRARIES = libdnstest.la
libdnstest_la_SOURCES = dnstest.c dnstest.h

check_PROGRAMS =		\
	acl_test		\
	db_test			\
	dbdiff_test		\
	dbiterator_test		\
	dbversion_test		\
	dh_test			\
	dispatch_test		\
	dst_test		\
	geoip_test		\
	keytable_test		\
	name_test		\
	nsec3_test		\
	peer_test		\
	private_test		\
	rbt_serialize_test	\
	rbt_test		\
	rdata_test		\
	rdataset_test		\
	rdatasetstats_test	\
	resolver_test		\
	result_test		\
	rsa_test		\
	sigs_test		\
	time_test		\
	tsig_test		\
	update_test		\
	zonemgr_test		\
	zt_test

TESTS = $(check_PROGRAMS)

if HAVE_PERL

check_PROGRAMS +=		\
	master_test

EXTRA_master_test_DEPENDENCIES = testdata/master/master12.data testdata/master/master13.data testdata/master/master14.data
CLEANFILES = $(EXTRA_master_test_DEPENDENCIES)

testdata/master/master12.data: testdata/master/master12.data.in
	mkdir -p testdata/master
	$(PERL) -w $(srcdir)/mkraw.pl < testdata/master/master12.data.in > $@

testdata/master/master13.data: testdata/master/master13.data.in
	mkdir -p testdata/master
	$(PERL) -w $(srcdir)/mkraw.pl < testdata/master/master13.data.in > $@

testdata/master/master14.data: testdata/master/master14.data.in
	mkdir -p testdata/master
	$(PERL) -w $(srcdir)/mkraw.pl < testdata/master/master14.data.in > $@

endif

if HAVE_GEOIP2
check_PROGRAMS +=		\
	geoip_test

geoip_test_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(MAXMINDDB_CFLAGS)

geoip_test_LDADD =		\
	$(LDADD)		\
	$(MAXMINDDB_LIBS)
endif

if HAVE_DNSTAP
check_PROGRAMS +=		\
	dnstap_test

dnstap_test_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(DNSTAP_CFLAGS)
dnstap_test_LDADD =		\
	$(LDADD)		\
	$(DNSTAP_LIBS)
endif

dh_test_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(OPENSSL_CFLAGS)

dst_test_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(OPENSSL_CFLAGS)

rsa_test_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(OPENSSL_CFLAGS)

unit-local: check

LOG_COMPILER = $(builddir)/../../unit-test-driver.sh
