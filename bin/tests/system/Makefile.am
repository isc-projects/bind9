include $(top_srcdir)/Makefile.top

SUBDIRS = dyndb/driver dlzexternal/driver

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)

LDADD =				\
	$(LIBISC_LIBS)

if HAVE_PERL

check_PROGRAMS =		\
	feature-test		\
	makejournal		\
	pipelined/pipequeries	\
	rndc/gencheck		\
	rpz/dnsrps		\
	tkey/keycreate		\
	tkey/keydelete

feature_test_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LIBDNS_CFLAGS)

makejournal_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LIBDNS_CFLAGS)

makejournal_LDADD =		\
	$(LDADD)		\
	$(LIBDNS_LIBS)

pipelined_pipequeries_CPPFLAGS =	\
	$(AM_CPPFLAGS)			\
	$(LIBDNS_CFLAGS)

pipelined_pipequeries_LDADD =	\
	$(LDADD)		\
	$(LIBDNS_LIBS)

tkey_keycreate_CPPFLAGS =	\
	$(AM_CPPFLAGS)		\
	$(LIBDNS_CFLAGS)

tkey_keycreate_LDADD =		\
	$(LDADD)		\
	$(LIBDNS_LIBS)

tkey_keydelete_CPPFLAGS =	\
	$(AM_CPPFLAGS)		\
	$(LIBDNS_CFLAGS)

tkey_keydelete_LDADD =		\
	$(LDADD)		\
	$(LIBDNS_LIBS)

if HAVE_DNSTAP
check_PROGRAMS += wire_test

wire_test_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LIBDNS_CFLAGS)

wire_test_LDADD =		\
	$(LDADD)		\
	$(LIBDNS_LIBS)
endif HAVE_DNSTAP

TESTS = \
	acl additional addzone allow-query auth autosign \
	builtin cacheclean case catz cds \
	checkconf checknames checkzone \
	cookie database dlz dlzexternal \
	dns64 dscp dsdigest dyndb \
	ednscompliance emptyzones \
	filter-aaaa formerr \
	geoip2 glue idna inline integrity keepalive \
	legacy limits logfileconfig \
	masterfile masterformat metadata mirror mkeys \
	names notify nslookup \
	padding pending \
	redirect rndc rootkeysentinel rpz \
	rrchecker rrl rrsetorder rsabigexponent runtime \
	sfcache smartsign sortlist \
	spf staticstub stub synthfromdnssec \
	tools tsig tsiggss \
	unknown verify views wildcard \
	xferquota zonechecks \
	ecdsa tkey

# eddsa test is broken
# TESTS += eddsa

# The "stress" test is not run by default since it creates enough
# load on the machine to make it unusable to other users.
# The "dialup", "delzone", and "dupsigs" tests are also not run by
# default because they take a very long time to complete.
# TESTS += delzone dialup dupsigs stress

if HAVE_LMDB
TESTS += nzd2nzf
endif # HAVE_LMDB

if HAVE_PERLMOD_NET_DNS

TESTS +=		\
	zero		\
	digdelv		\
	dnssec		\
	fetchlimit	\
	forward		\
	ixfr		\
	nsupdate	\
	resolver	\
	rpzrecurse	\
	statistics	\
	upforwd

if HAVE_DNSTAP
TESTS += dnstap
endif

if HAVE_PERLMOD_FILE_FETCH
TESTS += statschannel
endif HAVE_PERLMOD_FILE_FETCH

if HAVE_PERLMOD_DIGEST_HMAC
TESTS += xfer
endif HAVE_PERLMOD_DIGEST_HMAC

if HAVE_PERLMOD_TIME_HIRES
TESTS += serve-stale
endif HAVE_PERLMOD_TIME_HIRES

if HAVE_PERLMOD_NET_DNS_NAMESERVER
TESTS += reclimit
endif HAVE_PERLMOD_NET_DNS_NAMESERVER

endif HAVE_PERLMOD_NET_DNS

if HAVE_PYTHON
TESTS += tcp pipelined

if HAVE_PYMOD_DNS
TESTS += qmin

if HAVE_PERLMOD_NET_DNS
if HAVE_PERLMOD_NET_DNS_NAMESERVER
TESTS += chain
endif HAVE_PERLMOD_NET_DNS_NAMESERVER
endif HAVE_PERLMOD_NET_DNS

endif HAVE_PYMOD_DNS

endif HAVE_PYTHON

else !HAVE_PERL
check:
	echo Perl is not available, no tests were ran
	exit 1
endif !HAVE_PERL

LOG_COMPILER = $(builddir)/system-test-driver.sh

clean-local:
	-rm -f get_base_port.state get_base_port.lock
