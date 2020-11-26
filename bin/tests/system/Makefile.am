include $(top_srcdir)/Makefile.top

EXTRA_DIST = .

# Source tarballs must not contain configure/build artifacts.
dist-hook:
	git clean -n -x -d | \
	        grep -v "Makefile.in$$" | \
	        sed -n "s|^Would remove \(.*\)|$(distdir)/\1|p" | \
	        xargs -I{} rm -rf "{}"

SUBDIRS = dyndb/driver dlzexternal/driver hooks/driver

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

TESTS =

if HAVE_PERLMOD_TIME_HIRES
TESTS += serve-stale
endif HAVE_PERLMOD_TIME_HIRES

if HAVE_PERLMOD_NET_DNS
TESTS +=		\
	rpzrecurse
endif HAVE_PERLMOD_NET_DNS

TESTS +=			\
	acl			\
	additional		\
	addzone			\
	allow-query		\
	auth			\
	autosign		\
	builtin			\
	cacheclean		\
	case			\
	catz			\
	cds			\
	checkconf		\
	checknames		\
	checkzone		\
	database		\
	dlz			\
	dlzexternal		\
	dns64			\
	dscp			\
	dsdigest		\
	dyndb			\
	ecdsa			\
	ednscompliance		\
	emptyzones		\
	filter-aaaa		\
	formerr			\
	geoip2			\
	glue			\
	idna			\
	include-multiplecfg	\
	inline			\
	integrity		\
	hooks			\
	keepalive		\
	legacy			\
	limits			\
	logfileconfig		\
	masterfile		\
	masterformat		\
	metadata		\
	mirror			\
	mkeys			\
	names			\
	notify			\
	nsec3			\
	nslookup		\
	padding			\
	pending			\
	redirect		\
	rndc			\
	rootkeysentinel		\
	rpz			\
	rrchecker		\
	rrl			\
	rrsetorder		\
	rsabigexponent		\
	runtime			\
	sfcache			\
	smartsign		\
	sortlist		\
	spf			\
	staticstub		\
	stub			\
	synthfromdnssec		\
	tkey			\
	tools			\
	tsig			\
	tsiggss			\
	ttl			\
	unknown			\
	verify			\
	views			\
	wildcard		\
	xferquota		\
	zonechecks

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
	digdelv		\
	fetchlimit	\
	forward		\
	ixfr		\
	nsupdate	\
	resolver	\
	statistics	\
	dot		\
	upforwd		\
	zero

if HAVE_DNSTAP
TESTS += dnstap
endif

if HAVE_PERLMOD_FILE_FETCH
TESTS += statschannel
endif HAVE_PERLMOD_FILE_FETCH

if HAVE_PERLMOD_DIGEST_HMAC
TESTS += xfer
endif HAVE_PERLMOD_DIGEST_HMAC

if HAVE_PERLMOD_NET_DNS_NAMESERVER
TESTS += reclimit
endif HAVE_PERLMOD_NET_DNS_NAMESERVER

endif HAVE_PERLMOD_NET_DNS

if HAVE_PYTHON
TESTS += kasp tcp pipelined

if HAVE_PYMOD_DNS
TESTS += qmin cookie

if HAVE_PERLMOD_NET_DNS
TESTS += dnssec
if HAVE_PERLMOD_NET_DNS_NAMESERVER
TESTS += chain
endif HAVE_PERLMOD_NET_DNS_NAMESERVER
endif HAVE_PERLMOD_NET_DNS

if HAVE_PYTEST
TESTS += rpzextra shutdown
endif

endif HAVE_PYMOD_DNS

endif HAVE_PYTHON

if HAVE_PKCS11
TESTS += pkcs11
endif

else !HAVE_PERL
check:
	echo Perl is not available, no tests were ran
	exit 1
endif !HAVE_PERL

LOG_DRIVER_V = $(LOG_DRIVER_V_@AM_V@)
LOG_DRIVER_V_ = $(LOG_DRIVER_V_@AM_DEFAULT_V@)
LOG_DRIVER_V_0 = --verbose no
LOG_DRIVER_V_1 = --verbose yes

LOG_DRIVER = $(srcdir)/custom-test-driver
AM_LOG_DRIVER_FLAGS = $(LOG_DRIVER_V)

LOG_COMPILER = $(builddir)/run.sh
AM_LOG_FLAGS = -r

$(TESTS): run.sh

clean-local:
	-rm -f get_ports.state get_ports.lock

test-local: check
