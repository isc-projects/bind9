include $(top_srcdir)/Makefile.top

EXTRA_DIST = .

# Source tarballs must not contain configure/build artifacts.
dist-hook:
	git clean -n -x -d | \
	        grep -v "Makefile.in$$" | \
	        sed -n "s|^Would remove \(.*\)|$(distdir)/\1|p" | \
	        xargs -I{} rm -rf "{}"

SUBDIRS = dyndb/driver dlzexternal/driver hooks/driver

if DNSRPS
SUBDIRS += rpz/testlib
endif

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS) 	\
	$(LIBDNS_CFLAGS)

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)

if HAVE_PERL
if HAVE_PYTHON
if HAVE_PYTEST

noinst_PROGRAMS =		\
	feature-test		\
	makejournal		\
	pipelined/pipequeries	\
	rndc/gencheck		\
	rpz/dnsrps

feature_test_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LIBDNS_CFLAGS)	\
	$(OPENSSL_CFLAGS)

feature_test_LDADD =		\
	$(LDADD)		\
	$(LIBDNS_LIBS)		\
	$(OPENSSL_LIBS)

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

rpz_dnsrps_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LIBDNS_CFLAGS)	\
	-DLIBRPZ_LIB_OPEN=\"$(abs_builddir)/rpz/testlib/.libs/libdummyrpz.so\"

rpz_dnsrps_LDADD =		\
	$(LDADD)		\
	$(LIBDNS_LIBS)		\
	$(DLOPEN_LIBS)

# Longer running tests are listed (and executed) first to take the most
# advantage of parallel execution.
TESTS =				\
	rpz			\
	rpzrecurse		\
	serve_stale		\
	timeouts		\
	upforwd			\
	acl			\
	additional		\
	addzone			\
	allow_query		\
	allow_query_on		\
	auth			\
	autosign		\
	bailiwick		\
	builtin			\
	cacheclean		\
	camp			\
	cap_glues		\
	case			\
	catz			\
	cdnxdomain		\
	cds			\
	chain			\
	checkconf		\
	checkconf_keys		\
	checkds			\
	checknames		\
	checkzone		\
	cipher_suites		\
	class			\
	cname_dname_negcache	\
	cname_recursion		\
	cookie			\
	cpu			\
	database		\
	dialup			\
	digdelv			\
	dispatch		\
	dlzexternal		\
	dns64			\
	dns64_dname		\
	dnssec			\
	dnssec_bypass		\
	dnssec_cname_response	\
	dnssec_nsec3		\
	dnssec_parent_rrsig	\
	dnssec_py		\
	dnssec_wildcard		\
	dnstap			\
	doth			\
	dsdigest		\
	dyndb			\
	ecdsa			\
	eddsa			\
	ednscompliance		\
	emptyzones		\
	enginepkcs11		\
	expiredglue		\
	fetchlimit		\
	filters			\
	formerr			\
	forward			\
	fwdfirst		\
	geoip2			\
	glue			\
	hooks			\
	host			\
	idna			\
	include_multiplecfg	\
	inline			\
	integrity		\
	ixfr			\
	ixfr_nonminimal		\
	journal			\
	kasp			\
	keepalive		\
	keyfromlabel		\
	ksr			\
	legacy			\
	limits			\
	logfileconfig		\
	masterfile		\
	masterformat		\
	metadata		\
	migrate2kasp		\
	mirror			\
	mirror_root_zone	\
	mismatchtcp		\
	mkeys			\
	multisigner		\
	names			\
	notify			\
	nsec			\
	nsec3			\
	nsec3_impersonation	\
	nsec_grandparent	\
	nsec_ixfr		\
	nsec_piggyback		\
	nsec_synthesis		\
	nsec_wildcard_wrong_zone	\
	nslookup		\
	nsprocessinglimit	\
	nsupdate		\
	nta			\
	nzd2nzf			\
	optout			\
	outofzone_zonecut	\
	padding			\
	pending			\
	pipelined		\
	proxy			\
	qmin			\
	qpcache_rrsig_any	\
	query_source		\
	randomizens		\
	reclimit		\
	redirect		\
	resend_loop		\
	resolver		\
	rfc5011			\
	rndc			\
	rndc_confgen		\
	rollover		\
	rootkeysentinel		\
	rpzextra		\
	rrchecker		\
	rrl			\
	rrsetorder		\
	rsabigexponent		\
	runtime			\
	selfpointedglue		\
	selftest		\
	selftest_asyncdnsserver	\
	sfcache			\
	sfcache_cname		\
	shutdown		\
	sig0			\
	sig0_https		\
	smartsign		\
	sortlist		\
	spf			\
	srtt			\
	ssumaxtype		\
	ssutoctou		\
	staticstub		\
	statistics		\
	statschannel		\
	stress			\
	stub			\
	svcb_alias		\
	synthfromdnssec		\
	tcp			\
	tkey			\
	tkeyleak		\
	tools			\
	transport_acl		\
	transport_change	\
	tsig			\
	tsiggss			\
	ttl			\
	unknown			\
	verify			\
	views			\
	wildcard		\
	xfer			\
	xfer_servers_list	\
	xferquota		\
	zero			\
	zonechecks

else !HAVE_PYTEST
check:
	echo pytest is not available, no tests were ran
	exit 1
endif !HAVE_PYTEST
else !HAVE_PYTHON
check:
	echo Python is not available, no tests were ran
	exit 1
endif !HAVE_PYTHON
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

LOG_COMPILER = $(srcdir)/run.sh

test-local: check

clean-local::
	-find -L . -mindepth 1 -maxdepth 1 -type d -name "*-*" -exec rm -rf {} \;
