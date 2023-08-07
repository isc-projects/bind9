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

TESTS =

if HAVE_PERLMOD_TIME_HIRES
TESTS += serve-stale
endif HAVE_PERLMOD_TIME_HIRES

if HAVE_PERLMOD_NET_DNS
TESTS +=		\
	rpzrecurse
endif HAVE_PERLMOD_NET_DNS

if HAVE_LIBNGHTTP2
TESTS +=		\
	doth
endif

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
	dialup			\
	dlzexternal		\
	dns64			\
	dsdigest		\
	dyndb			\
	ecdsa			\
	eddsa			\
	ednscompliance		\
	emptyzones		\
	enginepkcs11		\
	filter-aaaa		\
	formerr			\
	geoip2			\
	glue			\
	idna			\
	include-multiplecfg	\
	inline			\
	integrity		\
	hooks			\
	host			\
	journal			\
	keepalive		\
	keyfromlabel		\
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
	tools			\
	transport-acl		\
	tsig			\
	tsiggss			\
	ttl			\
	unknown			\
	verify			\
	views			\
	wildcard		\
	xferquota		\
	zonechecks

if HAVE_LMDB
TESTS += nzd2nzf
endif # HAVE_LMDB

if HAVE_PERLMOD_NET_DNS

TESTS +=		\
	fetchlimit	\
	ixfr		\
	nsupdate	\
	resolver	\
	statistics	\
	stress		\
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
TESTS += kasp multisigner tcp pipelined

if HAVE_PYTEST
TESTS += checkds dispatch rpzextra shutdown timeouts
endif

if HAVE_PYMOD_DNS
TESTS += qmin cookie
if HAVE_PERLMOD_NET_DNS
TESTS += digdelv dnssec forward
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

LOG_DRIVER_V = $(LOG_DRIVER_V_@AM_V@)
LOG_DRIVER_V_ = $(LOG_DRIVER_V_@AM_DEFAULT_V@)
LOG_DRIVER_V_0 = --verbose no
LOG_DRIVER_V_1 = --verbose yes

LOG_DRIVER = $(srcdir)/custom-test-driver
AM_LOG_DRIVER_FLAGS = $(LOG_DRIVER_V)

LOG_COMPILER = $(builddir)/legacy.run.sh
AM_LOG_FLAGS = -r

$(TESTS): legacy.run.sh

test-local: check

clean-local::
	-find $(builddir) -maxdepth 1 -type d -name "*_*" | xargs rm -rf
