/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*! \file */

#include <bind.keys.h>

#include <dns/kasp.h>

#define DEFAULT_IANA_ROOT_ZONE_PRIMARIES "_default_iana_root_zone_primaries"

/*% default configuration */
constexpr char common_named_defaultconf[] = "\
options {\n\
	answer-cookie true;\n\
	automatic-interface-scan yes;\n\
#	blackhole {none;};\n\
	cookie-algorithm siphash24;\n\
#	directory <none>\n\
	dnssec-policy \"none\";\n\
	dump-file \"named_dump.db\";\n\
	edns-udp-size 1232;\n"
#if defined(HAVE_GEOIP2)
					    "\
	geoip-directory \"" MAXMINDDB_PREFIX "/share/GeoIP\";\n"
#elif defined(HAVE_GEOIP2)
					    "\
	geoip-directory \".\";\n"
#endif /* if defined(HAVE_GEOIP2) */
					    "\
	interface-interval 60m;\n\
	listen-on {any;};\n\
	listen-on-v6 {any;};\n\
	match-mapped-addresses no;\n\
	max-ixfr-ratio 100%;\n\
	max-rsa-exponent-size 0; /* no limit */\n\
	max-udp-size 1232;\n\
	memstatistics-file \"named.memstats\";\n\
	nocookie-udp-size 4096;\n\
	notify-rate 20;\n\
	nta-lifetime 3600;\n\
	nta-recheck 300;\n\
#	pid-file \"" NAMED_LOCALSTATEDIR "/run/named/named.pid\"; \n\
	port 53;\n"
#if HAVE_SO_REUSEPORT_LB
					    "\
	reuseport yes;\n"
#else
					    "\
	reuseport no;\n"
#endif
					    "\
	tls-port 853;\n"
#if HAVE_LIBNGHTTP2
					    "\
	http-port 80;\n\
	https-port 443;\n\
	http-listener-clients 300;\n\
	http-streams-per-connection 100;\n"
#endif
					    "\
	prefetch 2 9;\n\
#	querylog <boolean>;\n\
	recursing-file \"named.recursing\";\n\
	recursive-clients 1000;\n\
	request-nsid false;\n\
	request-zoneversion false;\n\
	resolver-query-timeout 10;\n\
#	responselog <boolean>;\n\
#	rrset-order { order cyclic; };\n\
	secroots-file \"named.secroots\";\n\
	send-cookie true;\n\
	serial-query-rate 20;\n\
	server-id none;\n\
	session-keyalg hmac-sha256;\n\
#	session-keyfile \"" NAMED_LOCALSTATEDIR "/run/named/session.key\";\n\
	session-keyname local-ddns;\n\
	startup-notify-rate 20;\n\
	sig0checks-quota 1;\n\
	sig0key-checks-limit 16;\n\
	sig0message-checks-limit 2;\n\
	statistics-file \"named.stats\";\n\
	tcp-advertised-timeout 300;\n\
	tcp-clients 150;\n\
	tcp-idle-timeout 300;\n\
	tcp-initial-timeout 300;\n\
	tcp-keepalive-timeout 300;\n\
	tcp-listen-queue 10;\n\
	tcp-primaries-timeout 150;\n\
	tcp-receive-buffer 0;\n\
	tcp-reuse-timeout 50;\n\
	tcp-send-buffer 0;\n\
	transfer-message-size 20480;\n\
	transfers-in 10;\n\
	transfers-out 10;\n\
	transfers-per-ns 2;\n\
	trust-anchor-telemetry yes;\n\
	udp-receive-buffer 0;\n\
	udp-send-buffer 0;\n\
	update-quota 100;\n\
\n\
	/* view */\n\
	allow-new-zones no;\n\
	allow-notify {none;};\n\
	allow-proxy {none;};\n\
	allow-proxy-on {any;};\n\
	allow-query-cache { localnets; localhost; };\n\
	allow-query-cache-on { any; };\n\
	allow-recursion { localnets; localhost; };\n\
	allow-recursion-on { any; };\n\
	allow-update-forwarding {none;};\n\
	auth-nxdomain false;\n\
	check-dup-records warn;\n\
	check-mx warn;\n\
	check-names primary fail;\n\
	check-names response ignore;\n\
	check-names secondary warn;\n\
	check-spf warn;\n\
	check-svcb yes;\n\
	clients-per-query 10;\n\
	dnssec-accept-expired no;\n\
	dnssec-validation " VALIDATION_DEFAULT "; \n"
#ifdef HAVE_DNSTAP
					    "	dnstap-identity hostname;\n"
#endif /* ifdef HAVE_DNSTAP */
					    "\
	fetch-quota-params 100 0.1 0.3 0.7;\n\
	fetches-per-server 0;\n\
	fetches-per-zone 0;\n\
	lame-ttl 0;\n\
	lmdb-mapsize 32M;\n\
	max-cache-size default;\n\
	max-cache-ttl 604800; /* 1 week */\n\
	max-delegation-ttl 0; /* disabled */\n\
	max-clients-per-query 100;\n\
	max-delegation-servers 13;\n\
	max-ncache-ttl 10800; /* 3 hours */\n\
	max-recursion-depth 7;\n\
	max-recursion-queries 50;\n\
	max-query-count 200;\n\
	max-query-restarts 11;\n\
	max-stale-ttl 86400; /* 1 day */\n\
	message-compression yes;\n\
	min-ncache-ttl 0; /* 0 hours */\n\
	min-cache-ttl 0; /* 0 seconds */\n\
	min-delegation-ttl 60; /* 1 minute */\n\
	minimal-any yes;\n\
	minimal-responses no-auth-recursive;\n\
	notify-source *;\n\
	notify-source-v6 *;\n\
	nsec3-test-zone no;\n\
	parental-source *;\n\
	parental-source-v6 *;\n\
	provide-ixfr true;\n\
	response-padding { none; } block-size 0;\n\
	qname-minimization relaxed;\n\
	query-source address *;\n\
	query-source-v6 address *;\n\
	recursion true;\n\
	request-expire true;\n\
	request-ixfr true;\n\
	request-ixfr-max-diffs 0;\n\
	require-server-cookie no;\n\
	root-key-sentinel yes;\n\
	servfail-ttl 1;\n\
	stale-answer-client-timeout off;\n\
	stale-answer-enable false;\n\
	stale-answer-ttl 30; /* 30 seconds */\n\
	stale-cache-enable false;\n\
	stale-refresh-time 30; /* 30 seconds */\n\
	synth-from-dnssec yes;\n\
#	topology <none>\n\
	transfer-format many-answers;\n\
	resolver-use-dns64 false;\n\
	v6-bias 50;\n\
	zero-no-soa-ttl-cache no;\n\
\n\
	/* zone */\n\
	allow-query {any;};\n\
	allow-query-on {any;};\n\
	allow-transfer {none;};\n\
#	also-notify <none>\n\
	check-integrity yes;\n\
	check-mx-cname warn;\n\
	check-sibling yes;\n\
	check-srv-cname warn;\n\
	check-wildcard yes;\n\
	dnssec-loadkeys-interval 60;\n\
#	forward <none>\n\
#	forwarders <none>\n\
#	inline-signing no;\n\
	ixfr-from-differences false;\n\
	max-journal-size default;\n\
	max-records 0;\n\
	max-records-per-type 100;\n\
	max-refresh-time 2419200; /* 4 weeks */\n\
	max-retry-time 1209600; /* 2 weeks */\n\
	max-types-per-name 100;\n\
	max-transfer-idle-in 60;\n\
	max-transfer-idle-out 60;\n\
	max-transfer-time-in 120;\n\
	max-transfer-time-out 120;\n\
	min-refresh-time 300;\n\
	min-retry-time 500;\n\
	min-transfer-rate-in 10240 5;\n\
	multi-master no;\n\
	notify yes;\n\
	notify-defer 0;\n\
	notify-delay 5;\n\
	notify-to-soa no;\n\
	provide-zoneversion yes;\n\
	send-report-channel .;\n\
	serial-update-method increment;\n\
	sig-signing-nodes 100;\n\
	sig-signing-signatures 10;\n\
	sig-signing-type 65534;\n\
	transfer-source *;\n\
	transfer-source-v6 *;\n\
	try-tcp-refresh yes; /* BIND 8 compat */\n\
	zero-no-soa-ttl yes;\n\
	zone-statistics terse;\n\
};\n\
"

					    "#\n\
#  Zones in the \"_bind\" view are NOT counted in the count of zones.\n\
#\n\
view \"_bind\" chaos {\n\
	recursion no;\n\
	notify no;\n\
	allow-new-zones no;\n\
	max-cache-size 2M;\n\
	provide-zoneversion no;\n\
\n\
	# Prevent use of this zone in DNS amplified reflection DoS attacks\n\
	rate-limit {\n\
		responses-per-second 3;\n\
		slip 0;\n\
		min-table-size 10;\n\
	};\n\
\n\
	zone \"version.bind\" chaos {\n\
		type primary;\n\
		database \"_builtin version\";\n\
	};\n\
\n\
	zone \"hostname.bind\" chaos {\n\
		type primary;\n\
		database \"_builtin hostname\";\n\
	};\n\
\n\
	zone \"authors.bind\" chaos {\n\
		type primary;\n\
		database \"_builtin authors\";\n\
	};\n\
\n\
	zone \"id.server\" chaos {\n\
		type primary;\n\
		database \"_builtin id\";\n\
	};\n\
};\n\
"
					    "#\n\
#  Built-in DNSSEC key and signing policies.\n\
#\n\
dnssec-policy \"default\" {\n\
	keys {\n\
		csk key-directory lifetime unlimited algorithm 13;\n\
	};\n\
\n\
	cdnskey yes;\n\
	cds-digest-types { 2; };\n\
	dnskey-ttl " DNS_KASP_KEY_TTL ";\n\
	inline-signing yes;\n\
	manual-mode no;\n\
	offline-ksk no;\n\
	publish-safety " DNS_KASP_PUBLISH_SAFETY "; \n\
	retire-safety " DNS_KASP_RETIRE_SAFETY "; \n\
	purge-keys " DNS_KASP_PURGE_KEYS "; \n\
	signatures-jitter " DNS_KASP_SIG_JITTER "; \n\
	signatures-refresh " DNS_KASP_SIG_REFRESH "; \n\
	signatures-validity " DNS_KASP_SIG_VALIDITY "; \n\
	signatures-validity-dnskey " DNS_KASP_SIG_VALIDITY_DNSKEY "; \n\
	max-zone-ttl " DNS_KASP_ZONE_MAXTTL "; \n\
	zone-propagation-delay " DNS_KASP_ZONE_PROPDELAY "; \n\
	parent-ds-ttl " DNS_KASP_DS_TTL "; \n\
	parent-propagation-delay " DNS_KASP_PARENT_PROPDELAY "; \n\
};\n\
\n\
dnssec-policy \"insecure\" {\n\
	max-zone-ttl 0; \n\
	keys { };\n\
	inline-signing yes;\n\
	manual-mode no;\n\
};\n\
\n\
"
					    "#\n\
#  Default trusted key(s), used if \n\
# \"dnssec-validation auto;\" is set and\n\
#  " NAMED_SYSCONFDIR "/bind.keys doesn't exist).\n\
#\n\
# BEGIN TRUST ANCHORS\n"

	/* Imported from bind.keys.h: */
	TRUST_ANCHORS

					    "# END TRUST ANCHORS\n\
\n\
remote-servers " DEFAULT_IANA_ROOT_ZONE_PRIMARIES " {\n\
	2801:1b8:10::b;		# b.root-servers.net\n\
	2001:500:2::c;		# c.root-servers.net\n\
	2001:500:2f::f;		# f.root-servers.net\n\
	2001:500:12::d0d;	# g.root-servers.net\n\
	2001:7fd::1;		# k.root-servers.net\n\
	2620:0:2830:202::132;	# xfr.cjr.dns.icann.org\n\
	2620:0:2d0:202::132;	# xfr.lax.dns.icann.org\n\
	170.247.170.2;		# b.root-servers.net\n\
	192.33.4.12;		# c.root-servers.net\n\
	192.5.5.241;		# f.root-servers.net\n\
	192.112.36.4;		# g.root-servers.net\n\
	193.0.14.129;		# k.root-servers.net\n\
	192.0.47.132;		# xfr.cjr.dns.icann.org\n\
	192.0.32.132;		# xfr.lax.dns.icann.org\n\
};\n\
";
