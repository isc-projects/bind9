#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck disable=SC1091
. ../conf.sh

common_dig_options="+noadd +nosea +nostat +noquest +nocmd"
msg_xfrs_not_allowed=";; zone transfers over the established TLS connection are not allowed"

dig_with_tls_opts() {
	# shellcheck disable=SC2086
	"$DIG" +tls $common_dig_options -p "${TLSPORT}" "$@"
}

dig_with_https_opts() {
	# shellcheck disable=SC2086
	"$DIG" +https $common_dig_options -p "${HTTPSPORT}" "$@"
}

dig_with_http_opts() {
	# shellcheck disable=SC2086
	"$DIG" +http-plain $common_dig_options -p "${HTTPPORT}" "$@"
}

wait_for_tls_xfer() (
	dig_with_tls_opts -b 10.53.0.3 @10.53.0.2 example. AXFR > "dig.out.ns2.test$n" || return 1
	grep "^;" "dig.out.ns2.test$n" > /dev/null && return 1
	return 0
)

status=0
n=0

n=$((n+1))
echo_i "testing XoT server functionality (using dig) ($n)"
ret=0
dig_with_tls_opts example. -b 10.53.0.3 @10.53.0.1 axfr > dig.out.ns1.test$n || ret=1
grep "^;" dig.out.ns1.test$n | cat_i
digcomp example.axfr.good dig.out.ns1.test$n || ret=1
if test $ret != 0 ; then echo_i "failed"; fi
status=$((status+ret))

n=$((n+1))
echo_i "testing incoming XoT functionality (from secondary) ($n)"
ret=0
if retry_quiet 10 wait_for_tls_xfer; then
	grep "^;" "dig.out.ns2.test$n" | cat_i
	digcomp example.axfr.good "dig.out.ns2.test$n" || ret=1
else
	echo_i "timed out waiting for zone transfer"
	ret=1
fi
if test $ret != 0 ; then echo_i "failed"; fi
status=$((status+ret))

n=$((n + 1))
echo_i "checking DoT query (ephemeral key) ($n)"
ret=0
dig_with_tls_opts @10.53.0.1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoT query via IPv6 (ephemeral key) ($n)"
ret=0
dig_with_tls_opts -6 @fd92:7065:b8e:ffff::1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoT query (static key) ($n)"
ret=0
dig_with_tls_opts @10.53.0.2 example SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoT query via IPv6 (static key) ($n)"
ret=0
dig_with_tls_opts -6 @fd92:7065:b8e:ffff::2 example SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoT XFR ($n)"
ret=0
dig_with_tls_opts +comm @10.53.0.1 . AXFR > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

# In this test we are trying to establish a DoT connection over the
# DoH port. That is intentional, as dig should fail right after
# handshake has happened and before sending any queries, as XFRs, per
# the RFC, could happen only over a connection where "dot" ALPN token
# was negotiated.  over DoH it cannot happen, as only "h2" token could
# be selected for a DoH connection.
n=$((n + 1))
echo_i "checking DoT XFR with wrong ALPN token (h2, failure expected) ($n)"
ret=0
# shellcheck disable=SC2086
"$DIG" +tls $common_dig_options -p "${HTTPSPORT}" +comm @10.53.0.1 . AXFR > dig.out.test$n
grep "$msg_xfrs_not_allowed" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query (POST) ($n)"
ret=0
dig_with_https_opts @10.53.0.1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query via IPv6 (POST) ($n)"
ret=0
dig_with_https_opts -6 @fd92:7065:b8e:ffff::1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query (POST, static key) ($n)"
ret=0
dig_with_https_opts @10.53.0.2 example SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query via IPv6 (POST, static key) ($n)"
ret=0
dig_with_https_opts -6 @fd92:7065:b8e:ffff::2 example SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query (POST, nonstandard endpoint) ($n)"
ret=0
dig_with_https_opts +https=/alter @10.53.0.1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query via IPv6 (POST, nonstandard endpoint) ($n)"
ret=0
dig_with_https_opts -6 +https=/alter @fd92:7065:b8e:ffff::1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query (POST, undefined endpoint, failure expected) ($n)"
ret=0
dig_with_https_opts +tries=1 +time=1 +https=/fake @10.53.0.1 . SOA > dig.out.test$n
grep "communications error" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query via IPv6 (POST, undefined endpoint, failure expected) ($n)"
ret=0
dig_with_https_opts -6 +tries=1 +time=1 +https=/fake @fd92:7065:b8e:ffff::1 . SOA > dig.out.test$n
grep "communications error" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH XFR (POST) (failure expected) ($n)"
ret=0
dig_with_https_opts +comm @10.53.0.1 . AXFR > dig.out.test$n
grep "; Transfer failed." dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query (GET) ($n)"
ret=0
dig_with_https_opts +https-get @10.53.0.1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query via IPv6 (GET) ($n)"
ret=0
dig_with_https_opts -6 +https-get @fd92:7065:b8e:ffff::1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query (GET, static key) ($n)"
ret=0
dig_with_https_opts +https-get @10.53.0.2 example SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query via IPv6 (GET, static key) ($n)"
ret=0
dig_with_https_opts -6 +https-get @fd92:7065:b8e:ffff::2 example SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query (GET, nonstandard endpoint) ($n)"
ret=0
dig_with_https_opts +https-get=/alter @10.53.0.1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query via IPv6 (GET, nonstandard endpoint) ($n)"
ret=0
dig_with_https_opts -6 +https-get=/alter @fd92:7065:b8e:ffff::1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query (GET, undefined endpoint, failure expected) ($n)"
ret=0
dig_with_https_opts +tries=1 +time=1 +https-get=/fake @10.53.0.1 . SOA > dig.out.test$n
grep "communications error" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query via IPv6 (GET, undefined endpoint, failure expected) ($n)"
ret=0
dig_with_https_opts -6 +tries=1 +time=1 +https-get=/fake @fd92:7065:b8e:ffff::1 . SOA > dig.out.test$n
grep "communications error" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH XFR (GET) (failure expected) ($n)"
ret=0
dig_with_https_opts +https-get +comm @10.53.0.1 . AXFR > dig.out.test$n
grep "; Transfer failed." dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking unencrypted DoH query (POST) ($n)"
ret=0
dig_with_http_opts @10.53.0.1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking unencrypted DoH query via IPv6 (POST) ($n)"
ret=0
dig_with_http_opts -6 @fd92:7065:b8e:ffff::1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking unencrypted DoH query (GET) ($n)"
ret=0
dig_with_http_opts +http-plain-get @10.53.0.1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking unencrypted DoH query via IPv6 (GET) ($n)"
ret=0
dig_with_http_opts -6 +http-plain-get @fd92:7065:b8e:ffff::1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking unencrypted DoH XFR (failure expected) ($n)"
ret=0
dig_with_http_opts +comm @10.53.0.1 . AXFR > dig.out.test$n
grep "; Transfer failed." dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query for a large answer (POST) ($n)"
ret=0
dig_with_https_opts @10.53.0.1 biganswer.example A > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "ANSWER: 2500" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query via IPv6 for a large answer (POST) ($n)"
ret=0
dig_with_https_opts -6 @fd92:7065:b8e:ffff::1 biganswer.example A > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "ANSWER: 2500" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query for a large answer (GET) ($n)"
ret=0
dig_with_https_opts +https-get @10.53.0.1 biganswer.example A > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "ANSWER: 2500" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH query via IPv6 for a large answer (GET) ($n)"
ret=0
dig_with_https_opts -6 +https-get @fd92:7065:b8e:ffff::1 biganswer.example A > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "ANSWER: 2500" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking unencrypted DoH query for a large answer (POST) ($n)"
ret=0
dig_with_http_opts @10.53.0.1 biganswer.example A > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "ANSWER: 2500" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking unencrypted DoH query via IPv6 for a large answer (POST) ($n)"
ret=0
dig_with_http_opts -6 @fd92:7065:b8e:ffff::1 biganswer.example A > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "ANSWER: 2500" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking unencrypted DoH query for a large answer (GET) ($n)"
ret=0
dig_with_http_opts +http-plain-get @10.53.0.1 biganswer.example A > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "ANSWER: 2500" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking unencrypted DoH query via IPv6 for a large answer (GET) ($n)"
ret=0
dig_with_http_opts -6 +http-plain-get @fd92:7065:b8e:ffff::1 biganswer.example A > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "ANSWER: 2500" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

test_opcodes() {
	EXPECT_STATUS="$1"
	shift
	for op in "$@";
	do
		n=$((n + 1))
		echo_i "checking unexpected opcode query over DoH for opcode $op ($n)"
		ret=0
		dig_with_https_opts +https @10.53.0.1 +opcode="$op" > dig.out.test$n
		grep "status: $EXPECT_STATUS" dig.out.test$n > /dev/null || ret=1
		if [ $ret != 0 ]; then echo_i "failed"; fi
		status=$((status + ret))

		n=$((n + 1))
		echo_i "checking unexpected opcode query over DoH via IPv6 for opcode $op ($n)"
		ret=0
		dig_with_https_opts -6 +https @fd92:7065:b8e:ffff::1 +opcode="$op" > dig.out.test$n
		grep "status: $EXPECT_STATUS" dig.out.test$n > /dev/null || ret=1
		if [ $ret != 0 ]; then echo_i "failed"; fi
		status=$((status + ret))

		n=$((n + 1))
		echo_i "checking unexpected opcode query over DoH without encryption for opcode $op ($n)"
		ret=0
		dig_with_http_opts +http-plain @10.53.0.1 +opcode="$op" > dig.out.test$n
		grep "status: $EXPECT_STATUS" dig.out.test$n > /dev/null || ret=1
		if [ $ret != 0 ]; then echo_i "failed"; fi
		status=$((status + ret))

		n=$((n + 1))
		echo_i "checking unexpected opcode query over DoH via IPv6 without encryption for opcode $op ($n)"
		ret=0
		dig_with_http_opts -6 +http-plain @fd92:7065:b8e:ffff::1 +opcode="$op" > dig.out.test$n
		grep "status: $EXPECT_STATUS" dig.out.test$n > /dev/null || ret=1
		if [ $ret != 0 ]; then echo_i "failed"; fi
		status=$((status + ret))

		n=$((n + 1))
		echo_i "checking unexpected opcode query over DoT for opcode $op ($n)"
		ret=0
		dig_with_tls_opts +tls @10.53.0.1 +opcode="$op" > dig.out.test$n
		grep "status: $EXPECT_STATUS" dig.out.test$n > /dev/null || ret=1
		if [ $ret != 0 ]; then echo_i "failed"; fi
		status=$((status + ret))

		n=$((n + 1))
		echo_i "checking unexpected opcode query over DoT via IPv6 for opcode $op ($n)"
		ret=0
		dig_with_tls_opts -6 +tls @fd92:7065:b8e:ffff::1 +opcode="$op" > dig.out.test$n
		grep "status: $EXPECT_STATUS" dig.out.test$n > /dev/null || ret=1
		if [ $ret != 0 ]; then echo_i "failed"; fi
		status=$((status + ret))
	done
}

test_opcodes NOERROR 0
test_opcodes NOTIMP 1 2 3 6 7 8 9 10 11 12 13 14 15
test_opcodes FORMERR 4 5

n=$((n + 1))
echo_i "checking server quotas for both encrypted and unencrypted HTTP ($n)"
ret=0
if [ -x "$PYTHON" ]; then
	BINDHOST="10.53.0.1" "$PYTHON" "$TOP_SRCDIR/bin/tests/system/doth/stress_http_quota.py"
	ret=$?
else
	echo_i "Python is not available. Skipping the test..."
fi
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
