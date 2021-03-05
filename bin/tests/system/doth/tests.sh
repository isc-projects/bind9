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

. ../conf.sh

dig_with_tls_opts() {
	"$DIG" +tls +noadd +nosea +nostat +noquest +nocmd -p "${TLSPORT}" "$@"
}

dig_with_https_opts() {
	"$DIG" +https +noadd +nosea +nostat +noquest +nocmd -p "${HTTPSPORT}" "$@"
}

dig_with_http_opts() {
	"$DIG" +http-plain +noadd +nosea +nostat +noquest +nocmd -p "${HTTPPORT}" "$@"
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
digcomp dig1.good dig.out.ns1.test$n || ret=1
if test $ret != 0 ; then echo_i "failed"; fi
status=$((status+ret))

n=$((n+1))
echo_i "testing incoming XoT functionality (from secondary) ($n)"
ret=0
if retry_quiet 10 wait_for_tls_xfer; then
	grep "^;" "dig.out.ns2.test$n" | cat_i
	digcomp dig1.good "dig.out.ns2.test$n" || ret=1
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
echo_i "checking DoT query (static key) ($n)"
ret=0
dig_with_tls_opts @10.53.0.2 example SOA > dig.out.test$n
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

n=$((n + 1))
echo_i "checking DoH query (POST) ($n)"
ret=0
dig_with_https_opts @10.53.0.1 . SOA > dig.out.test$n
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
echo_i "checking DoH query (POST, nonstandard endpoint) ($n)"
ret=0
dig_with_https_opts +https=/alter @10.53.0.1 . SOA > dig.out.test$n
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
echo_i "checking DoH XFR (POST) (failure expected) ($n)"
ret=0
dig_with_https_opts +comm @10.53.0.1 . AXFR > dig.out.test$n
grep "status: FORMERR" dig.out.test$n > /dev/null || ret=1
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
echo_i "checking DoH query (GET, static key) ($n)"
ret=0
dig_with_https_opts +https-get @10.53.0.2 example SOA > dig.out.test$n
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
echo_i "checking DoH query (GET, undefined endpoint, failure expected) ($n)"
ret=0
dig_with_https_opts +tries=1 +time=1 +https-get=/fake @10.53.0.1 . SOA > dig.out.test$n
grep "communications error" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoH XFR (GET) (failure expected) ($n)"
ret=0
dig_with_https_opts +https-get +comm @10.53.0.1 . AXFR > dig.out.test$n
grep "status: FORMERR" dig.out.test$n > /dev/null || ret=1
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
echo_i "checking unencrypted DoH query (GET) ($n)"
ret=0
dig_with_http_opts +http-plain-get @10.53.0.1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking unencrypted DoH XFR (failure expected) ($n)"
ret=0
dig_with_http_opts +comm @10.53.0.1 . AXFR > dig.out.test$n
grep "status: FORMERR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
