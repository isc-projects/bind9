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

dig_with_opts() {
	"$DIG" +tls +noadd +nosea +nostat +noquest +nocomm +nocmd -p "${TLSPORT}" "$@"
}

wait_for_xfer() (
	dig_with_opts -b 10.53.0.3 @10.53.0.2 example. AXFR > "dig.out.ns2.test$n" || return 1
	grep "^;" "dig.out.ns2.test$n" > /dev/null && return 1
	return 0
)

status=0
n=0

n=$((n+1))
echo_i "testing XoT server functionality (using dig) ($n)"
ret=0
dig_with_opts example. -b 10.53.0.3 @10.53.0.1 axfr > dig.out.ns1.test$n || ret=1
grep "^;" dig.out.ns1.test$n | cat_i
digcomp dig1.good dig.out.ns1.test$n || ret=1
if test $ret != 0 ; then echo_i "failed"; fi
status=$((status+ret))

n=$((n+1))
echo_i "testing basic incoming XoT functionality (from secondary) ($n)"
ret=0
if retry_quiet 10 wait_for_xfer; then
	grep "^;" "dig.out.ns2.test$n" | cat_i
	digcomp dig1.good "dig.out.ns2.test$n" || ret=1
else
	echo_i "timed out waiting for zone transfer"
	ret=1
fi
if test $ret != 0 ; then echo_i "failed"; fi
status=$((status+ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
