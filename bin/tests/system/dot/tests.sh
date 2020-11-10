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

set -e

# shellcheck source=../conf.sh
. ../conf.sh

dig_dot_with_opts() {
	"${DIG}" -p "${TLSPORT}" +tls "$@"
}

status=0
n=0

n=$((n + 1))
echo_i "checking DoT query response ($n)"
ret=0
dig_dot_with_opts @10.53.0.1 . SOA > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "checking DoT XFR ($n)"
ret=0
dig_dot_with_opts +comment @10.53.0.1 . AXFR > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
