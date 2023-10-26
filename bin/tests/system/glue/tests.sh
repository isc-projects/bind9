#!/bin/sh

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

set -e

. ../conf.sh

dig_with_opts() {
  "$DIG" +norec -p "${PORT}" "$@"
}

status=0
n=0

n=$((n + 1))
echo_i "testing that a ccTLD referral gets a full glue set from the root zone ($n)"
ret=0
dig_with_opts @10.53.0.1 foo.bar.fi. A >dig.out.$n || ret=1
digcomp --lc fi.good dig.out.$n || ret=1
if [ "$ret" -ne 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "testing that we don't find out-of-zone glue ($n)"
ret=0
dig_with_opts @10.53.0.1 example.net. A >dig.out.$n || ret=1
digcomp noglue.good dig.out.$n || ret=1
if [ "$ret" -ne 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "testing truncation for unsigned referrals close to UDP packet size limit (A glue) ($n)"
ret=0
dig_with_opts @10.53.0.1 +ignore +noedns foo.subdomain-a.tc-test-unsigned. >dig.out.$n || ret=1
grep -q "flags:[^;]* tc" dig.out.$n || ret=1
if [ "$ret" -ne 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "testing truncation for unsigned referrals close to UDP packet size limit (AAAA glue) ($n)"
ret=0
dig_with_opts @10.53.0.1 +ignore +noedns foo.subdomain-aaaa.tc-test-unsigned. >dig.out.$n || ret=1
grep -q "flags:[^;]* tc" dig.out.$n || ret=1
if [ "$ret" -ne 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "testing truncation for unsigned referrals close to UDP packet size limit (A+AAAA glue) ($n)"
ret=0
dig_with_opts @10.53.0.1 +ignore +noedns foo.subdomain-both.tc-test-unsigned. >dig.out.$n || ret=1
grep -q "flags:[^;]* tc" dig.out.$n || ret=1
if [ "$ret" -ne 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "testing truncation for signed referrals close to UDP packet size limit (A glue) ($n)"
ret=0
dig_with_opts @10.53.0.1 +ignore +dnssec +bufsize=512 foo.subdomain-a.tc-test-signed. >dig.out.$n || ret=1
grep -q "flags:[^;]* tc" dig.out.$n || ret=1
if [ "$ret" -ne 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "testing truncation for signed referrals close to UDP packet size limit (AAAA glue) ($n)"
ret=0
dig_with_opts @10.53.0.1 +ignore +dnssec +bufsize=512 foo.subdomain-aaaa.tc-test-signed. >dig.out.$n || ret=1
grep -q "flags:[^;]* tc" dig.out.$n || ret=1
if [ "$ret" -ne 0 ]; then echo_i "failed"; fi
status=$((status + ret))

n=$((n + 1))
echo_i "testing truncation for signed referrals close to UDP packet size limit (A+AAAA glue) ($n)"
ret=0
dig_with_opts @10.53.0.1 +ignore +dnssec +bufsize=512 foo.subdomain-both.tc-test-signed. >dig.out.$n || ret=1
grep -q "flags:[^;]* tc" dig.out.$n || ret=1
if [ "$ret" -ne 0 ]; then echo_i "failed"; fi
status=$((status + ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
