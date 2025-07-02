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

# shellcheck source=conf.sh
. ../conf.sh

status=0
n=1

delv_with_opts() {
  "$DELV" -a ns1/trusted.conf -p "$PORT" "$@"
}

if [ -x "${DELV}" ]; then
  ret=0
  echo_i "checking positive validation NSEC using dns_client ($n)"
  delv_with_opts @10.53.0.4 a a.example >delv.out$n || ret=1
  grep "a.example..*10.0.0.1" delv.out$n >/dev/null || ret=1
  grep "a.example..*.RRSIG.A [0-9][0-9]* 2 3600 .*" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking positive validation NSEC using dns_client (trusted-keys) ($n)"
  "$DELV" -a ns1/trusted.keys -p "$PORT" @10.53.0.4 a a.example >delv.out$n || ret=1
  grep "a.example..*10.0.0.1" delv.out$n >/dev/null || ret=1
  grep "a.example..*.RRSIG.A [0-9][0-9]* 2 3600 .*" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking positive validation NSEC3 using dns_client ($n)"
  delv_with_opts @10.53.0.4 a a.nsec3.example >delv.out$n || ret=1
  grep "a.nsec3.example..*10.0.0.1" delv.out$n >/dev/null || ret=1
  grep "a.nsec3.example..*RRSIG.A [0-9][0-9]* 3 300 .*" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  SP="[[:space:]]+"

  ret=0
  echo_i "checking positive validation OPTOUT using dns_client ($n)"
  delv_with_opts @10.53.0.4 a a.optout.example >delv.out$n || ret=1
  grep -Eq "^a\\.optout\\.example\\.""$SP""[0-9]+""$SP""IN""$SP""A""$SP""10.0.0.1" delv.out$n || ret=1
  grep -Eq "^a\\.optout\\.example\\.""$SP""[0-9]+""$SP""IN""$SP""RRSIG""$SP""A""$SP""$DEFAULT_ALGORITHM_NUMBER""$SP""3""$SP""300" delv.out$n || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking positive wildcard validation NSEC using dns_client ($n)"
  delv_with_opts @10.53.0.4 a a.wild.example >delv.out$n || ret=1
  grep "a.wild.example..*10.0.0.27" delv.out$n >/dev/null || ret=1
  grep -E "a.wild.example..*RRSIG.A [0-9]+ 2 3600 .*" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking positive wildcard validation NSEC3 using dns_client ($n)"
  delv_with_opts @10.53.0.4 a a.wild.nsec3.example >delv.out$n || ret=1
  grep -E "a.wild.nsec3.example..*10.0.0.6" delv.out$n >/dev/null || ret=1
  grep -E "a.wild.nsec3.example..*RRSIG.A [0-9][0-9]* 3 300.*" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking positive wildcard validation OPTOUT using dns_client ($n)"
  delv_with_opts @10.53.0.4 a a.wild.optout.example >delv.out$n || ret=1
  grep "a.wild.optout.example..*10.0.0.6" delv.out$n >/dev/null || ret=1
  grep "a.wild.optout.example..*RRSIG.A [0-9][0-9]* 3 300.*" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking negative validation NXDOMAIN NSEC using dns_client ($n)"
  delv_with_opts @10.53.0.4 a q.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: ncache nxdomain" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking negative validation NXDOMAIN NSEC3 using dns_client ($n)"
  delv_with_opts @10.53.0.4 a q.nsec3.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: ncache nxdomain" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking negative validation NXDOMAIN OPTOUT using dns_client ($n)"
  delv_with_opts @10.53.0.4 a q.optout.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: ncache nxdomain" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking negative validation NODATA OPTOUT using dns_client ($n)"
  delv_with_opts @10.53.0.4 txt a.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: ncache nxrrset" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking negative validation NODATA NSEC3 using dns_client ($n)"
  delv_with_opts @10.53.0.4 txt a.nsec3.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: ncache nxrrset" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking negative validation NODATA OPTOUT using dns_client ($n)"
  delv_with_opts @10.53.0.4 txt a.optout.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: ncache nxrrset" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking negative wildcard validation NSEC using dns_client ($n)"
  delv_with_opts @10.53.0.4 txt b.wild.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: ncache nxrrset" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking negative wildcard validation NSEC3 using dns_client ($n)"
  delv_with_opts @10.53.0.4 txt b.wild.nsec3.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: ncache nxrrset" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking negative wildcard validation OPTOUT using dns_client ($n)"
  delv_with_opts @10.53.0.4 txt b.optout.nsec3.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: ncache nxrrset" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking 1-server insecurity proof NSEC using dns_client ($n)"
  delv_with_opts @10.53.0.4 a a.insecure.example >delv.out$n || ret=1
  grep "a.insecure.example..*10.0.0.1" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking 1-server insecurity proof NSEC3 using dns_client ($n)"
  delv_with_opts @10.53.0.4 a a.insecure.nsec3.example >delv.out$n || ret=1
  grep "a.insecure.nsec3.example..*10.0.0.1" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking 1-server insecurity proof OPTOUT using dns_client ($n)"
  delv_with_opts @10.53.0.4 a a.insecure.optout.example >delv.out$n || ret=1
  grep "a.insecure.optout.example..*10.0.0.1" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking 1-server negative insecurity proof NSEC using dns_client ($n)"
  delv_with_opts @10.53.0.4 a q.insecure.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: ncache nxdomain" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking 1-server negative insecurity proof NSEC3 using dns_client ($n)"
  delv_with_opts @10.53.0.4 a q.insecure.nsec3.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: ncache nxdomain" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking 1-server negative insecurity proof OPTOUT using dns_client ($n)"
  delv_with_opts @10.53.0.4 a q.insecure.optout.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: ncache nxdomain" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking failed validation using dns_client ($n)"
  delv_with_opts +cd @10.53.0.4 a a.bogus.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: RRSIG failed to verify" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking that validation fails when key record is missing using dns_client ($n)"
  delv_with_opts +cd @10.53.0.4 a a.b.keyless.example >delv.out$n 2>&1 || ret=1
  grep "resolution failed: insecurity proof failed" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  ret=0
  echo_i "checking that validation succeeds when a revoked key is encountered using dns_client ($n)"
  delv_with_opts +cd @10.53.0.4 soa revkey.example >delv.out$n 2>&1 || ret=1
  grep "fully validated" delv.out$n >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
fi

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
