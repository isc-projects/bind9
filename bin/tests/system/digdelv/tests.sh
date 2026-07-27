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
n=0

# use delv insecure mode by default, as we're mostly not testing dnssec
delv_with_opts() {
  "$DELV" +noroot -p "$PORT" "$@"
}

if [ -x "$DELV" ]; then
  n=$((n + 1))
  echo_i "check NS output from delv +ns ($n)"
  ret=0
  delv_with_opts -i +ns +nortrace +nostrace +nomtrace +novtrace +hint=root.hint ns example >delv.out.test$n || ret=1
  lines=$(awk '$1 == "example." && $4 == "NS" {print}' delv.out.test$n | wc -l)
  [ $lines -eq 2 ] || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +ns (no validation) ($n)"
  ret=0
  delv_with_opts -i +ns +hint=root.hint a a.example >delv.out.test$n || ret=1
  grep -q '; authoritative' delv.out.test$n || ret=1
  grep -q '_.example' delv.out.test$n && ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +ns +qmin (no validation) ($n)"
  ret=0
  delv_with_opts -i +ns +qmin +hint=root.hint a a.example >delv.out.test$n || ret=1
  grep -q '; authoritative' delv.out.test$n || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +ns (with validation) ($n)"
  ret=0
  delv_with_opts -a ns1/anchor.dnskey +root +ns +hint=root.hint a a.example >delv.out.test$n || ret=1
  grep -q '; fully validated' delv.out.test$n || ret=1
  grep -q '_.example' delv.out.test$n && ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +ns +qmin (with validation) ($n)"
  ret=0
  delv_with_opts -a ns1/anchor.dnskey +root +ns +qmin +hint=root.hint a a.example >delv.out.test$n || ret=1
  grep -q '; fully validated' delv.out.test$n || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  if testsock6 fd92:7065:b8e:ffff::2 2>/dev/null; then
    n=$((n + 1))
    echo_i "checking delv -4 +ns uses only IPv4 ($n)"
    ret=0
    delv_with_opts -a ns1/anchor.dnskey +root -4 +ns +hint=root.hint a a.example >delv.out.test$n || ret=1
    grep -q 'sending packet from [0-9.]*#[0-9]* to' delv.out.test$n >/dev/null || ret=1
    grep -q 'sending packet from [0-9a-f:]*#[0-9]* to' delv.out.test$n >/dev/null && ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))

    n=$((n + 1))
    echo_i "checking delv -6 +ns uses only IPv6 ($n)"
    ret=0
    delv_with_opts -a ns1/anchor.dnskey +root -6 +ns +hint=root.hint a a.example >delv.out.test$n || ret=1
    grep -q 'sending packet from [0-9.]*#[0-9]* to' delv.out.test$n >/dev/null && ret=1
    grep -q 'sending packet from [0-9a-f:]*#[0-9]* to' delv.out.test$n >/dev/null || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))
  fi

  n=$((n + 1))
  echo_i "checking delv +ns +cookie adds DNS COOKIE options ($n)"
  ret=0
  delv_with_opts -a ns1/anchor.dnskey +root +ns +qmin +hint=root.hint +cookie -d 99 a a.example >delv.out.test$n 2>&1 || ret=1
  grep -q '; COOKIE:' delv.out.test$n || ret=1
  grep -q '; fully validated' delv.out.test$n || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +ns +nocookie doesn't add DNS COOKIE options $n)"
  ret=0
  delv_with_opts -a ns1/anchor.dnskey +root +ns +qmin +hint=root.hint +nocookie -d 99 a a.example >delv.out.test$n 2>&1 || ret=1
  grep -q '; COOKIE:' delv.out.test$n && ret=1
  grep -q '; fully validated' delv.out.test$n || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

else
  echo_i "$DELV is needed, so skipping these delv tests"
fi

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
