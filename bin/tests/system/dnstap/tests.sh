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

RNDCCMD="$RNDC -p ${CONTROLPORT} -c ../_common/rndc.conf"

status=0

echo_i "wait for servers to finish loading"
ret=0
wait_for_log 20 "all zones loaded" ns2/named.run || ret=1
wait_for_log 20 "all zones loaded" ns3/named.run || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

_test_dnstap_roll() (
  ip="$1"
  ns="$2"
  n="$3"

  $RNDCCMD -s "${ip}" dnstap -roll "${n}" | sed "s/^/${ns} /" | cat_i \
    && files=$(find "$ns" -name "dnstap.out.[0-9]" | wc -l) \
    && test "$files" -eq "${n}" && test "$files" -ge "1" || return 1
)

test_dnstap_roll() {
  echo_i "checking 'rndc -roll $4' ($1)"
  ret=0

  try=0
  while test $try -lt 12; do
    touch "$3/dnstap.out.$try"
    try=$((try + 1))
  done

  _repeat 10 _test_dnstap_roll $2 $3 $4 || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))
}

test_dnstap_roll "no versions" 10.53.0.3 ns3 6
test_dnstap_roll "no versions" 10.53.0.3 ns3 3
test_dnstap_roll "no versions" 10.53.0.3 ns3 1

test_dnstap_roll "versions" 10.53.0.2 ns2 6
test_dnstap_roll "versions" 10.53.0.2 ns2 3
test_dnstap_roll "versions" 10.53.0.2 ns2 1

echo_i "exit status: $status"
[ "$status" -eq 0 ] || exit 1
