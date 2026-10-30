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

DIGOPTS="-p ${PORT}"
RNDCCMD="$RNDC -p ${CONTROLPORT} -c ../_common/rndc.conf"

status=0

# dnstap_data_ready <fstrm_capture_PID> <capture_file> <min_file_size>
# Flushes capture_file and checks wheter its size is >= min_file_size.
dnstap_data_ready() {
  # Process id of running fstrm_capture.
  fstrm_capture_pid=$1
  # Output file provided to fstrm_capture via -w switch.
  capture_file=$2
  # Minimum expected file size.
  min_size_expected=$3

  kill -HUP $fstrm_capture_pid
  file_size=$(wc -c <"$capture_file" | tr -d ' ')
  if [ $file_size -lt $min_size_expected ]; then
    return 1
  fi
}

check_count() {
  [ $2 -eq $3 ] || {
    echo_i "$1 $2 expected $3"
    ret=1
  }
}

echo_i "wait for servers to finish loading"
ret=0
wait_for_log 20 "all zones loaded" ns1/named.run || ret=1
wait_for_log 20 "all zones loaded" ns2/named.run || ret=1
wait_for_log 20 "all zones loaded" ns3/named.run || ret=1
wait_for_log 20 "all zones loaded" ns4/named.run || ret=1
wait_for_log 20 "all zones loaded" ns5/named.run || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

if [ -n "$FSTRM_CAPTURE" ]; then
  ret=0
  echo_i "starting fstrm_capture"
  $FSTRM_CAPTURE -t protobuf:dnstap.Dnstap -u ns4/dnstap.out \
    -w dnstap.out >fstrm_capture.out.1 2>&1 &
  fstrm_capture_pid=$!
  wait_for_log 10 "socket path ns4/dnstap.out" fstrm_capture.out.1 || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))
fi

echo_i "reopen capture stream"
$RNDCCMD -s 10.53.0.4 dnstap -reopen | sed 's/^/ns4 /' | cat_i

# ns4 must not be able to reach any other server, so that only its
# client-facing frames are written to the unix socket.
$RNDCCMD -s 10.53.0.1 stop | sed 's/^/ns1 /' | cat_i
$RNDCCMD -s 10.53.0.2 stop | sed 's/^/ns2 /' | cat_i
$RNDCCMD -s 10.53.0.3 stop | sed 's/^/ns3 /' | cat_i
$RNDCCMD -s 10.53.0.5 stop | sed 's/^/ns5 /' | cat_i

if [ -n "$FSTRM_CAPTURE" ]; then
  ret=0
  $DIG $DIGOPTS @10.53.0.4 a.example >dig.out || ret=1

  # send an UPDATE to ns4
  $NSUPDATE <<-EOF >nsupdate.out 2>&1 && ret=1
	server 10.53.0.4 ${PORT}
	zone example
	update add b.example 3600 in a 10.10.10.10
	send
EOF
  grep "update failed: NOTAUTH" nsupdate.out >/dev/null || ret=1

  echo_i "checking unix socket message counts"
  sleep 2
  retry_quiet 5 dnstap_data_ready $fstrm_capture_pid dnstap.out 450 || {
    echo_i "dnstap output file smaller than expected"
    ret=1
  }
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))
  kill $fstrm_capture_pid
  wait
  udp4=$($DNSTAPREAD dnstap.out | grep "UDP " | wc -l)
  tcp4=$($DNSTAPREAD dnstap.out | grep "TCP " | wc -l)
  aq4=$($DNSTAPREAD dnstap.out | grep "AQ " | wc -l)
  ar4=$($DNSTAPREAD dnstap.out | grep "AR " | wc -l)
  cq4=$($DNSTAPREAD dnstap.out | grep "CQ " | wc -l)
  cr4=$($DNSTAPREAD dnstap.out | grep "CR " | wc -l)
  fq4=$($DNSTAPREAD dnstap.out | grep "FQ " | wc -l)
  fr4=$($DNSTAPREAD dnstap.out | grep "FR " | wc -l)
  rq4=$($DNSTAPREAD dnstap.out | grep "RQ " | wc -l)
  rr4=$($DNSTAPREAD dnstap.out | grep "RR " | wc -l)
  uq4=$($DNSTAPREAD dnstap.out | grep "UQ " | wc -l)
  ur4=$($DNSTAPREAD dnstap.out | grep "UR " | wc -l)

  echo_i "checking UDP message counts"
  ret=0
  check_count ns4 $udp4 4
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking TCP message counts"
  ret=0
  check_count ns4 $tcp4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking AUTH_QUERY message counts"
  ret=0
  check_count ns4 $aq4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking AUTH_RESPONSE message counts"
  ret=0
  check_count ns4 $ar4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking CLIENT_QUERY message counts"
  ret=0
  check_count ns4 $cq4 1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking CLIENT_RESPONSE message counts"
  ret=0
  check_count ns4 $cr4 1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking RESOLVER_QUERY message counts"
  ret=0
  check_count ns4 $rq4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking RESOLVER_RESPONSE message counts"
  ret=0
  check_count ns4 $rr4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking FORWARDER_QUERY message counts"
  ret=0
  check_count ns4 $fq4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking FORWARDER_RESPONSE message counts"
  ret=0
  check_count ns4 $fr4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking UPDATE_QUERY message counts"
  ret=0
  check_count ns4 $uq4 1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking UPDATE_RESPONSE message counts"
  ret=0
  check_count ns4 $ur4 1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  mv dnstap.out dnstap.out.save

  echo_i "restarting fstrm_capture"
  $FSTRM_CAPTURE -t protobuf:dnstap.Dnstap -u ns4/dnstap.out \
    -w dnstap.out >fstrm_capture.out.2 2>&1 &
  fstrm_capture_pid=$!
  wait_for_log 10 "socket path ns4/dnstap.out" fstrm_capture.out.2 || {
    echo_i "failed"
    ret=1
  }
  $RNDCCMD -s 10.53.0.4 dnstap -reopen | sed 's/^/ns4 /' | cat_i
  $DIG $DIGOPTS @10.53.0.4 a.example >dig.out || ret=1

  echo_i "checking reopened unix socket message counts"
  sleep 2
  retry_quiet 5 dnstap_data_ready $fstrm_capture_pid dnstap.out 270 || {
    echo_i "dnstap output file smaller than expected"
    ret=1
  }
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))
  kill $fstrm_capture_pid
  wait
  udp4=$($DNSTAPREAD dnstap.out | grep "UDP " | wc -l)
  tcp4=$($DNSTAPREAD dnstap.out | grep "TCP " | wc -l)
  aq4=$($DNSTAPREAD dnstap.out | grep "AQ " | wc -l)
  ar4=$($DNSTAPREAD dnstap.out | grep "AR " | wc -l)
  cq4=$($DNSTAPREAD dnstap.out | grep "CQ " | wc -l)
  cr4=$($DNSTAPREAD dnstap.out | grep "CR " | wc -l)
  fq4=$($DNSTAPREAD dnstap.out | grep "FQ " | wc -l)
  fr4=$($DNSTAPREAD dnstap.out | grep "FR " | wc -l)
  rq4=$($DNSTAPREAD dnstap.out | grep "RQ " | wc -l)
  rr4=$($DNSTAPREAD dnstap.out | grep "RR " | wc -l)
  uq4=$($DNSTAPREAD dnstap.out | grep "UQ " | wc -l)
  ur4=$($DNSTAPREAD dnstap.out | grep "UR " | wc -l)

  echo_i "checking UDP message counts"
  ret=0
  check_count ns4 $udp4 2
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking TCP message counts"
  ret=0
  check_count ns4 $tcp4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking AUTH_QUERY message counts"
  ret=0
  check_count ns4 $aq4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking AUTH_RESPONSE message counts"
  ret=0
  check_count ns4 $ar4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking CLIENT_QUERY message counts"
  ret=0
  check_count ns4 $cq4 1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking CLIENT_RESPONSE message counts"
  ret=0
  check_count ns4 $cr4 1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking RESOLVER_QUERY message counts"
  ret=0
  check_count ns4 $rq4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking RESOLVER_RESPONSE message counts"
  ret=0
  check_count ns4 $rr4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking FORWARDER_QUERY message counts"
  ret=0
  check_count ns4 $fq4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking FORWARDER_RESPONSE message counts"
  ret=0
  check_count ns4 $fr4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking UPDATE_QUERY message counts"
  ret=0
  check_count ns4 $uq4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  echo_i "checking UPDATE_RESPONSE message counts"
  ret=0
  check_count ns4 $ur4 0
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))
fi

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

start_server --noclean --restart --port "${PORT}" ns3
test_dnstap_roll "no versions" 10.53.0.3 ns3 6
test_dnstap_roll "no versions" 10.53.0.3 ns3 3
test_dnstap_roll "no versions" 10.53.0.3 ns3 1

start_server --noclean --restart --port "${PORT}" ns2
test_dnstap_roll "versions" 10.53.0.2 ns2 6
test_dnstap_roll "versions" 10.53.0.2 ns2 3
test_dnstap_roll "versions" 10.53.0.2 ns2 1

echo_i "exit status: $status"
[ "$status" -eq 0 ] || exit 1
