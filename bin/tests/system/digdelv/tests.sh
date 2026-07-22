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

# Check if response in file $1 has the correct TTL range.
# The response record must have RRtype $2 and class IN (CLASS1).
# Maximum TTL is given by $3.  This works in most cases where TTL is
# the second word on the line.  TTL position can be adjusted with
# setting the position $4, but that requires updating this function.
check_ttl_range() {
  file=$1
  pos=$4

  case "$pos" in
    "3")
      {
        awk -v rrtype="$2" -v ttl="$3" '($4 == "IN" || $4 == "CLASS1" ) && $5 == rrtype { if ($3 <= ttl) { ok=1 } } END { exit(ok?0:1) }' <$file
        result=$?
      } || true
      ;;
    *)
      {
        awk -v rrtype="$2" -v ttl="$3" '($3 == "IN" || $3 == "CLASS1" ) && $4 == rrtype { if ($2 <= ttl) { ok=1 } } END { exit(ok?0:1) }' <$file
        result=$?
      } || true
      ;;
  esac

  [ $result -eq 0 ] || echo_i "ttl check failed"
  return $result
}

# use delv insecure mode by default, as we're mostly not testing dnssec
delv_with_opts() {
  "$DELV" +noroot -p "$PORT" "$@"
}

KEYID="$(cat ns2/keyid)"
KEYDATA="$(sed <ns2/keydata -e 's/+/[+]/g')"
NOSPLIT="$(sed <ns2/keydata -e 's/+/[+]/g' -e 's/ //g')"

HAS_PYYAML=0
$PYTHON -c "import yaml" 2>/dev/null && HAS_PYYAML=1

if [ -x "$DELV" ]; then
  n=$((n + 1))
  echo_i "checking delv short form works ($n)"
  ret=0
  delv_with_opts @10.53.0.3 +short a a.example >delv.out.test$n || ret=1
  test "$(wc -l <delv.out.test$n)" -eq 1 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +cookie works ($n)"
  ret=0
  delv_with_opts @10.53.0.3 +cookie a a.example -d 10 >delv.out.test$n 2>&1 || ret=1
  grep "; COOKIE:" delv.out.test$n >/dev/null || ret=1
  grep "; answer not validated" delv.out.test$n >/dev/null || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +nocookie works ($n)"
  ret=0
  delv_with_opts @10.53.0.3 +nocookie +strace a a.example -d 10 >delv.out.test$n 2>&1 || ret=1
  grep "; COOKIE:" delv.out.test$n >/dev/null && ret=1
  grep "; answer not validated" delv.out.test$n >/dev/null || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv split width works ($n)"
  ret=0
  delv_with_opts @10.53.0.3 +split=4 -t sshfp foo.example >delv.out.test$n || ret=1
  grep " 9ABC DEF6 7890 " <delv.out.test$n >/dev/null || ret=1
  check_ttl_range delv.out.test$n "SSHFP" 300 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +unknownformat works ($n)"
  ret=0
  delv_with_opts @10.53.0.3 +unknownformat a a.example >delv.out.test$n || ret=1
  grep "CLASS1[ 	][ 	]*TYPE1[ 	][ 	]*\\\\# 4 0A000001" <delv.out.test$n >/dev/null || ret=1
  check_ttl_range delv.out.test$n "TYPE1" 300 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv -4 -6 ($n)"
  ret=0
  delv_with_opts @10.53.0.3 -4 -6 A a.example >delv.out.test$n 2>&1 && ret=1
  grep "only one of -4 and -6 allowed" <delv.out.test$n >/dev/null || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv exits cleanly on malformed query name ($n)"
  ret=0
  longlabel="$(printf 'a%.0s' $(seq 1 64))"
  delv_with_opts @10.53.0.3 -t a "$longlabel.example.com" >delv.out.test$n 2>&1
  rc=$?
  # Pre-fix: SIGABRT (exit 134) from dns_client_detach(NULL) in run_resolve cleanup.
  [ $rc -eq 134 ] && ret=1
  grep "label too long" delv.out.test$n >/dev/null || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv with IPv6 on IPv4 does not work ($n)"
  if testsock6 fd92:7065:b8e:ffff::3 2>/dev/null; then
    ret=0
    # following should fail because @IPv4 overrides earlier @IPv6 above
    # and -6 forces IPv6 so this should fail, with a message
    # "Use of IPv4 disabled by -6"
    delv_with_opts @fd92:7065:b8e:ffff::3 @10.53.0.3 -6 -t txt foo.example >delv.out.test$n 2>&1 && ret=1
    # it should have no results but error output
    grep "testing" <delv.out.test$n >/dev/null && ret=1
    grep "Use of IPv4 disabled by -6" delv.out.test$n >/dev/null || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))
  else
    echo_i "IPv6 unavailable; skipping"
  fi

  n=$((n + 1))
  echo_i "checking delv with IPv4 on IPv6 does not work ($n)"
  if testsock6 fd92:7065:b8e:ffff::3 2>/dev/null; then
    ret=0
    # following should fail because @IPv6 overrides earlier @IPv4 above
    # and -4 forces IPv4 so this should fail, with a message
    # "Use of IPv6 disabled by -4"
    delv_with_opts @10.53.0.3 @fd92:7065:b8e:ffff::3 -4 -t txt foo.example >delv.out.test$n 2>&1 && ret=1
    # it should have no results but error output
    grep "testing" delv.out.test$n >/dev/null && ret=1
    grep "Use of IPv6 disabled by -4" delv.out.test$n >/dev/null || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))
  else
    echo_i "IPv6 unavailable; skipping"
  fi

  n=$((n + 1))
  echo_i "checking delv with reverse lookup works ($n)"
  ret=0
  delv_with_opts @10.53.0.3 -x 127.0.0.1 >delv.out.test$n 2>&1 || ret=1
  # doesn't matter if has answer
  grep -i "127\\.in-addr\\.arpa\\." <delv.out.test$n >/dev/null || ret=1
  check_ttl_range delv.out.test$n '\\-ANY' 10800 3 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv over TCP works ($n)"
  ret=0
  delv_with_opts +tcp @10.53.0.3 a a.example >delv.out.test$n || ret=1
  grep "10\\.0\\.0\\.1$" <delv.out.test$n >/dev/null || ret=1
  check_ttl_range delv.out.test$n "A" 300 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +multi +norrcomments works for DNSKEY (when default is rrcomments)($n)"
  ret=0
  delv_with_opts +tcp @10.53.0.3 +multi +norrcomments DNSKEY example >delv.out.test$n || ret=1
  grep "; ZSK; alg = $DEFAULT_ALGORITHM ; key id = $KEYID" <delv.out.test$n >/dev/null && ret=1
  check_ttl_range delv.out.test$n "DNSKEY" 300 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +multi +norrcomments works for SOA (when default is rrcomments)($n)"
  ret=0
  delv_with_opts +tcp @10.53.0.3 +multi +norrcomments SOA example >delv.out.test$n || ret=1
  grep "; ZSK; alg = $DEFAULT_ALGORITHM ; key id = $KEYID" <delv.out.test$n >/dev/null && ret=1
  check_ttl_range delv.out.test$n "SOA" 300 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +rrcomments works for DNSKEY($n)"
  ret=0
  delv_with_opts +tcp @10.53.0.3 +rrcomments DNSKEY example >delv.out.test$n || ret=1
  grep "; ZSK; alg = $DEFAULT_ALGORITHM ; key id = $KEYID" <delv.out.test$n >/dev/null || ret=1
  check_ttl_range delv.out.test$n "DNSKEY" 300 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +short +rrcomments works for DNSKEY ($n)"
  ret=0
  delv_with_opts +tcp @10.53.0.3 +short +rrcomments DNSKEY example >delv.out.test$n || ret=1
  grep "; ZSK; alg = $DEFAULT_ALGORITHM ; key id = $KEYID" <delv.out.test$n >/dev/null || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +short +rrcomments works ($n)"
  ret=0
  delv_with_opts +tcp @10.53.0.3 +short +rrcomments DNSKEY example >delv.out.test$n || ret=1
  grep -q "$KEYDATA  ; ZSK; alg = $DEFAULT_ALGORITHM ; key id = $KEYID" <delv.out.test$n || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +short +nosplit works ($n)"
  ret=0
  delv_with_opts +tcp @10.53.0.3 +short +nosplit DNSKEY example >delv.out.test$n || ret=1
  grep -q "$NOSPLIT" <delv.out.test$n || ret=1
  test "$(wc -l <delv.out.test$n)" -eq 1 || ret=1
  test "$(awk '{print NF}' <delv.out.test$n)" -eq 14 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +short +nosplit +norrcomments works ($n)"
  ret=0
  delv_with_opts +tcp @10.53.0.3 +short +nosplit +norrcomments DNSKEY example >delv.out.test$n || ret=1
  grep -q "$NOSPLIT\$" <delv.out.test$n || ret=1
  test "$(wc -l <delv.out.test$n)" -eq 1 || ret=1
  test "$(awk '{print NF}' <delv.out.test$n)" -eq 4 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +sp works as an abbriviated form of split ($n)"
  ret=0
  delv_with_opts @10.53.0.3 +sp=4 -t sshfp foo.example >delv.out.test$n || ret=1
  grep " 9ABC DEF6 7890 " <delv.out.test$n >/dev/null || ret=1
  check_ttl_range delv.out.test$n "SSHFP" 300 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv +sh works as an abbriviated form of short ($n)"
  ret=0
  delv_with_opts @10.53.0.3 +sh a a.example >delv.out.test$n || ret=1
  test "$(wc -l <delv.out.test$n)" -eq 1 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv -c IN works ($n)"
  ret=0
  delv_with_opts @10.53.0.3 -c IN -t a a.example >delv.out.test$n || ret=1
  grep "a.example." <delv.out.test$n >/dev/null || ret=1
  check_ttl_range delv.out.test$n "A" 300 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv -c CH is ignored, and treated like IN ($n)"
  ret=0
  delv_with_opts @10.53.0.3 -c CH -t a a.example >delv.out.test$n || ret=1
  grep "a.example." <delv.out.test$n >/dev/null || ret=1
  check_ttl_range delv.out.test$n "A" 300 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking delv -c CH is ignored, and treated like IN ($n)"
  ret=0
  delv_with_opts @10.53.0.3 -c CH -t a a.example >delv.out.test$n || ret=1
  grep "a.example." <delv.out.test$n >/dev/null || ret=1
  check_ttl_range delv.out.test$n "A" 300 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "check that delv -q -m works ($n)"
  ret=0
  delv_with_opts @10.53.0.3 -q -m >delv.out.test$n 2>&1 || ret=1
  grep '^; -m\..*[0-9]*.*IN.*ANY.*;' delv.out.test$n >/dev/null || ret=1
  grep "^add " delv.out.test$n >/dev/null && ret=1
  grep "^del " delv.out.test$n >/dev/null && ret=1
  check_ttl_range delv.out.test$n '\\-ANY' 300 3 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "check that delv -t ANY works ($n)"
  ret=0
  delv_with_opts @10.53.0.3 -t ANY example >delv.out.test$n 2>&1 || ret=1
  grep "^example." <delv.out.test$n >/dev/null || ret=1
  check_ttl_range delv.out.test$n NS 300 || ret=1
  check_ttl_range delv.out.test$n SOA 300 || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "check that delv loads key-style trust anchors ($n)"
  ret=0
  delv_with_opts -a ns3/anchor.dnskey +root=example @10.53.0.3 -t DNSKEY example >delv.out.test$n 2>&1 || ret=1
  grep "fully validated" delv.out.test$n >/dev/null || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "check that delv loads DS-style trust anchors ($n)"
  ret=0
  delv_with_opts -a ns3/anchor.ds +root=example @10.53.0.3 -t DNSKEY example >delv.out.test$n 2>&1 || ret=1
  grep "fully validated" delv.out.test$n >/dev/null || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  if [ $HAS_PYYAML -ne 0 ]; then
    n=$((n + 1))
    echo_i "check delv +yaml ANY output ($n)"
    ret=0
    delv_with_opts +yaml @10.53.0.3 any ns2.example >delv.out.test$n || ret=1
    $PYTHON yamlget.py delv.out.test$n status >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "success" ] || ret=1
    $PYTHON yamlget.py delv.out.test$n query_name >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "ns2.example" ] || ret=1
    $PYTHON yamlget.py delv.out.test$n records 0 answer_not_validated 0 >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    count=$(echo $value | wc -w)
    [ ${count:-0} -eq 5 ] || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))

    n=$((n + 1))
    echo_i "check delv +yaml NODATA output ($n)"
    ret=0
    delv_with_opts +yaml @10.53.0.3 type500 ns2.example >delv.out.test$n || ret=1
    $PYTHON yamlget.py delv.out.test$n status >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "ncache nxrrset" ] || ret=1
    $PYTHON yamlget.py delv.out.test$n query_name >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "ns2.example" ] || ret=1
    $PYTHON yamlget.py delv.out.test$n records 0 negative_response_answer_not_validated 0 >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    count=$(echo $value | wc -w)
    [ ${count:-0} -eq 5 ] || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))

    n=$((n + 1))
    echo_i "check delv +yaml NXDOMAIN output ($n)"
    ret=0
    delv_with_opts +yaml @10.53.0.3 a this-does-not-exist.ns2.example >delv.out.test$n || ret=1
    $PYTHON yamlget.py delv.out.test$n status >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "ncache nxdomain" ] || ret=1
    $PYTHON yamlget.py delv.out.test$n query_name >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "this-does-not-exist.ns2.example" ] || ret=1
    $PYTHON yamlget.py delv.out.test$n records 0 negative_response_answer_not_validated 0 >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    count=$(echo $value | wc -w)
    [ ${count:-0} -eq 5 ] || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))
  fi

  n=$((n + 1))
  echo_i "check that delv handles REFUSED when chasing DS records ($n)"
  ret=0
  delv_with_opts @10.53.0.2 +root xxx.example.tld A >delv.out.test$n 2>&1 || ret=1
  grep ";; resolution failed: broken trust chain" delv.out.test$n >/dev/null || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

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
