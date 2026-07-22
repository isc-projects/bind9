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

dig_with_opts() {
  "$DIG" -p "$PORT" "$@"
}

mdig_with_opts() {
  "$MDIG" -p "$PORT" "$@"
}

set_response_sequence() {
  SEQUENCE="${1}"
  LOGID="${2}"
  dig_with_opts @10.53.0.5 "${SEQUENCE}.response-sequence._control" TXT >dig.out.control${LOGID} 2>&1 || ret=1
}

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

if [ -x "$DIG" ]; then
  if [ $HAS_PYYAML -ne 0 ]; then
    n=$((n + 1))
    echo_i "check dig +yaml ANY output ($n)"
    ret=0
    dig_with_opts +qr +yaml @10.53.0.3 any ns2.example >dig.out.test$n 2>&1 || ret=1
    $PYTHON yamlget.py dig.out.test$n 0 message query_message_data status >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "NOERROR" ] || ret=1
    $PYTHON yamlget.py dig.out.test$n 1 message response_message_data status >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "NOERROR" ] || ret=1
    $PYTHON yamlget.py dig.out.test$n 1 message response_message_data QUESTION_SECTION 0 >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "ns2.example. IN ANY" ] || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))

    n=$((n + 1))
    echo_i "check dig +yaml output of an IPv6 address ending in zeroes ($n)"
    ret=0
    dig_with_opts +qr +yaml @10.53.0.3 aaaa d.example >dig.out.test$n 2>&1 || ret=1
    $PYTHON yamlget.py dig.out.test$n 1 message response_message_data ANSWER_SECTION 0 >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "d.example. 300 IN AAAA fd92:7065:b8e:ffff::0" ] || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))

    # When all servers fail (here: a UDP query that times out with no
    # response), dig must not emit the ";"-prefixed startup banner ahead of
    # the "- type: DIG_ERROR" block, as that would make the +yaml output
    # invalid YAML.  The query name is deliberately placed before +yaml on the
    # command line: that is what makes dig build the banner (while +cmd is
    # still in effect) before switching to YAML output, which is the ordering
    # that regressed.
  fi

  # +nocmd placed after the query name must suppress the startup banner
  # ("<<>> DiG ..." lines), including on the error path.  This regressed
  # because the banner was built as soon as the query name was seen, before
  # +nocmd had been parsed; it is now built after the whole command line has
  # been processed.  The default (+cmd) case is checked first so the absence
  # check below is meaningful.
  # See [GL #3020] for more information
  # With +short, dig must not emit the ";; " progress/error comments (here:
  # the "Got SERVFAIL reply from ..." note printed while retrying).  +short
  # normally turns comments off, but "+short +comments" re-enables them while
  # short form is still in effect; the comment output then belongs to the
  # verbose form and would corrupt the short output.  The "+comments" case
  # (without +short) is checked first so the absence check below is meaningful.
  # Note that we combine TCP socket "connection error" and "timeout" cases in
  # one, because it is not trivial to simulate the timeout case in a system test
  # in Linux without a firewall, but the code which handles error cases during
  # the connection establishment time does not differentiate between timeout and
  # other types of errors (unlike during reading), so this one check should be
  # sufficient for both cases.
  # See [GL #3248] for more information
  # See [GL #3244] for more information
  # See GL#5609
else
  echo_i "$DIG is needed, so skipping these dig tests"
fi

if [ -x "$MDIG" ]; then
  n=$((n + 1))
  echo_i "checking mdig +tcp works with a source address and port ($n)"
  ret=0
  # When running more than once in quick succession with a source address#port,
  # we can get a "response failed with address not available" error because
  # the address#port is still busy, but we are not interested in that error,
  # as we are only looking for the unexpected error case, that's why we ignore
  # the return code from mdig, but we check for the unexpected error message
  # using grep. See GitLab #4969.
  mdig_with_opts -b "10.53.0.3#${EXTRAPORT8}" +tcp @10.53.0.3 example >dig.out.test$n 2>&1 || true
  grep -F "unexpected error" dig.out.test$n >/dev/null && ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "check that mdig handles malformed option '+ednsopt=:' gracefully ($n)"
  ret=0
  mdig_with_opts @10.53.0.3 +ednsopt=: a.example >dig.out.test$n 2>&1 && ret=1
  grep "ednsopt no code point specified" dig.out.test$n >/dev/null || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking mdig +multi +norrcomments works for DNSKEY (when default is rrcomments)($n)"
  ret=0
  mdig_with_opts +tcp @10.53.0.3 +multi +norrcomments -t DNSKEY example >dig.out.test$n || ret=1
  grep "; ZSK; alg = $DEFAULT_ALGORITHM ; key id = $KEYID" dig.out.test$n && ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  n=$((n + 1))
  echo_i "checking mdig +multi +norrcomments works for SOA (when default is rrcomments)($n)"
  ret=0
  mdig_with_opts +tcp @10.53.0.3 +multi +norrcomments -t SOA example >dig.out.test$n || ret=1
  grep "; serial" <dig.out.test$n >/dev/null && ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))

  if [ $HAS_PYYAML -ne 0 ]; then
    n=$((n + 1))
    echo_i "check mdig +yaml output ($n)"
    ret=0
    mdig_with_opts +yaml @10.53.0.3 -t any ns2.example >dig.out.test$n 2>&1 || ret=1
    $PYTHON yamlget.py dig.out.test$n 0 message response_message_data status >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "NOERROR" ] || ret=1
    $PYTHON yamlget.py dig.out.test$n 0 message response_message_data QUESTION_SECTION 0 >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "ns2.example. IN ANY" ] || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))
  fi
else
  echo_i "$MDIG is needed, so skipping these mdig tests"
fi

if [ -x "$DELV" ]; then
  n=$((n + 1))
  echo_i "checking delv short form works ($n)"
  ret=0
  delv_with_opts @10.53.0.3 +short a a.example >delv.out.test$n || ret=1
  test "$(wc -l <delv.out.test$n)" -eq 1 || ret=1
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
    grep -qF 'sending packet to 10.53' delv.out.test$n >/dev/null || ret=1
    grep -qF 'sending packet to fd92:7065' delv.out.test$n >/dev/null && ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))

    n=$((n + 1))
    echo_i "checking delv -6 +ns uses only IPv6 ($n)"
    ret=0
    delv_with_opts -a ns1/anchor.dnskey +root -6 +ns +hint=root.hint a a.example >delv.out.test$n || ret=1
    grep -qF 'sending packet to 10.53' delv.out.test$n >/dev/null && ret=1
    grep -qF 'sending packet to fd92:7065' delv.out.test$n >/dev/null || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))
  fi

else
  echo_i "$DELV is needed, so skipping these delv tests"
fi

if [ $HAS_PYYAML -ne 0 ]; then
  for qname in "yaml" "'.yaml" "[.yaml" "{.yaml" "&.yaml" "#.yaml"; do
    n=$((n + 1))
    echo_i "check yaml special '${yaml}.example' ($n)"
    ret=0
    dig_with_opts @10.53.0.3 +yaml "${qname}.example" TXT +qr >dig.out.test$n 2>&1 || ret=1
    $PYTHON yamlget.py dig.out.test$n 0 message query_message_data QUESTION_SECTION 0 >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "${qname}.example. IN TXT" ] || ret=1
    $PYTHON yamlget.py dig.out.test$n 1 message response_message_data ANSWER_SECTION 0 >yamlget.out.test$n 2>&1 || ret=1
    read -r value <yamlget.out.test$n
    [ "$value" = "${qname}"'.example. 300 IN TXT "a: b"' ] || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status + ret))
  done

  n=$((n + 1))
  echo_i "check yaml character values ($n)"
  ret=0
  dig_with_opts @10.53.0.3 +yaml "all.yaml.example" TXT +qr >dig.out.test$n 2>&1 || ret=1
  $PYTHON yamlget.py dig.out.test$n 1 message response_message_data ANSWER_SECTION 0 >yamlget.out.test$n 2>&1 || ret=1
  read -r value <yamlget.out.test$n
  expected='all.yaml.example. 300 IN TXT'
  expected="$expected "'"\000" "\001" "\002" "\003" "\004" "\005" "\006" "\007"'
  expected="$expected "'"\008" "\009" "\010" "\011" "\012" "\013" "\014" "\015"'
  expected="$expected "'"\016" "\017" "\018" "\019" "\020" "\021" "\022" "\023"'
  expected="$expected "'"\024" "\025" "\026" "\027" "\028" "\029" "\030" "\031"'
  expected="$expected "'" " "!" "\"" "#" "$" "%" "&" "'"'"'" "(" ")" "*" "+" ","'
  expected="$expected "'"-" "." "/" "0" "1" "2" "3" "4" "5" "6" "7" "8" "9" ":"'
  expected="$expected "'";" "<" "=" ">" "?" "@" "A" "B" "C" "D" "E" "F" "G" "H"'
  expected="$expected "'"I" "J" "K" "L" "M" "N" "O" "P" "Q" "R" "S" "T" "U" "V"'
  expected="$expected "'"W" "X" "Y" "Z" "[" "\\" "]" "^" "_" "`" "a" "b" "c" "d"'
  expected="$expected "'"e" "f" "g" "h" "i" "j" "k" "l" "m" "n" "o" "p" "q" "r"'
  expected="$expected "'"s" "t" "u" "v" "w" "x" "y" "z" "{" "|" "}" "~" "\127"'
  expected="$expected "'"\128" "\129" "\130" "\131" "\132" "\133" "\134" "\135"'
  expected="$expected "'"\136" "\137" "\138" "\139" "\140" "\141" "\142" "\143"'
  expected="$expected "'"\144" "\145" "\146" "\147" "\148" "\149" "\150" "\151"'
  expected="$expected "'"\152" "\153" "\154" "\155" "\156" "\157" "\158" "\159"'
  expected="$expected "'"\160" "\161" "\162" "\163" "\164" "\165" "\166" "\167"'
  expected="$expected "'"\168" "\169" "\170" "\171" "\172" "\173" "\174" "\175"'
  expected="$expected "'"\176" "\177" "\178" "\179" "\180" "\181" "\182" "\183"'
  expected="$expected "'"\184" "\185" "\186" "\187" "\188" "\189" "\190" "\191"'
  expected="$expected "'"\192" "\193" "\194" "\195" "\196" "\197" "\198" "\199"'
  expected="$expected "'"\200" "\201" "\202" "\203" "\204" "\205" "\206" "\207"'
  expected="$expected "'"\208" "\209" "\210" "\211" "\212" "\213" "\214" "\215"'
  expected="$expected "'"\216" "\217" "\218" "\219" "\220" "\221" "\222" "\223"'
  expected="$expected "'"\224" "\225" "\226" "\227" "\228" "\229" "\230" "\231"'
  expected="$expected "'"\232" "\233" "\234" "\235" "\236" "\237" "\238" "\239"'
  expected="$expected "'"\240" "\241" "\242" "\243" "\244" "\245" "\246" "\247"'
  expected="$expected "'"\248" "\249" "\250" "\251" "\252" "\253" "\254" "\255"'
  [ "$value" = "$expected" ] || ret=1
  if [ $ret -ne 0 ]; then echo_i "failed"; fi
  status=$((status + ret))
fi

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
