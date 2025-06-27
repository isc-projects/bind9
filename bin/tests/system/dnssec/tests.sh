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

rm -f dig.out.*

dig_with_opts() {
  "$DIG" +tcp +noadd +nosea +nostat +nocmd +dnssec -p "$PORT" "$@"
}

dig_with_answeropts() {
  "$DIG" +noall +answer +dnssec -p "$PORT" "$@"
}

delv_with_opts() {
  "$DELV" -a ns1/trusted.conf -p "$PORT" "$@"
}

rndccmd() {
  "$RNDC" -c ../_common/rndc.conf -p "$CONTROLPORT" -s "$@"
}

# TODO: Move loadkeys_on to conf.sh.common
dnssec_loadkeys_on() {
  nsidx=$1
  zone=$2
  nextpart ns${nsidx}/named.run >/dev/null
  rndccmd 10.53.0.${nsidx} loadkeys ${zone} | sed "s/^/ns${nsidx} /" | cat_i
  wait_for_log 20 "next key event" ns${nsidx}/named.run || return 1
}

# convert private-type records to readable form
showprivate() {
  echo "-- $* --"
  dig_with_opts +nodnssec +short "@$2" -t type65534 "$1" >dig.out.$1.test$n
  cut -f3 -d' ' <dig.out.$1.$n | while read -r record; do
    # shellcheck disable=SC2016
    $PERL -e 'my $rdata = pack("H*", @ARGV[0]);
              die "invalid record" unless length($rdata) == 5 || length($rdata) == 7;
              my ($dns, $key, $remove, $complete, $alg) = unpack("CnCCn", $rdata);
              die "invalid record" unless $dns != 0;
              my $action = "signing";
              $action = "removing" if $remove;
              my $state = " (incomplete)";
              $state = " (complete)" if $complete;
              $alg = $dns if ! defined($alg);
              print ("$action: alg: $alg, key: $key$state\n");' "$record"
  done
}

# check that signing records are marked as complete
checkprivate() {
  for i in 1 2 3 4 5 6 7 8 9 10; do
    showprivate "$@" | grep -q incomplete || return 0
    sleep 1
  done
  echo_d "$1 signing incomplete"
  return 1
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

# Run a minimal update test if possible.  This is really just
# a regression test for RT #2399; more tests should be added.

if $PERL -e 'use Net::DNS;' 2>/dev/null; then
  echo_i "running DNSSEC update test"
  ret=0
  {
    output=$($PERL dnssec_update_test.pl -s 10.53.0.3 -p "$PORT" dynamic.example.)
    rc=$?
  } || true
  test "$rc" -eq 0 || ret=1
  echo "$output" | cat_i
  [ $ret -eq 1 ] && status=1
else
  echo_i "The DNSSEC update test requires the Net::DNS library." >&2
fi

echo_i "checking that the NSEC3 record for the apex is properly signed when a DNSKEY is added via UPDATE ($n)"
ret=0
(
  kskname=$($KEYGEN -q -3 -a $DEFAULT_ALGORITHM -fk update-nsec3.example)
  (
    echo zone update-nsec3.example
    echo server 10.53.0.3 "$PORT"
    grep DNSKEY "${kskname}.key" | sed -e 's/^/update add /' -e 's/IN/300 IN/'
    echo send
  ) | $NSUPDATE
)
dig_with_opts +dnssec a update-nsec3.example. @10.53.0.4 >dig.out.ns4.test$n || ret=1
grep "NOERROR" dig.out.ns4.test$n >/dev/null || ret=1
grep "flags:.* ad[ ;]" dig.out.ns4.test$n >/dev/null || ret=1
grep "NSEC3 1 0 0 - .*" dig.out.ns4.test$n >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking that signing records have been marked as complete ($n)"
ret=0
checkprivate dynamic.example 10.53.0.3 || ret=1
checkprivate auto-nsec3.example 10.53.0.3 || ret=1
checkprivate expiring.example 10.53.0.3 || ret=1
checkprivate auto-nsec.example 10.53.0.3 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that 'rndc signing' without arguments is handled ($n)"
ret=0
rndccmd 10.53.0.3 signing >/dev/null 2>&1 && ret=1
rndccmd 10.53.0.3 status >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that 'rndc signing -list' without zone is handled ($n)"
ret=0
rndccmd 10.53.0.3 signing -list >/dev/null 2>&1 && ret=1
rndccmd 10.53.0.3 status >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that 'rndc signing -clear' without additional arguments is handled ($n)"
ret=0
rndccmd 10.53.0.3 signing -clear >/dev/null 2>&1 && ret=1
rndccmd 10.53.0.3 status >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that 'rndc signing -clear all' without zone is handled ($n)"
ret=0
rndccmd 10.53.0.3 signing -clear all >/dev/null 2>&1 && ret=1
rndccmd 10.53.0.3 status >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check rndc signing -list output ($n)"
ret=0
{ rndccmd 10.53.0.3 signing -list dynamic.example >signing.out.dynamic.example; } 2>&1
grep -q "No signing records found" signing.out.dynamic.example || {
  ret=1
  sed 's/^/ns3 /' signing.out.dynamic.example | cat_i
}
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that a split dnssec dnssec-signzone work ($n)"
ret=0
dig_with_opts soa split-dnssec.example. @10.53.0.4 >dig.out.ns4.test$n || ret=1
grep "NOERROR" dig.out.ns4.test$n >/dev/null || ret=1
grep "ANSWER: 2," dig.out.ns4.test$n >/dev/null || ret=1
grep "flags:.* ad[ ;]" dig.out.ns4.test$n >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that a smart split dnssec dnssec-signzone work ($n)"
ret=0
dig_with_opts soa split-smart.example. @10.53.0.4 >dig.out.ns4.test$n || ret=1
grep "NOERROR" dig.out.ns4.test$n >/dev/null || ret=1
grep "ANSWER: 2," dig.out.ns4.test$n >/dev/null || ret=1
grep "flags:.* ad[ ;]" dig.out.ns4.test$n >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "testing soon-to-expire RRSIGs without a replacement private key ($n)"
ret=0
dig_with_answeropts +nottlid expiring.example ns @10.53.0.3 | grep RRSIG >dig.out.ns3.test$n 2>&1
# there must be a signature here
[ -s dig.out.ns3.test$n ] || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that named doesn't loop when all private keys are not available ($n)"
ret=0
lines=$(grep -c "reading private key file expiring.example" ns3/named.run || true)
test "${lines:-1000}" -lt 15 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check the correct resigning time is reported in zonestatus ($n)"
ret=0
rndccmd 10.53.0.3 \
  zonestatus secure.example >rndc.out.ns3.test$n
# next resign node: secure.example/DNSKEY
qname=$(awk '/next resign node:/ { print $4 }' rndc.out.ns3.test$n | sed 's,/.*,,')
qtype=$(awk '/next resign node:/ { print $4 }' rndc.out.ns3.test$n | sed 's,.*/,,')
# next resign time: Thu, 24 Apr 2014 10:38:16 GMT
time=$(awk 'BEGIN { m["Jan"] = "01"; m["Feb"] = "02"; m["Mar"] = "03";
		   m["Apr"] = "04"; m["May"] = "05"; m["Jun"] = "06";
		   m["Jul"] = "07"; m["Aug"] = "08"; m["Sep"] = "09";
		   m["Oct"] = "10"; m["Nov"] = "11"; m["Dec"] = "12";}
	 /next resign time:/ { printf "%d%s%02d%s\n", $7, m[$6], $5, $8 }' rndc.out.ns3.test$n | sed 's/://g')
dig_with_opts +noall +answer "$qname" "$qtype" @10.53.0.3 >dig.out.test$n
expire=$(awk '$4 == "RRSIG" { print $9 }' dig.out.test$n)
inception=$(awk '$4 == "RRSIG" { print $10 }' dig.out.test$n)
$PERL -e 'exit(0) if ("'"$time"'" lt "'"$expire"'" && "'"$time"'" gt "'"$inception"'"); exit(1);' || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that CDS records are signed using KSK by dnssec-signzone ($n)"
ret=0
dig_with_opts +noall +answer @10.53.0.2 cds cds.secure >dig.out.test$n
lines=$(awk '$4 == "RRSIG" && $5 == "CDS" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 2 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that CDS records are not signed using ZSK by dnssec-signzone -x ($n)"
ret=0
dig_with_opts +noall +answer @10.53.0.2 cds cds-x.secure >dig.out.test$n
lines=$(awk '$4 == "RRSIG" && $5 == "CDS" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 2 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that CDS records are signed using KSK by with dnssec-policy ($n)"
ret=0
dig_with_opts +noall +answer @10.53.0.2 cds cds-auto.secure >dig.out.test$n
lines=$(awk '$4 == "RRSIG" && $5 == "CDS" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that a CDS deletion record is accepted ($n)"
ret=0
(
  echo zone cds-update.secure
  echo server 10.53.0.2 "$PORT"
  echo update delete cds-update.secure CDS
  echo update add cds-update.secure 0 CDS 0 0 0 00
  echo send
) | $NSUPDATE >nsupdate.out.test$n 2>&1
dig_with_opts +noall +answer @10.53.0.2 cds cds-update.secure >dig.out.test$n
lines=$(awk '$4 == "CDS" {print}' dig.out.test$n | wc -l)
test "${lines:-10}" -eq 1 || ret=1
lines=$(awk '$4 == "CDS" && $5 == "0" && $6 == "0" && $7 == "0" && $8 == "00" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that CDS records are signed only using KSK when added by nsupdate ($n)"
ret=0
keyid=$(cat ns2/cds-update.secure.id)
(
  echo zone cds-update.secure
  echo server 10.53.0.2 "$PORT"
  echo update delete cds-update.secure CDS
  echo send
  dig_with_opts +noall +answer @10.53.0.2 dnskey cds-update.secure \
    | grep "DNSKEY.257" \
    | $DSFROMKEY -12 -C -f - -T 1 cds-update.secure \
    | sed "s/^/update add /"
  echo send
) | $NSUPDATE
dig_with_opts +noall +answer @10.53.0.2 cds cds-update.secure >dig.out.test$n
lines=$(awk '$4 == "RRSIG" && $5 == "CDS" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
lines=$(awk -v id="${keyid}" '$4 == "RRSIG" && $5 == "CDS" && $11 == id {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
lines=$(awk '$4 == "CDS" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 2 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that CDS deletion records are signed only using KSK when added by nsupdate ($n)"
ret=0
keyid=$(cat ns2/cds-update.secure.id)
(
  echo zone cds-update.secure
  echo server 10.53.0.2 "$PORT"
  echo update delete cds-update.secure CDS
  echo update add cds-update.secure 0 CDS 0 0 0 00
  echo send
) | $NSUPDATE
dig_with_opts +noall +answer @10.53.0.2 cds cds-update.secure >dig.out.test$n
lines=$(awk '$4 == "RRSIG" && $5 == "CDS" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
lines=$(awk -v id="${keyid}" '$4 == "RRSIG" && $5 == "CDS" && $11 == id {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
lines=$(awk '$4 == "CDS" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
lines=$(awk '$4 == "CDS" && $5 == "0" && $6 == "0" && $7 == "0" && $8 == "00" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that a non matching CDS record is accepted with a matching CDS record ($n)"
ret=0
(
  echo zone cds-update.secure
  echo server 10.53.0.2 "$PORT"
  echo update delete cds-update.secure CDS
  echo send
  dig_with_opts +noall +answer @10.53.0.2 dnskey cds-update.secure \
    | grep "DNSKEY.257" \
    | $DSFROMKEY -12 -C -f - -T 1 cds-update.secure \
    | sed "s/^/update add /"
  dig_with_opts +noall +answer @10.53.0.2 dnskey cds-update.secure \
    | grep "DNSKEY.257" | sed 's/DNSKEY.257/DNSKEY 258/' \
    | $DSFROMKEY -12 -C -A -f - -T 1 cds-update.secure \
    | sed "s/^/update add /"
  echo send
) | $NSUPDATE
dig_with_opts +noall +answer @10.53.0.2 cds cds-update.secure >dig.out.test$n
lines=$(awk '$4 == "RRSIG" && $5 == "CDS" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
lines=$(awk '$4 == "CDS" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 4 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that CDNSKEY records are signed using KSK by dnssec-signzone ($n)"
ret=0
dig_with_opts +noall +answer @10.53.0.2 cdnskey cdnskey.secure >dig.out.test$n
lines=$(awk '$4 == "RRSIG" && $5 == "CDNSKEY" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 2 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that CDNSKEY records are not signed using ZSK by dnssec-signzone -x ($n)"
ret=0
dig_with_opts +noall +answer @10.53.0.2 cdnskey cdnskey-x.secure >dig.out.test$n
lines=$(awk '$4 == "RRSIG" && $5 == "CDNSKEY" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 2 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that CDNSKEY records are signed using KSK by with dnssec-auto ($n)"
ret=0
dig_with_opts +noall +answer @10.53.0.2 cdnskey cdnskey-auto.secure >dig.out.test$n
lines=$(awk '$4 == "RRSIG" && $5 == "CDNSKEY" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# TODO: test case for GL #1689.
# If we allow the dnssec tools to use deprecated algorithms (such as RSAMD5)
# we could write a test that signs a zone with supported and unsupported
# algorithm, apply a fixed rrset order such that the unsupported algorithm
# precedes the supported one in the DNSKEY RRset, and verify the result still
# validates succesfully.

echo_i "check that a CDNSKEY deletion record is accepted ($n)"
ret=0
(
  echo zone cdnskey-update.secure
  echo server 10.53.0.2 "$PORT"
  echo update delete cdnskey-update.secure CDNSKEY
  echo update add cdnskey-update.secure 0 CDNSKEY 0 3 0 AA==
  echo send
) | $NSUPDATE >nsupdate.out.test$n 2>&1
dig_with_opts +noall +answer @10.53.0.2 cdnskey cdnskey-update.secure >dig.out.test$n
lines=$(awk '$4 == "CDNSKEY" {print}' dig.out.test$n | wc -l)
test "${lines:-10}" -eq 1 || ret=1
lines=$(awk '$4 == "CDNSKEY" && $5 == "0" && $6 == "3" && $7 == "0" && $8 == "AA==" {print}' dig.out.test$n | wc -l)
test "${lines:-10}" -eq 1 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that CDNSKEY records are signed using KSK only when added by nsupdate ($n)"
ret=0
keyid=$(cat ns2/cdnskey-update.secure.id)
(
  echo zone cdnskey-update.secure
  echo server 10.53.0.2 "$PORT"
  echo update delete cdnskey-update.secure CDNSKEY
  dig_with_opts +noall +answer @10.53.0.2 dnskey cdnskey-update.secure \
    | sed -n -e "s/^/update add /" -e 's/DNSKEY.257/CDNSKEY 257/p'
  echo send
) | $NSUPDATE
dig_with_opts +noall +answer @10.53.0.2 cdnskey cdnskey-update.secure >dig.out.test$n
lines=$(awk '$4 == "RRSIG" && $5 == "CDNSKEY" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
lines=$(awk -v id="${keyid}" '$4 == "RRSIG" && $5 == "CDNSKEY" && $11 == id {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
lines=$(awk '$4 == "CDNSKEY" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that a non matching CDNSKEY record is accepted with a matching CDNSKEY record ($n)"
ret=0
(
  echo zone cdnskey-update.secure
  echo server 10.53.0.2 "$PORT"
  echo update delete cdnskey-update.secure CDNSKEY
  dig_with_opts +noall +answer @10.53.0.2 dnskey cdnskey-update.secure \
    | sed -n -e "s/^/update add /" -e 's/DNSKEY.257/CDNSKEY 257/p'
  dig_with_opts +noall +answer @10.53.0.2 dnskey cdnskey-update.secure \
    | sed -n -e "s/^/update add /" -e 's/DNSKEY.257/CDNSKEY 258/p'
  echo send
) | $NSUPDATE
dig_with_opts +noall +answer @10.53.0.2 cdnskey cdnskey-update.secure >dig.out.test$n
lines=$(awk '$4 == "RRSIG" && $5 == "CDNSKEY" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
lines=$(awk '$4 == "CDNSKEY" {print}' dig.out.test$n | wc -l)
test "$lines" -eq 2 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that DNAME at apex with NSEC3 is correctly signed (dnssec-signzone) ($n)"
ret=0
dig_with_opts txt dname-at-apex-nsec3.example @10.53.0.3 >dig.out.ns3.test$n || ret=1
grep "RRSIG.NSEC3 $DEFAULT_ALGORITHM_NUMBER 3 600" dig.out.ns3.test$n >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that DNSKEY and other occluded data are excluded from the delegating bitmap ($n)"
ret=0
dig_with_opts axfr occluded.example @10.53.0.3 >dig.out.ns3.test$n || ret=1
grep "^delegation.occluded.example..*NSEC.*NS KEY DS RRSIG NSEC$" dig.out.ns3.test$n >/dev/null || ret=1
grep "^delegation.occluded.example..*DNSKEY.*" dig.out.ns3.test$n >/dev/null || ret=1
grep "^delegation.occluded.example..*AAAA.*" dig.out.ns3.test$n >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking DNSSEC records are occluded from ANY in an insecure zone ($n)"
ret=0
dig_with_opts any x.insecure.example. @10.53.0.3 >dig.out.ns3.1.test$n || ret=1
grep "status: NOERROR" dig.out.ns3.1.test$n >/dev/null || ret=1
grep "ANSWER: 0," dig.out.ns3.1.test$n >/dev/null || ret=1
dig_with_opts any z.secure.example. @10.53.0.3 >dig.out.ns3.2.test$n || ret=1
grep "status: NOERROR" dig.out.ns3.2.test$n >/dev/null || ret=1
# A+RRSIG, NSEC+RRSIG
grep "ANSWER: 4," dig.out.ns3.2.test$n >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

###
### Additional checks for when the KSK is offline.
###

# Save some useful information
zone="updatecheck-kskonly.secure"
KSK=$(cat ns2/${zone}.ksk.key)
ZSK=$(cat ns2/${zone}.zsk.key)
KSK_ID=$(cat ns2/${zone}.ksk.id)
ZSK_ID=$(cat ns2/${zone}.zsk.id)
SECTIONS="+answer +noauthority +noadditional"
echo_i "testing zone $zone KSK=$KSK_ID ZSK=$ZSK_ID"

# Set key state for KSK. The ZSK rollovers below assume that there is a chain
# of trust established, so we tell named that the DS is in omnipresent state.
$SETTIME -s -d OMNIPRESENT now -K ns2 $KSK >/dev/null

# Print IDs of keys used for generating RRSIG records for RRsets of type $1
# found in dig output file $2.
get_keys_which_signed() {
  qtype=$1
  output=$2
  # The key ID is the 11th column of the RRSIG record line.
  awk -v qt="$qtype" '$4 == "RRSIG" && $5 == qt {print $11}' <"$output"
}

# Basic checks to make sure everything is fine before the KSK is made offline.
for qtype in "DNSKEY" "CDNSKEY" "CDS"; do
  echo_i "checking $qtype RRset is signed with KSK only ($n)"
  ret=0
  dig_with_opts $SECTIONS @10.53.0.2 $qtype $zone >dig.out.test$n
  lines=$(get_keys_which_signed $qtype dig.out.test$n | wc -l)
  test "$lines" -eq 1 || ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$KSK_ID$" >/dev/null || ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID$" >/dev/null && ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
done

echo_i "checking SOA RRset is signed with ZSK only ($n)"
ret=0
dig_with_opts $SECTIONS @10.53.0.2 soa $zone >dig.out.test$n
lines=$(get_keys_which_signed "SOA" dig.out.test$n | wc -l)
test "$lines" -eq 1 || ret=1
get_keys_which_signed "SOA" dig.out.test$n | grep "^$KSK_ID$" >/dev/null && ret=1
get_keys_which_signed "SOA" dig.out.test$n | grep "^$ZSK_ID$" >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Roll the ZSK.
zsk2=$("$KEYGEN" -q -P none -A none -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -K ns2 "$zone")
keyfile_to_key_id "$zsk2" >ns2/$zone.zsk.id2
ZSK_ID2=$(cat ns2/$zone.zsk.id2)
ret=0
echo_i "prepublish new ZSK $ZSK_ID2 for $zone ($n)"
rndccmd 10.53.0.2 dnssec -rollover -key $ZSK_ID $zone 2>&1 | sed 's/^/ns2 /' | cat_i
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

zsk_count_equals() {
  expectedzsks=$1
  dig_with_opts @10.53.0.2 DNSKEY $zone >dig.out.test$n
  lines=$(cat dig.out.test$n | grep "DNSKEY.*256 3 13" | wc -l)
  test "$lines" -eq $expectedzsks || return 1
}
echo_i "check DNSKEY RRset has successor ZSK $ZSK_ID2 ($n)"
ret=0
# The expected number of ZSKs is 2.
retry_quiet 5 zsk_count_equals 2 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Make new ZSK active.
echo_i "make ZSK $ZSK_ID inactive and make new ZSK $ZSK_ID2 active for zone $zone ($n)"
ret=0
$SETTIME -s -I now -K ns2 $ZSK >/dev/null
$SETTIME -s -k OMNIPRESENT now -A now -K ns2 $zsk2 >/dev/null
dnssec_loadkeys_on 2 $zone || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Wait for newest ZSK to become active.
echo_i "wait until new ZSK $ZSK_ID2 active and ZSK $ZSK_ID inactive"
for i in 1 2 3 4 5 6 7 8 9 10; do
  ret=0
  grep "DNSKEY $zone/$DEFAULT_ALGORITHM/$ZSK_ID2 (ZSK) is now active" ns2/named.run >/dev/null || ret=1
  grep "DNSKEY $zone/$DEFAULT_ALGORITHM/$ZSK_ID (ZSK) is now inactive" ns2/named.run >/dev/null || ret=1
  [ "$ret" -eq 0 ] && break
  sleep 1
done
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Remove the KSK from disk.
echo_i "remove the KSK $KSK_ID for zone $zone from disk"
mv ns2/$KSK.key ns2/$KSK.key.bak
mv ns2/$KSK.private ns2/$KSK.private.bak

# Update the zone that requires a resign of the SOA RRset.
echo_i "update the zone with $zone IN TXT nsupdate added me"
(
  echo zone $zone
  echo server 10.53.0.2 "$PORT"
  echo update add $zone. 300 in txt "nsupdate added me"
  echo send
) | $NSUPDATE

# Redo the tests now that the zone is updated and the KSK is offline.
for qtype in "DNSKEY" "CDNSKEY" "CDS"; do
  echo_i "checking $qtype RRset is signed with KSK only, KSK offline ($n)"
  ret=0
  dig_with_opts $SECTIONS @10.53.0.2 $qtype $zone >dig.out.test$n
  lines=$(get_keys_which_signed $qtype dig.out.test$n | wc -l)
  test "$lines" -eq 1 || ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$KSK_ID$" >/dev/null || ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID$" >/dev/null && ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID2$" >/dev/null && ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
done

for qtype in "SOA" "TXT"; do
  echo_i "checking $qtype RRset is signed with new ZSK $ZSK_ID2 only, KSK offline ($n)"
  ret=0
  dig_with_opts $SECTIONS @10.53.0.2 $qtype $zone >dig.out.test$n
  lines=$(get_keys_which_signed $qtype dig.out.test$n | wc -l)
  test "$lines" -eq 1 || ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$KSK_ID$" >/dev/null && ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID$" >/dev/null && ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID2$" >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
done

# Put back the KSK.
echo_i "put back the KSK $KSK_ID for zone $zone from disk"
mv ns2/$KSK.key.bak ns2/$KSK.key
mv ns2/$KSK.private.bak ns2/$KSK.private

# Roll the ZSK again.
zsk3=$("$KEYGEN" -q -P none -A none -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -K ns2 "$zone")
ret=0
keyfile_to_key_id "$zsk3" >ns2/$zone.zsk.id3
ZSK_ID3=$(cat ns2/$zone.zsk.id3)
echo_i "delete old ZSK $ZSK_ID, schedule ZSK $ZSK_ID2 inactive, and pre-publish ZSK $ZSK_ID3 for zone $zone ($n)"
$SETTIME -s -k HIDDEN now -z HIDDEN now -D now -K ns2 $ZSK >/dev/null
$SETTIME -s -k OMNIPRESENT now -z OMNIPRESENT now -K ns2 $zsk2 >/dev/null
dnssec_loadkeys_on 2 $zone || ret=1
rndccmd 10.53.0.2 dnssec -rollover -key $ZSK_ID2 $zone 2>&1 | sed 's/^/ns2 /' | cat_i
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Wait for newest ZSK to become published.
echo_i "wait until new ZSK $ZSK_ID3 published"
for i in 1 2 3 4 5 6 7 8 9 10; do
  ret=0
  grep "DNSKEY $zone/$DEFAULT_ALGORITHM/$ZSK_ID3 (ZSK) is now published" ns2/named.run >/dev/null || ret=1
  [ "$ret" -eq 0 ] && break
  sleep 1
done
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Remove the KSK from disk.
echo_i "remove the KSK $KSK_ID for zone $zone from disk"
mv ns2/$KSK.key ns2/$KSK.key.bak
mv ns2/$KSK.private ns2/$KSK.private.bak

# Update the zone that requires a resign of the SOA RRset.
echo_i "update the zone with $zone IN TXT nsupdate added me again"
(
  echo zone $zone
  echo server 10.53.0.2 "$PORT"
  echo update add $zone. 300 in txt "nsupdate added me again"
  echo send
) | $NSUPDATE

# Redo the tests now that the ZSK roll has deleted the old key.
for qtype in "DNSKEY" "CDNSKEY" "CDS"; do
  echo_i "checking $qtype RRset is signed with KSK only, old ZSK deleted ($n)"
  ret=0
  dig_with_opts $SECTIONS @10.53.0.2 $qtype $zone >dig.out.test$n
  lines=$(get_keys_which_signed $qtype dig.out.test$n | wc -l)
  test "$lines" -eq 1 || ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$KSK_ID$" >/dev/null || ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID$" >/dev/null && ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID2$" >/dev/null && ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID3$" >/dev/null && ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
done

for qtype in "SOA" "TXT"; do
  echo_i "checking $qtype RRset is signed with ZSK $ZSK_ID2 only, old ZSK deleted ($n)"
  ret=0
  dig_with_opts $SECTIONS @10.53.0.2 $qtype $zone >dig.out.test$n
  lines=$(get_keys_which_signed $qtype dig.out.test$n | wc -l)
  test "$lines" -eq 1 || ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$KSK_ID$" >/dev/null && ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID$" >/dev/null && ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID2$" >/dev/null || ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID3$" >/dev/null && ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
done

# Put back the KSK.
echo_i "put back the KSK $KSK_ID for zone $zone from disk"
mv ns2/$KSK.key.bak ns2/$KSK.key
mv ns2/$KSK.private.bak ns2/$KSK.private

# Make the new ZSK (ZSK3) active.
echo_i "make new ZSK $ZSK_ID3 active for zone $zone ($n)"
ret=0
$SETTIME -s -I now -K ns2 $zsk2 >/dev/null
$SETTIME -s -k OMNIPRESENT now -A now -K ns2 $zsk3 >/dev/null
dnssec_loadkeys_on 2 $zone || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Wait for newest ZSK to become active.
echo_i "wait until new ZSK $ZSK_ID3 active and ZSK $ZSK_ID2 inactive"
for i in 1 2 3 4 5 6 7 8 9 10; do
  ret=0
  grep "DNSKEY $zone/$DEFAULT_ALGORITHM/$ZSK_ID3 (ZSK) is now active" ns2/named.run >/dev/null || ret=1
  grep "DNSKEY $zone/$DEFAULT_ALGORITHM/$ZSK_ID2 (ZSK) is now inactive" ns2/named.run >/dev/null || ret=1
  [ "$ret" -eq 0 ] && break
  sleep 1
done
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Remove the KSK from disk.
echo_i "remove the KSK $KSK_ID for zone $zone from disk"
mv ns2/$KSK.key ns2/$KSK.key.bak
mv ns2/$KSK.private ns2/$KSK.private.bak

# Update the zone that requires a resign of the SOA RRset.
echo_i "update the zone with $zone IN TXT nsupdate added me one more time"
(
  echo zone $zone
  echo server 10.53.0.2 "$PORT"
  echo update add $zone. 300 in txt "nsupdate added me one more time"
  echo send
) | $NSUPDATE
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Redo the tests one more time.
for qtype in "DNSKEY" "CDNSKEY" "CDS"; do
  echo_i "checking $qtype RRset is signed with KSK only, new ZSK active ($n)"
  ret=0
  dig_with_opts $SECTIONS @10.53.0.2 $qtype $zone >dig.out.test$n
  lines=$(get_keys_which_signed $qtype dig.out.test$n | wc -l)
  test "$lines" -eq 1 || ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$KSK_ID$" >/dev/null || ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID$" >/dev/null && ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID2$" >/dev/null && ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID3$" >/dev/null && ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
done

for qtype in "SOA" "TXT"; do
  echo_i "checking $qtype RRset is signed with new ZSK $ZSK_ID3 only, new ZSK active ($n)"
  ret=0
  dig_with_opts $SECTIONS @10.53.0.2 $qtype $zone >dig.out.test$n
  lines=$(get_keys_which_signed $qtype dig.out.test$n | wc -l)
  test "$lines" -eq 1 || ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$KSK_ID$" >/dev/null && ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID$" >/dev/null && ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID2$" >/dev/null && ret=1
  get_keys_which_signed $qtype dig.out.test$n | grep "^$ZSK_ID3$" >/dev/null || ret=1
  n=$((n + 1))
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
done

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
