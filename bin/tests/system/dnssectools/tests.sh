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

# check that a zone file is raw format, version 0
israw0() {
  # shellcheck disable=SC2016
  $PERL <"$1" -e 'binmode STDIN;
	             read(STDIN, $input, 8);
	             ($style, $version) = unpack("NN", $input);
	             exit 1 if ($style != 2 || $version != 0);' || return $?
}

# check that a zone file is raw format, version 1
israw1() {
  # shellcheck disable=SC2016
  $PERL <"$1" -e 'binmode STDIN;
		     read(STDIN, $input, 8);
                     ($style, $version) = unpack("NN", $input);
                     exit 1 if ($style != 2 || $version != 1);' || return $?
}

echo_i "basic dnssec-signzone checks:"
echo_ic "two DNSKEYs ($n)"
ret=0
(
  cd signer/general || exit 1
  rm -f signed.zone
  $SIGNER -f signed.zone -o example.com. test1.zone >signer.out.$n
  test -f signed.zone
) || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "two DNSKEYs, DNSKEY RRset only by KSK ($n)"
ret=0
(
  cd signer/general || exit 1
  rm -f signed.zone
  $SIGNER -s now-1mo -e now+2d -P -x -f signed.zone -O full -o example.com. test1.zone >signer.out.$n
  test -f signed.zone
) || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "two DNSKEYs, DNSKEY RRset only by KSK, private key missing ($n)"
ret=0
(
  cd signer/general || exit 1
  cp signed.zone signed.expect
  grep "example\.com\..*3600.*IN.*RRSIG.*DNSKEY.*10.*2.*3600.*28633.*example\.com\." signed.expect >dnskey.expect || exit 1
  mv Kexample.com.+010+28633.private Kexample.com.+010+28633.offline
  $SIGNER -P -x -f signed.zone -O full -o example.com. signed.zone >signer.out.$n 2>/dev/null
  mv Kexample.com.+010+28633.offline Kexample.com.+010+28633.private
  grep "$(cat dnskey.expect)" signed.zone >/dev/null || exit 1
) || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "one non-KSK DNSKEY ($n)"
ret=0
(
  cd signer/general || exit 0
  rm -f signed.zone
  $SIGNER -f signed.zone -o example.com. test2.zone >signer.out.$n
  test -f signed.zone
) && ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "one KSK DNSKEY ($n)"
ret=0
(
  cd signer/general || exit 0
  rm -f signed.zone
  $SIGNER -f signed.zone -o example.com. test3.zone >signer.out.$n 2>/dev/null
  test -f signed.zone
) && ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "three DNSKEY ($n)"
ret=0
(
  cd signer/general || exit 1
  rm -f signed.zone
  $SIGNER -f signed.zone -o example.com. test4.zone >signer.out.$n 2>/dev/null
  test -f signed.zone
) || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "three DNSKEY, one private key missing ($n)"
ret=0
(
  cd signer/general || exit 1
  rm -f signed.zone
  $SIGNER -f signed.zone -o example.com. test5.zone >signer.out.$n 2>/dev/null
  test -f signed.zone
) || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "four DNSKEY ($n)"
ret=0
(
  cd signer/general || exit 1
  rm -f signed.zone
  $SIGNER -f signed.zone -o example.com. test6.zone >signer.out.$n 2>/dev/null
  test -f signed.zone
) || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "two DNSKEY, both private keys missing ($n)"
ret=0
(
  cd signer/general || exit 0
  rm -f signed.zone
  $SIGNER -f signed.zone -o example.com. test7.zone >signer.out.$n 2>/dev/null
  test -f signed.zone
) && ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "two DNSKEY, one private key missing ($n)"
ret=0
(
  cd signer/general || exit 0
  rm -f signed.zone
  $SIGNER -f signed.zone -o example.com. test8.zone >signer.out.$n 2>/dev/null
  test -f signed.zone
) && ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "check that 'dnssec-signzone -F' works with allowed algorithm ($n)"
ret=0
if $FEATURETEST --fips-provider; then
  (
    cd signer/general || exit 1
    rm -f signed.zone
    $SIGNER -F -f signed.zone -o example.com. test1.zone >signer.out.$n
    test -f signed.zone
  ) || ret=1
else
  echo_i "skipped no FIPS provider available"
fi
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "check that 'dnssec-signzone -F' failed with disallowed algorithm ($n)"
ret=0
if ! $FEATURETEST --fips-provider; then
  echo_i "skipped no FIPS provider available"
elif [ $RSASHA1_SUPPORTED = 0 ]; then
  echo_i "skipped: RSASHA1 is not supported"
else
  (
    cd signer/general || exit 1
    rm -f signed.zone
    $SIGNER -F -f signed.zone -o example.com. test11.zone >signer.out.$n 2>&1 && exit 1
    grep -F -e "fatal: No signing keys specified or found" \
      -e "fatal: dnskey 'example.com/RSASHA1/19857' failed to sign data" signer.out.$n >/dev/null
  ) || ret=1
fi
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "revoked KSK ID collides with ZSK ($n)"
ret=0
# signing should fail, but should not coredump
(
  cd signer/general || exit 0
  rm -f signed.zone
  $SIGNER -S -f signed.zone -o . test12.zone >signer.out.$n 2>/dev/null
) && ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "check that dnssec-signzone rejects excessive NSEC3 iterations ($n)"
ret=0
(
  cd signer/general || exit 0
  rm -f signed.zone
  $SIGNER -f signed.zone -3 - -H 51 -o example.com. test9.zone >signer.out.$n
  test -f signed.zone
) && ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "check that dnssec-signzone -J loads journal files ($n)"
ret=0
(
  cd signer/general || exit 0
  rm -f signed.zone
  $MAKEJOURNAL example.com. test9.zone test10.zone test9.zone.jnl
  $SIGNER -f signed.zone -o example.com. -J test9.zone.jnl test9.zone >signer.out.$n
  grep -q extra signed.zone
) || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_ic "check that dnssec-signzone accepts maximum NSEC3 iterations ($n)"
ret=0
(
  cd signer/general || exit 1
  rm -f signed.zone
  $SIGNER -f signed.zone -3 - -H 50 -o example.com. test9.zone >signer.out.$n
  test -f signed.zone
) || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

get_default_algorithm_key_ids_from_sigs() {
  zone=$1

  awk -v alg=$DEFAULT_ALGORITHM_NUMBER '
		NF < 8 { next }
		$(NF-5) != "RRSIG" { next }
		$(NF-3) != alg { next }
		$NF != "(" { next }
		{
			getline;
			print $3;
		}
	' signer/$zone.db.signed | sort -u
}

# Test dnssec-signzone ZSK prepublish smooth rollover.
echo_i "check dnssec-signzone doesn't sign with prepublished zsk ($n)"
ret=0
zone=prepub
# Generate keys.
ksk=$("$KEYGEN" -K signer -f KSK -q -a $DEFAULT_ALGORITHM "$zone")
zsk1=$("$KEYGEN" -K signer -q -a $DEFAULT_ALGORITHM "$zone")
zsk2=$("$KEYGEN" -K signer -q -a $DEFAULT_ALGORITHM "$zone")
zskid1=$(keyfile_to_key_id "$zsk1")
zskid2=$(keyfile_to_key_id "$zsk2")
(
  cd signer || exit 1
  # Set times such that the current set of keys are introduced 60 days ago and
  # start signing now. The successor key is prepublished now and will be active
  # next day.
  $SETTIME -P now-60d -A now $ksk >/dev/null
  $SETTIME -P now-60d -A now -I now+1d -D now+60d $zsk1 >/dev/null
  $SETTIME -S $zsk1 -i 1h $zsk2.key >/dev/null
  $SETTIME -P now -A now+1d $zsk2.key >/dev/null
  # Sign the zone with initial keys and prepublish successor. The zone signatures
  # are valid for 30 days and the DNSKEY signature is valid for 60 days.
  cp -f $zone.db.in $zone.db
  $SIGNER -SDx -e +2592000 -X +5184000 -o $zone $zone.db >/dev/null
  echo "\$INCLUDE \"$zone.db.signed\"" >>$zone.db
)
get_default_algorithm_key_ids_from_sigs $zone | grep "^$zskid1$" >/dev/null || ret=1
get_default_algorithm_key_ids_from_sigs $zone | grep "^$zskid2$" >/dev/null && ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed: missing signatures from key $zskid1"
status=$((status + ret))

echo_i "check dnssec-signzone retains signatures of predecessor zsk ($n)"
ret=0
zone=prepub
(
  cd signer || exit 1
  # Roll the ZSK. The predecessor is inactive from now on and the successor is
  # activated. The zone signatures are valid for 30 days and the DNSKEY
  # signature is valid for 60 days. Because of the predecessor/successor
  # relationship, the signatures of the predecessor are retained and no new
  # signatures with the successor should be generated.
  $SETTIME -A now-30d -I now -D now+30d $zsk1 >/dev/null
  $SETTIME -A now $zsk2 >/dev/null
  $SIGNER -SDx -e +2592000 -X +5184000 -o $zone $zone.db >/dev/null
)
get_default_algorithm_key_ids_from_sigs $zone | grep "^$zskid1$" >/dev/null || ret=1
get_default_algorithm_key_ids_from_sigs $zone | grep "^$zskid2$" >/dev/null && ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check dnssec-signzone swaps zone signatures after interval ($n)"
ret=0
zone=prepub
(
  cd signer || exit 1
  # After some time the signatures should be replaced. When signing, set the
  # interval to 30 days plus one second, meaning all predecessor signatures
  # are within the refresh interval and should be replaced with successor
  # signatures.
  $SETTIME -A now-50d -I now-20d -D now+10d $zsk1 >/dev/null
  $SETTIME -A now-20d $zsk2 >/dev/null
  $SIGNER -SDx -e +2592000 -X +5184000 -i 2592001 -o $zone $zone.db >/dev/null
)
get_default_algorithm_key_ids_from_sigs $zone | grep "^$zskid1$" >/dev/null && ret=1
get_default_algorithm_key_ids_from_sigs $zone | grep "^$zskid2$" >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking that a key using an unsupported algorithm cannot be generated ($n)"
ret=0
zone=example
# If dnssec-keygen fails, the test script will exit immediately.  Prevent that
# from happening, and also trigger a test failure if dnssec-keygen unexpectedly
# succeeds, by using "&& ret=1".
$KEYGEN -a 255 $zone >dnssectools.out.test$n 2>&1 && ret=1
grep -q "unsupported algorithm: 255" dnssectools.out.test$n || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking that a DS record cannot be generated for a key using an unsupported algorithm ($n)"
ret=0
zone=example
# Fake an unsupported algorithm key
unsupportedkey=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
awk '$3 == "DNSKEY" { $6 = 255 } { print }' ${unsupportedkey}.key >${unsupportedkey}.tmp
mv ${unsupportedkey}.tmp ${unsupportedkey}.key
# If dnssec-dsfromkey fails, the test script will exit immediately.  Prevent
# that from happening, and also trigger a test failure if dnssec-dsfromkey
# unexpectedly succeeds, by using "&& ret=1".
$DSFROMKEY ${unsupportedkey} >dnssectools.out.test$n 2>&1 && ret=1
grep -q "algorithm is unsupported" dnssectools.out.test$n || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking that a zone cannot be signed with a key using an unsupported algorithm ($n)"
ret=0
ret=0
cat signer/example.db.in "${unsupportedkey}.key" >signer/example.db
# If dnssec-signzone fails, the test script will exit immediately.  Prevent that
# from happening, and also trigger a test failure if dnssec-signzone
# unexpectedly succeeds, by using "&& ret=1".
$SIGNER -o example signer/example.db ${unsupportedkey} >dnssectools.out.test$n 2>&1 && ret=1
grep -q "algorithm is unsupported" dnssectools.out.test$n || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking that we can sign a zone with out-of-zone records ($n)"
ret=0
zone=example
key1=$($KEYGEN -K signer -q -a $DEFAULT_ALGORITHM $zone)
key2=$($KEYGEN -K signer -q -f KSK -a $DEFAULT_ALGORITHM $zone)
(
  cd signer || exit 1
  cat example.db.in "$key1.key" "$key2.key" >example.db
  $SIGNER -o example -f example.db example.db >/dev/null
) || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking that we can sign a zone (NSEC3) with out-of-zone records ($n)"
ret=0
zone=example
key1=$($KEYGEN -K signer -q -a $DEFAULT_ALGORITHM $zone)
key2=$($KEYGEN -K signer -q -f KSK -a $DEFAULT_ALGORITHM $zone)
(
  cd signer || exit 1
  cat example.db.in "$key1.key" "$key2.key" >example.db
  $SIGNER -3 - -H 10 -o example -f example.db example.db >/dev/null
  awk '/^IQF9LQTLK/ {
		printf("%s", $0);
		while (!index($0, ")")) {
			if (getline <= 0)
				break;
			printf (" %s", $0);
		}
		printf("\n");
	}' example.db | sed 's/[ 	][ 	]*/ /g' >nsec3param.out

  grep "IQF9LQTLKKNFK0KVIFELRAK4IC4QLTMG.example. 0 IN NSEC3 1 0 10 - ( IQF9LQTLKKNFK0KVIFELRAK4IC4QLTMG A NS SOA RRSIG DNSKEY NSEC3PARAM )" nsec3param.out >/dev/null
) || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking NSEC3 signing with empty nonterminals above a delegation ($n)"
ret=0
zone=example
key1=$($KEYGEN -K signer -q -a $DEFAULT_ALGORITHM $zone)
key2=$($KEYGEN -K signer -q -f KSK -a $DEFAULT_ALGORITHM $zone)
(
  cd signer || exit 1
  cat example.db.in "$key1.key" "$key2.key" >example3.db
  echo "some.empty.nonterminal.nodes.example 60 IN NS ns.example.tld" >>example3.db
  $SIGNER -3 - -A -H 10 -o example -f example3.db example3.db >/dev/null
  awk '/^IQF9LQTLK/ {
		printf("%s", $0);
		while (!index($0, ")")) {
			if (getline <= 0)
				break;
			printf (" %s", $0);
		}
		printf("\n");
	}' example.db | sed 's/[ 	][ 	]*/ /g' >nsec3param.out

  grep "IQF9LQTLKKNFK0KVIFELRAK4IC4QLTMG.example. 0 IN NSEC3 1 0 10 - ( IQF9LQTLKKNFK0KVIFELRAK4IC4QLTMG A NS SOA RRSIG DNSKEY NSEC3PARAM )" nsec3param.out >/dev/null
) || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking that dnssec-signzone updates originalttl on ttl changes ($n)"
ret=0
zone=example
key1=$($KEYGEN -K signer -q -a $DEFAULT_ALGORITHM $zone)
key2=$($KEYGEN -K signer -q -f KSK -a $DEFAULT_ALGORITHM $zone)
(
  cd signer || exit 1
  cat example.db.in "$key1.key" "$key2.key" >example.db
  $SIGNER -o example -f example.db.before example.db >/dev/null
  sed 's/60.IN.SOA./50 IN SOA /' example.db.before >example.db.changed
  $SIGNER -o example -f example.db.after example.db.changed >/dev/null
)
grep "SOA $DEFAULT_ALGORITHM_NUMBER 1 50" signer/example.db.after >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone keeps valid signatures from removed keys ($n)"
ret=0
zone=example
key1=$($KEYGEN -K signer -q -f KSK -a $DEFAULT_ALGORITHM $zone)
key2=$($KEYGEN -K signer -q -a $DEFAULT_ALGORITHM $zone)
keyid2=$(keyfile_to_key_id "$key2")
key3=$($KEYGEN -K signer -q -a $DEFAULT_ALGORITHM $zone)
keyid3=$(keyfile_to_key_id "$key3")
(
  cd signer || exit 1
  cat example.db.in "$key1.key" "$key2.key" >example.db
  $SIGNER -D -o example example.db >/dev/null

  # now switch out key2 for key3 and resign the zone
  cat example.db.in "$key1.key" "$key3.key" >example.db
  echo "\$INCLUDE \"example.db.signed\"" >>example.db
  $SIGNER -D -o example example.db >/dev/null
) || ret=1
get_default_algorithm_key_ids_from_sigs $zone | grep "^$keyid2$" >/dev/null || ret=1
get_default_algorithm_key_ids_from_sigs $zone | grep "^$keyid3$" >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -R purges signatures from removed keys ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -RD -o example example.db >/dev/null
) || ret=1
get_default_algorithm_key_ids_from_sigs $zone | grep "^$keyid2$" >/dev/null && ret=1
get_default_algorithm_key_ids_from_sigs $zone | grep "^$keyid3$" >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone keeps valid signatures from inactive keys ($n)"
ret=0
zone=example
(
  cd signer || exit 1
  cp -f example.db.in example.db
  $SIGNER -SD -o example example.db >/dev/null
  echo "\$INCLUDE \"example.db.signed\"" >>example.db
  # now retire key2 and resign the zone
  $SETTIME -I now "$key2" >/dev/null 2>&1
  $SIGNER -SD -o example example.db >/dev/null
) || ret=1
get_default_algorithm_key_ids_from_sigs $zone | grep "^$keyid2$" >/dev/null || ret=1
get_default_algorithm_key_ids_from_sigs $zone | grep "^$keyid3$" >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -Q purges signatures from inactive keys ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -SDQ -o example example.db >/dev/null
) || ret=1
get_default_algorithm_key_ids_from_sigs $zone | grep "^$keyid2$" >/dev/null && ret=1
get_default_algorithm_key_ids_from_sigs $zone | grep "^$keyid3$" >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone retains unexpired signatures ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -Sxt -o example example.db >signer.out.1
  $SIGNER -Sxt -o example -f example.db.signed example.db.signed >signer.out.2
) || ret=1
gen1=$(awk '/generated/ {print $3}' signer/signer.out.1)
retain1=$(awk '/retained/ {print $3}' signer/signer.out.1)
gen2=$(awk '/generated/ {print $3}' signer/signer.out.2)
retain2=$(awk '/retained/ {print $3}' signer/signer.out.2)
drop2=$(awk '/dropped/ {print $3}' signer/signer.out.2)
[ "$retain2" -eq $((gen1 + retain1)) ] || ret=1
[ "$gen2" -eq 0 ] || ret=1
[ "$drop2" -eq 0 ] || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone purges RRSIGs from formerly-owned glue (nsec) ($n)"
ret=0
(
  cd signer || exit 1
  # remove NSEC-only keys
  rm -f Kexample.+005*
  cp -f example.db.in example2.db
  cat <<EOF >>example2.db
sub1.example. IN A 10.53.0.1
ns.sub2.example. IN A 10.53.0.2
EOF
  echo "\$INCLUDE \"example2.db.signed\"" >>example2.db
  touch example2.db.signed
  $SIGNER -DS -O full -f example2.db.signed -o example example2.db >/dev/null
) || ret=1
grep "^sub1\\.example\\..*RRSIG[ 	]A[ 	]" signer/example2.db.signed >/dev/null 2>&1 || ret=1
grep "^ns\\.sub2\\.example\\..*RRSIG[ 	]A[ 	]" signer/example2.db.signed >/dev/null 2>&1 || ret=1
(
  cd signer || exit 1
  cp -f example.db.in example2.db
  cat <<EOF >>example2.db
sub1.example. IN NS sub1.example.
sub1.example. IN A 10.53.0.1
sub2.example. IN NS ns.sub2.example.
ns.sub2.example. IN A 10.53.0.2
EOF
  echo "\$INCLUDE \"example2.db.signed\"" >>example2.db
  $SIGNER -DS -O full -f example2.db.signed -o example example2.db >/dev/null
) || ret=1
grep "^sub1\\.example\\..*RRSIG[ 	]A[ 	]" signer/example2.db.signed >/dev/null 2>&1 && ret=1
grep "^ns\\.sub2\\.example\\..*RRSIG[ 	]A[ 	]" signer/example2.db.signed >/dev/null 2>&1 && ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone purges RRSIGs from formerly-owned glue (nsec3) ($n)"
ret=0
(
  cd signer || exit 1
  rm -f example2.db.signed
  cp -f example.db.in example2.db
  cat <<EOF >>example2.db
sub1.example. IN A 10.53.0.1
ns.sub2.example. IN A 10.53.0.2
EOF
  echo "\$INCLUDE \"example2.db.signed\"" >>example2.db
  touch example2.db.signed
  $SIGNER -DS -3 feedabee -O full -f example2.db.signed -o example example2.db >/dev/null
) || ret=1
grep "^sub1\\.example\\..*RRSIG[ 	]A[ 	]" signer/example2.db.signed >/dev/null 2>&1 || ret=1
grep "^ns\\.sub2\\.example\\..*RRSIG[ 	]A[ 	]" signer/example2.db.signed >/dev/null 2>&1 || ret=1
(
  cd signer || exit 1
  cp -f example.db.in example2.db
  cat <<EOF >>example2.db
sub1.example. IN NS sub1.example.
sub1.example. IN A 10.53.0.1
sub2.example. IN NS ns.sub2.example.
ns.sub2.example. IN A 10.53.0.2
EOF
  echo "\$INCLUDE \"example2.db.signed\"" >>example2.db
  $SIGNER -DS -3 feedabee -O full -f example2.db.signed -o example example2.db >/dev/null
) || ret=1
grep "^sub1\\.example\\..*RRSIG[ 	]A[ 	]" signer/example2.db.signed >/dev/null 2>&1 && ret=1
grep "^ns\\.sub2\\.example\\..*RRSIG[ 	]A[ 	]" signer/example2.db.signed >/dev/null 2>&1 && ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone output format ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -O full -f - -Sxt -o example example.db >signer.out.3 2>/dev/null
  $SIGNER -O text -f - -Sxt -o example example.db >signer.out.4 2>/dev/null
  $SIGNER -O raw -f signer.out.5 -Sxt -o example example.db >/dev/null
  $SIGNER -O raw=0 -f signer.out.6 -Sxt -o example example.db >/dev/null
  $SIGNER -O raw -f - -Sxt -o example example.db >signer.out.7 2>/dev/null
) || ret=1
awk 'BEGIN { found = 0; }
     $1 == "example." && $3 == "IN" && $4 == "SOA" { found = 1; if (NF != 11) exit(1); }
     END { if (!found) exit(1); }' signer/signer.out.3 || ret=1
awk 'BEGIN { found = 0; }
     $1 == "example." && $3 == "IN" && $4 == "SOA" { found = 1; if (NF != 7) exit(1); }
     END { if (!found) exit(1); }' signer/signer.out.4 || ret=1
israw1 signer/signer.out.5 || ret=1
israw0 signer/signer.out.6 || ret=1
israw1 signer/signer.out.7 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking TTLs are capped by dnssec-signzone -M ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -O full -f signer.out.8 -S -M 30 -o example example.db >/dev/null
) || ret=1
awk '/^;/ { next; } $2 > 30 { exit 1; }' signer/signer.out.8 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -N date ($n)"
ret=0
(
  cd signer || exit 1
  TZ=UTC $SIGNER -O full -f signer.out.9 -S -N date -o example example2.db >/dev/null
) || ret=1
# shellcheck disable=SC2016
now=$(TZ=UTC $PERL -e '@lt=localtime(); printf "%.4d%0.2d%0.2d00\n",$lt[5]+1900,$lt[4]+1,$lt[3];')
serial=$(awk '/^;/ { next; } $4 == "SOA" { print $7 }' signer/signer.out.9)
[ "$now" -eq "$serial" ] || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -G ($n)"
ret=0
(
  cd signer || exit 1
  $SETTIME -P ds now -P sync now "$key1" >/dev/null
  $SIGNER -G "cdnskey,cds:sha384" -O full -S -f signer.out.$n -o example example2.db >/dev/null
) || ret=1
test $(awk '$4 == "CDNSKEY" { print }' signer/signer.out.$n | wc -l) -eq 1 || ret=1
test $(awk '$4 == "CDS" && $7 == "2" { print }' signer/signer.out.$n | wc -l) -eq 0 || ret=1
test $(awk '$4 == "CDS" && $7 == "4" { print }' signer/signer.out.$n | wc -l) -eq 1 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -G (default) ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -O full -S -f signer.out.$n -o example example2.db >/dev/null
) || ret=1
test $(awk '$4 == "CDNSKEY" { print }' signer/signer.out.$n | wc -l) -eq 1 || ret=1
test $(awk '$4 == "CDS" && $7 == "2" { print }' signer/signer.out.$n | wc -l) -eq 1 || ret=1
test $(awk '$4 == "CDS" && $7 == "4" { print }' signer/signer.out.$n | wc -l) -eq 0 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -G (empty) ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -G "" -O full -S -f signer.out.$n -o example example2.db >/dev/null
) || ret=1
test $(awk '$4 == "CDNSKEY" { print }' signer/signer.out.$n | wc -l) -eq 0 || ret=1
test $(awk '$4 == "CDS" && $7 == "2" { print }' signer/signer.out.$n | wc -l) -eq 0 || ret=1
test $(awk '$4 == "CDS" && $7 == "4" { print }' signer/signer.out.$n | wc -l) -eq 0 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -G (no CDNSKEY) ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -G "cds:sha-256,cds:sha384" -O full -S -f signer.out.$n -o example example2.db >/dev/null
) || ret=1
test $(awk '$4 == "CDNSKEY" { print }' signer/signer.out.$n | wc -l) -eq 0 || ret=1
test $(awk '$4 == "CDS" && $7 == "2" { print }' signer/signer.out.$n | wc -l) -eq 1 || ret=1
test $(awk '$4 == "CDS" && $7 == "4" { print }' signer/signer.out.$n | wc -l) -eq 1 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -G (no CDS) ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -G "cdnskey" -O full -S -f signer.out.$n -o example example2.db >/dev/null
) || ret=1
test $(awk '$4 == "CDNSKEY" { print }' signer/signer.out.$n | wc -l) -eq 1 || ret=1
test $(awk '$4 == "CDS" && $7 == "2" { print }' signer/signer.out.$n | wc -l) -eq 0 || ret=1
test $(awk '$4 == "CDS" && $7 == "4" { print }' signer/signer.out.$n | wc -l) -eq 0 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -G (suppress duplicates) ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -G "cdnskey,cds:sha256,cds:sha256,cdnskey" -O full -S -f signer.out.$n -o example example2.db >/dev/null
) || ret=1
test $(awk '$4 == "CDNSKEY" { print }' signer/signer.out.$n | wc -l) -eq 1 || ret=1
test $(awk '$4 == "CDS" && $7 == "2" { print }' signer/signer.out.$n | wc -l) -eq 1 || ret=1
test $(awk '$4 == "CDS" && $7 == "4" { print }' signer/signer.out.$n | wc -l) -eq 0 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -G (bad argument) ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -G "cdnskey,foobar" -O full -S -f signer.out.$n -o example example2.db 2>signer.err.$n && ret=1
  grep "digest must specify cds:algorithm ('foobar')" signer.err.$n >/dev/null || ret=1
)
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -G (bad digest - name) ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -G "cdnskey,cds:foobar" -O full -S -f signer.out.$n -o example example2.db 2>signer.err.$n && ret=1
  grep "bad digest 'cds:foobar'" signer.err.$n >/dev/null || ret=1
)
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -G (bad digest - number) ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -G "cdnskey,cds:256" -O full -S -f signer.out.$n -o example example2.db 2>signer.err.$n && ret=1
  grep "bad digest 'cds:256': out of range" signer.err.$n >/dev/null || ret=1
)
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -G (unsupported digest - name) ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -G "cdnskey,cds:gost" -O full -S -f signer.out.$n -o example example2.db 2>signer.err.$n && ret=1
  grep "unsupported digest 'cds:gost'" signer.err.$n >/dev/null || ret=1
)
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking dnssec-signzone -G (unsupported digest - number) ($n)"
ret=0
(
  cd signer || exit 1
  $SIGNER -G "cdnskey,cds:200" -O full -S -f signer.out.$n -o example example2.db 2>signer.err.$n && ret=1
  grep "unsupported digest 'cds:200'" signer.err.$n >/dev/null || ret=1
)
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that RRSIGs are correctly removed from apex when RRset is removed  NSEC ($n)"
ret=0
# generate signed zone with MX and AAAA records at apex.
(
  cd signer || exit 1
  $KEYGEN -q -a $DEFAULT_ALGORITHM -3 -fK remove >/dev/null
  $KEYGEN -q -a $DEFAULT_ALGORITHM -33 remove >/dev/null
  echo >remove.db.signed
  $SIGNER -S -o remove -D -f remove.db.signed remove.db.in >signer.out.1.$n
)
grep "RRSIG MX" signer/remove.db.signed >/dev/null || {
  ret=1
  cp signer/remove.db.signed signer/remove.db.signed.pre$n
}
# re-generate signed zone without MX and AAAA records at apex.
(
  cd signer || exit 1
  $SIGNER -S -o remove -D -f remove.db.signed remove2.db.in >signer.out.2.$n
)
grep "RRSIG MX" signer/remove.db.signed >/dev/null && {
  ret=1
  cp signer/remove.db.signed signer/remove.db.signed.post$n
}
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that RRSIGs are correctly removed from apex when RRset is removed  NSEC3 ($n)"
ret=0
# generate signed zone with MX and AAAA records at apex.
(
  cd signer || exit 1
  echo >remove.db.signed
  $SIGNER -3 - -S -o remove -D -f remove.db.signed remove.db.in >signer.out.1.$n
)
grep "RRSIG MX" signer/remove.db.signed >/dev/null || {
  ret=1
  cp signer/remove.db.signed signer/remove.db.signed.pre$n
}
# re-generate signed zone without MX and AAAA records at apex.
(
  cd signer || exit 1
  $SIGNER -3 - -S -o remove -D -f remove.db.signed remove2.db.in >signer.out.2.$n
)
grep "RRSIG MX" signer/remove.db.signed >/dev/null && {
  ret=1
  cp signer/remove.db.signed signer/remove.db.signed.post$n
}
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "checking that records other than DNSKEY are not signed by a revoked key by dnssec-signzone ($n)"
ret=0
(
  cd signer || exit 0
  key1=$(${KEYGEN} -a "${DEFAULT_ALGORITHM}" -f KSK revoke.example)
  key2=$(${KEYGEN} -a "${DEFAULT_ALGORITHM}" -f KSK revoke.example)
  key3=$(${KEYGEN} -a "${DEFAULT_ALGORITHM}" revoke.example)
  rkey=$(${REVOKE} "$key2")
  cat >>revoke.example.db <<EOF
\$TTL 3600
@ SOA . . 0 0 0 0 3600
@ NS .
\$INCLUDE "${key1}.key"
\$INCLUDE "${rkey}.key"
\$INCLUDE "${key3}.key"
EOF
  "${DSFROMKEY}" -C "$key1" >>revoke.example.db
  "${SIGNER}" -o revoke.example revoke.example.db >signer.out.$n
) || ret=1
keycount=$(grep -c "RRSIG.DNSKEY ${DEFAULT_ALGORITHM_NUMBER} " signer/revoke.example.db.signed)
cdscount=$(grep -c "RRSIG.CDS ${DEFAULT_ALGORITHM_NUMBER} " signer/revoke.example.db.signed)
soacount=$(grep -c "RRSIG.SOA ${DEFAULT_ALGORITHM_NUMBER} " signer/revoke.example.db.signed)
[ $keycount -eq 3 ] || ret=1
[ $cdscount -eq 2 ] || ret=1
[ $soacount -eq 1 ] || ret=1
n=$((n + 1))
if [ "$ret" -ne 0 ]; then echo_i "failed"; fi
status=$((status + ret))

echo_i "check that 'dnssec-keygen -S' works for all supported algorithms ($n)"
ret=0
alg=1
until test $alg -eq 258; do
  zone="keygen-$alg."
  case $alg in
    2) # Diffie Helman
      alg=$((alg + 1))
      continue
      ;;
    157 | 160 | 161 | 162 | 163 | 164 | 165) # private - non standard
      alg=$((alg + 1))
      continue
      ;;
    1 | 5 | 7 | 8 | 10) # RSA algorithms
      key1=$($KEYGEN -a "$alg" -b "2048" "$zone" 2>"keygen-$alg.err" || true)
      ;;
    15 | 16)
      key1=$($KEYGEN -a "$alg" "$zone" 2>"keygen-$alg.err" || true)
      ;;
    256)
      key1=$($KEYGEN -a "RSASHA256OID" "$zone" 2>"keygen-$alg.err" || true)
      ;;
    257)
      key1=$($KEYGEN -a "RSASHA512OID" "$zone" 2>"keygen-$alg.err" || true)
      ;;
    *)
      key1=$($KEYGEN -a "$alg" "$zone" 2>"keygen-$alg.err" || true)
      ;;
  esac
  if grep "unknown algorithm" "keygen-$alg.err" >/dev/null; then
    alg=$((alg + 1))
    continue
  fi
  if grep "unsupported algorithm" "keygen-$alg.err" >/dev/null; then
    alg=$((alg + 1))
    continue
  fi
  if test -z "$key1"; then
    echo_i "'$KEYGEN -a $alg': failed"
    cat "keygen-$alg.err"
    ret=1
    alg=$((alg + 1))
    continue
  fi
  $SETTIME -I now+4d "$key1.private" >/dev/null
  key2=$($KEYGEN -v 10 -i 3d -S "$key1.private" 2>/dev/null)
  test -f "$key2.key" -a -f "$key2.private" || {
    ret=1
    echo_i "'dnssec-keygen -S' failed for algorithm: $alg"
  }
  alg=$((alg + 1))
done
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that 'dnssec-keygen -F' disables rsasha1 ($n)"
ret=0
if $FEATURETEST --have-fips-mode; then
  echo_i "skipped: already in FIPS mode"
elif ! $FEATURETEST --fips-provider; then
  echo_i "skipped no FIPS provider available"
elif [ $RSASHA1_SUPPORTED = 0 ]; then
  echo_i "skipped: RSASHA1 is not supported"
else
  $KEYGEN -F -a rsasha1 example.fips 2>keygen.err$n || true
  grep -i "unsupported algorithm: RSASHA1" "keygen.err$n" >/dev/null || ret=1
fi
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that 'dnssec-keygen -F' disables nsec3rsasha1 ($n)"
ret=0
if $FEATURETEST --have-fips-mode; then
  echo_i "skipped: already in FIPS mode"
elif ! $FEATURETEST --fips-provider; then
  echo_i "skipped: cannot switch to FIPS mode"
elif [ $RSASHA1_SUPPORTED = 0 ]; then
  echo_i "skipped: RSASHA1 is not supported"
else
  $KEYGEN -F -a nsec3rsasha1 example.fips 2>keygen.err$n || true
  grep -i "unsupported algorithm: NSEC3RSASHA1" "keygen.err$n" >/dev/null || ret=1
fi
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check that dnssec-keygen honours key tag ranges ($n)"
ret=0
zone=settagrange
ksk=$("$KEYGEN" -f KSK -q -a $DEFAULT_ALGORITHM -M 0:32767 "$zone")
zsk=$("$KEYGEN" -q -a $DEFAULT_ALGORITHM -M 32768:65535 "$zone")
kid=$(keyfile_to_key_id "$ksk")
zid=$(keyfile_to_key_id "$zsk")
[ $kid -ge 0 -a $kid -le 32767 ] || ret=1
[ $zid -ge 32768 -a $zid -le 65535 ] || ret=1
rksk=$($REVOKE -R $ksk)
rzsk=$($REVOKE -R $zsk)
krid=$(keyfile_to_key_id "$rksk")
zrid=$(keyfile_to_key_id "$rzsk")
[ $krid -ge 0 -a $krid -le 32767 ] || ret=1
[ $zrid -ge 32768 -a $zrid -le 65535 ] || ret=1
n=$((n + 1))
if [ "$ret" -ne 0 ]; then echo_i "failed"; fi
status=$((status + ret))

echo_i "check dnssec-dsfromkey from stdin ($n)"
ret=0
cat algroll.dnskey | $DSFROMKEY -f - algroll. >dsfromkey.out.test$n
NF=$(awk '{print NF}' dsfromkey.out.test$n | sort -u)
[ "${NF}" = 7 ] || ret=1
# make canonical
awk '/^algroll/ {
	for (i=1;i<7;i++) printf("%s ", $i);
	for (i=7;i<=NF;i++) printf("%s", $i);
	printf("\n");
}' <dsfromkey.out.test$n >canonical1.$n || ret=1
awk '/^algroll/ {
	for (i=1;i<7;i++) printf("%s ", $i);
	for (i=7;i<=NF;i++) printf("%s", $i);
	printf("\n");
}' <dsset-algroll. >canonical2.$n || ret=1
diff -b canonical1.$n canonical2.$n >/dev/null 2>&1 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Intentionally strip ".key" from keyfile name to ensure the error message
# includes it anyway to avoid confusion (RT #21731)
echo_i "check dnssec-dsfromkey error message when keyfile is not found ($n)"
ret=0
key=$($KEYGEN -a $DEFAULT_ALGORITHM -q example. 2>/dev/null) || ret=1
mv "$key.key" "$key"
$DSFROMKEY "$key" >dsfromkey.out.$n 2>&1 && ret=1
grep "$key.key: file not found" dsfromkey.out.$n >/dev/null || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "check dnssec-dsfromkey with revoked key ($n)"
ret=0
$DSFROMKEY -f revkey.dnskey revkey.example. >dsfromkey.out.test$n || ret=1
test $(wc -l <dsfromkey.out.test$n) -eq 1 || ret=1
n=$((n + 1))
test "$ret" -eq 0 || echo_i "failed"

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
