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

# shellcheck source=conf.sh
. ../conf.sh
# shellcheck source=kasp.sh
. ../kasp.sh

set -e

status=0
n=0

# Get timing metadata from a value plus additional time.
# $1: Value
# $2: Additional time
addtime() {
        if [ -x "$PYTHON" ]; then
                # Convert "%Y%m%d%H%M%S" format to epoch seconds.
                # Then, add the additional time (can be negative).
                _value=$1
                _plus=$2
                $PYTHON > python.out <<EOF
from datetime import datetime
from datetime import timedelta
_now = datetime.strptime("$_value", "%Y%m%d%H%M%S")
_delta = timedelta(seconds=$_plus)
_then = _now + _delta
print(_then.strftime("%Y%m%d%H%M%S"));
EOF
                cat python.out
        fi
}

# Check keys that were created. The keys created are listed in the latest ksr output
# file, ksr.keygen.out.$n.
# $1: zone name
# $2: key directory
check_keys () (
	zone=$1
	dir=$2
	lifetime=$LIFETIME
	alg=$ALG
	size=$SIZE
	inception=0
	pad=$(printf "%03d" "$alg")

	num=0
	for key in $(grep "K${zone}.+$pad+" ksr.keygen.out.$n)
	do
		grep "; Created:" "${dir}/${key}.key" > created.out || return 1
		created=$(awk '{print $3}' < created.out)
		test "$num" -eq 0 && retired=$created
		# active: retired previous key
		active=$retired
		# published: 2h5m (dnskey-ttl + publish-safety + propagation)
		published=$(addtime $active -7500)
		# retired: zsk-lifetime
		retired=$(addtime $active $lifetime)
		# removed: 10d1h5m (ttlsig + retire-safety + sign-delay + propagation)
		removed=$(addtime $retired 867900)

		echo_i "check metadata on $key"
		statefile="${dir}/${key}.state"
		grep "Algorithm: $alg" $statefile > /dev/null || return 1
		grep "Length: $size" $statefile > /dev/null || return 1
		grep "Lifetime: $lifetime" $statefile > /dev/null || return 1
		grep "KSK: no" $statefile > /dev/null || return 1
		grep "ZSK: yes" $statefile > /dev/null || return 1
		grep "Published: $published" $statefile > /dev/null || return 1
		grep "Active: $active" $statefile > /dev/null || return 1
		grep "Retired: $retired" $statefile > /dev/null || return 1
		grep "Removed: $removed" $statefile > /dev/null || return 1

		inception=$((inception+lifetime))
		num=$((num+1))

		# Save some information for testing
		cp ${dir}/${key}.key ${key}.key.expect
		cp ${dir}/${key}.private ${key}.private.expect
		cp ${dir}/${key}.state ${key}.state.expect
		cat ${dir}/${key}.key | grep -v ";.*" > "${zone}.${alg}.zsk${num}"
		echo $key > "${zone}.${alg}.zsk${num}.id"
	done

	return 0
)

# Print the DNSKEY records for zone $1, which have keys listed in file $5
# that match the keys with numbers $2 and $3, and match algorithm number $4,
# sorted by keytag.
print_dnskeys () {
	for key in $(cat $5 | sort)
	do
		for num in $2 $3
		do
			zsk=$(cat $1.$4.zsk$num.id)
			if [ "$key" = "$zsk" ]; then
				cat $1.$4.zsk$num >> ksr.request.expect.$n
			fi
		done
	done
}
# Call the dnssec-ksr command:
# ksr <policy> [options] <command> <zone>
ksr () {
	$KSR -l named.conf -k "$@"
}

# Unknown action.
n=$((n+1))
echo_i "check that 'dnssec-ksr' errors on unknown action ($n)"
ret=0
ksr common foobar common.test > ksr.foobar.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: unknown command 'foobar'" ksr.foobar.out.$n > /dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Key generation: common
set_zsk () {
	ALG=$1
	SIZE=$2
	LIFETIME=$3
}

n=$((n+1))
echo_i "check that 'dnssec-ksr keygen' errors on missing end date ($n)"
ret=0
ksr common keygen common.test > ksr.keygen.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: keygen requires an end date" ksr.keygen.out.$n > /dev/null|| ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-ksr keygen' pregenerates right amount of keys in the common case ($n)"
ret=0
ksr common -i now -e +1y keygen common.test > ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
check_keys common.test "." || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))
# save now time
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
grep "; Created:" "${key}.key" > now.out || ret=1
now=$(awk '{print $3}' < now.out)

n=$((n+1))
echo_i "check that 'dnssec-ksr keygen' selects pregenerated keys for the same time bundle ($n)"
ret=0
ksr common -e +1y keygen common.test > ksr.keygen.out.$n 2>&1 || ret=1
diff ksr.keygen.out.expect ksr.keygen.out.$n > /dev/null|| ret=1
for key in $(cat ksr.keygen.out.$n)
do
	# Ensure the files are not modified.
	diff ${key}.key ${key}.key.expect > /dev/null || ret=1
	diff ${key}.private ${key}.private.expect > /dev/null || ret=1
	diff ${key}.state ${key}.state.expect > /dev/null || ret=1
done
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Create request: common
n=$((n+1))
echo_i "check that 'dnssec-ksr request' errors on missing end date ($n)"
ret=0
ksr common request common.test > ksr.request.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: request requires an end date" ksr.request.out.$n > /dev/null|| ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-ksr request' creates correct KSR in the common case ($n)"
ret=0
ksr common -i $now -e +1y request common.test > ksr.request.out.$n 2>&1 || ret=1
# Bundle 1: KSK + ZSK1
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat $key.state | grep "Generated" | cut -d' ' -f 2-)
echo ";; KSR common.test - bundle $inception" > ksr.request.expect.$n
cat common.test.ksk1 >> ksr.request.expect.$n
cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1 >> ksr.request.expect.$n
# Bundle 2: KSK + ZSK1 + ZSK2
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk2.id)
inception=$(cat $key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KSR common.test - bundle $inception" >> ksr.request.expect.$n
cat common.test.ksk1 >> ksr.request.expect.$n
print_dnskeys common.test 1 2 $DEFAULT_ALGORITHM_NUMBER ksr.keygen.out.expect
# Bundle 3: KSK + ZSK2
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat $key.state | grep "Removed" | cut -d' ' -f 2-)
echo ";; KSR common.test - bundle $inception" >> ksr.request.expect.$n
cat common.test.ksk1 >> ksr.request.expect.$n
cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk2 >> ksr.request.expect.$n
diff ksr.request.out.$n ksr.request.expect.$n > /dev/null || ret=1
cp ksr.request.expect.$n ksr.request.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Key generation: common (2)
n=$((n+1))
echo_i "check that 'dnssec-ksr keygen' pregenerates keys in the given key-directory ($n)"
ret=0
ksr common -e +1y -K keydir keygen common.test > ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
check_keys common.test keydir || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-ksr keygen' selects generates only necessary keys for overlapping time bundle ($n)"
ret=0
ksr common -e +2y -v 1 keygen common.test > ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 4 ] || ret=1
# 2 selected, 2 generated
num=$(grep "Selecting" ksr.keygen.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
num=$(grep "Generating" ksr.keygen.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "run 'dnssec-ksr keygen' again with verbosity 0 ($n)"
ret=0
ksr common -i $now -e +2y keygen common.test > ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 4 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
check_keys common.test "." || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Create request: common (2)
n=$((n+1))
echo_i "check that 'dnssec-ksr request' creates correct KSR if the interval is shorter ($n)"
ret=0
ksr common -i $now -e +1y request common.test > ksr.request.out.$n 2>&1 || ret=1
# Same as earlier.
diff ksr.request.out.$n ksr.request.expect > /dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-ksr request' creates correct KSR with new interval ($n)"
ret=0
ksr common -i $now -e +2y request common.test > ksr.request.out.$n 2>&1 || ret=1
cp ksr.request.expect ksr.request.expect.$n
# Bundle 4: KSK + ZSK2 + ZSK3
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk3.id)
inception=$(cat $key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KSR common.test - bundle $inception" >> ksr.request.expect.$n
cat common.test.ksk1 >> ksr.request.expect.$n
print_dnskeys common.test 2 3 $DEFAULT_ALGORITHM_NUMBER ksr.keygen.out.expect
# Bundle 5: KSK + ZSK3
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk2.id)
inception=$(cat $key.state | grep "Removed" | cut -d' ' -f 2-)
echo ";; KSR common.test - bundle $inception" >> ksr.request.expect.$n
cat common.test.ksk1 >> ksr.request.expect.$n
cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk3 >> ksr.request.expect.$n
# Bundle 6: KSK + ZSK3 + ZSK4
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk4.id)
inception=$(cat $key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KSR common.test - bundle $inception" >> ksr.request.expect.$n
cat common.test.ksk1 >> ksr.request.expect.$n
print_dnskeys common.test 3 4 $DEFAULT_ALGORITHM_NUMBER ksr.keygen.out.expect
# Bundle 7: KSK + ZSK4
key=$(cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk3.id)
inception=$(cat $key.state | grep "Removed" | cut -d' ' -f 2-)
echo ";; KSR common.test - bundle $inception" >> ksr.request.expect.$n
cat common.test.ksk1 >> ksr.request.expect.$n
cat common.test.$DEFAULT_ALGORITHM_NUMBER.zsk4 >> ksr.request.expect.$n
diff ksr.request.out.$n ksr.request.expect.$n > /dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-ksr request' errors if there are not enough keys ($n)"
ret=0
ksr common -i $now -e +3y request common.test > ksr.request.out.$n 2> ksr.request.err.$n && ret=1
grep "dnssec-ksr: fatal: no common.test/ECDSAP256SHA256 zsk key pair found for bundle" ksr.request.err.$n > /dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Key generation: csk
n=$((n+1))
echo_i "check that 'dnssec-ksr keygen' creates no keys for policy with csk ($n)"
ret=0
ksr csk -e +2y keygen csk.test > ksr.keygen.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: policy 'csk' has no zsks" ksr.keygen.out.$n > /dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Key generation: unlimited
n=$((n+1))
echo_i "check that 'dnssec-ksr keygen' creates only one key for zsk with unlimited lifetime ($n)"
ret=0
ksr unlimited -e +2y keygen unlimited.test > ksr.keygen.out.$n 2>&1 || ret=1
num=$(cat ksr.keygen.out.$n | wc -l)
[ $num -eq 1 ] || ret=1
key=$(cat ksr.keygen.out.$n)
grep "; Created:" "${key}.key" > created.out || ret=1
created=$(awk '{print $3}' < created.out)
active=$created
published=$(addtime $active -7500)
echo_i "check metadata on $key"
grep "Algorithm: $DEFAULT_ALGORITHM_NUMBER" ${key}.state > /dev/null || ret=1
grep "Length: $DEFAULT_BITS" ${key}.state > /dev/null || ret=1
grep "Lifetime: 0" ${key}.state > /dev/null || ret=1
grep "KSK: no" ${key}.state > /dev/null || ret=1
grep "ZSK: yes" ${key}.state > /dev/null || ret=1
grep "Published: $published" ${key}.state > /dev/null || ret=1
grep "Active: $active" ${key}.state > /dev/null || ret=1
grep "Retired:" ${key}.state > /dev/null && ret=1
grep "Removed:" ${key}.state > /dev/null && ret=1
cat ${key}.key | grep -v ";.*" > unlimited.test.$DEFAULT_ALGORITHM_NUMBER.zsk1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Create request: unlimited
n=$((n+1))
echo_i "check that 'dnssec-ksr request' creates correct KSR with unlimited zsk ($n)"
ret=0
ksr unlimited -i $created -e +10y request unlimited.test > ksr.request.out.$n 2>&1 || ret=1
# Only one bundle: KSK + ZSK
inception=$(cat $key.state | grep "Generated" | cut -d' ' -f 2-)
echo ";; KSR unlimited.test - bundle $inception" > ksr.request.expect.$n
cat unlimited.test.ksk1 >> ksr.request.expect.$n
cat unlimited.test.$DEFAULT_ALGORITHM_NUMBER.zsk1 >> ksr.request.expect.$n
diff ksr.request.out.$n ksr.request.expect.$n > /dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Key generation: two-tone
n=$((n+1))
echo_i "check that 'dnssec-ksr keygen' creates keys for different algorithms ($n)"
ret=0
ksr two-tone -e +1y keygen two-tone.test > ksr.keygen.out.$n 2>&1 || ret=1
# First algorithm keys have a lifetime of 3 months, so there should be 4 created keys.
alg=$(printf "%03d" "$DEFAULT_ALGORITHM_NUMBER")
num=$(grep "Ktwo-tone.test.+$alg+" ksr.keygen.out.$n | wc -l)
[ $num -eq 4 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 8035200
check_keys two-tone.test "." || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect.$DEFAULT_ALGORITHM_NUMBER
# Second algorithm keys have a lifetime of 5 months, so there should be 3 created keys.
# While only two time bundles of 5 months fit into one year, we need to create an
# extra key for the remainder of the bundle.
alg=$(printf "%03d" "$ALTERNATIVE_ALGORITHM_NUMBER")
num=$(grep "Ktwo-tone.test.+$alg+" ksr.keygen.out.$n | wc -l)
[ $num -eq 3 ] || ret=1
set_zsk $ALTERNATIVE_ALGORITHM_NUMBER $ALTERNATIVE_BITS 13392000
check_keys two-tone.test "." $ALTERNATIVE_ALGORITHM_NUMBER 13392000 || ret=1
cp ksr.keygen.out.$n ksr.keygen.out.expect.$ALTERNATIVE_ALGORITHM_NUMBER
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Create request: two-tone
n=$((n+1))
echo_i "check that 'dnssec-ksr request' creates correct KSR with multiple algorithms ($n)"
ret=0
key=$(cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
grep "; Created:" "${key}.key" > created.out || ret=1
created=$(awk '{print $3}' < created.out)
ksr two-tone -i $created -e +6mo request two-tone.test > ksr.request.out.$n 2>&1 || ret=1
# The two-tone policy uses two sets of KSK/ZSK with different algorithms. One
# set uses the default algorithm (denoted as A below), the other is using the
# alternative algorithm (denoted as B). The A-ZSKs roll every three months,
# so in the second bundle there should be a new DNSKEY prepublished, and the
# predecessor is removed in the third bundle. Then, after five months the
# ZSK for the B set is rolled, adding the successor in bundle 4 and removing
# its predecessor in bundle 5.
#
# Bundle 1: KSK-A1, KSK-B1, ZSK-A1, ZSK-B1
key=$(cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat $key.state | grep "Generated" | cut -d' ' -f 2-)
echo ";; KSR two-tone.test - bundle $inception" > ksr.request.expect.$n
cat two-tone.test.ksk1 >> ksr.request.expect.$n
cat two-tone.test.ksk2 >> ksr.request.expect.$n
cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk1 >> ksr.request.expect.$n
cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk1 >> ksr.request.expect.$n
# Bundle 2: KSK-A1, KSK-B1, ZSK-A1 + ZSK-A2, ZSK-B1
key=$(cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk2.id)
inception=$(cat $key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KSR two-tone.test - bundle $inception" >> ksr.request.expect.$n
cat two-tone.test.ksk1 >> ksr.request.expect.$n
cat two-tone.test.ksk2 >> ksr.request.expect.$n
print_dnskeys two-tone.test 1 2 $DEFAULT_ALGORITHM_NUMBER ksr.keygen.out.expect.$DEFAULT_ALGORITHM_NUMBER >> ksr.request.expect.$n
cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk1 >> ksr.request.expect.$n
# Bundle 3: KSK-A1, KSK-B1, ZSK-A2, ZSK-B1
key=$(cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat $key.state | grep "Removed" | cut -d' ' -f 2-)
echo ";; KSR two-tone.test - bundle $inception" >> ksr.request.expect.$n
cat two-tone.test.ksk1 >> ksr.request.expect.$n
cat two-tone.test.ksk2 >> ksr.request.expect.$n
cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk2 >> ksr.request.expect.$n
cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk1 >> ksr.request.expect.$n
# Bundle 4: KSK-A1, KSK-B1, ZSK-A2, ZSK-B1 + ZSK-B2
key=$(cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk2.id)
inception=$(cat $key.state | grep "Published" | cut -d' ' -f 2-)
echo ";; KSR two-tone.test - bundle $inception" >> ksr.request.expect.$n
cat two-tone.test.ksk1 >> ksr.request.expect.$n
cat two-tone.test.ksk2 >> ksr.request.expect.$n
cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk2 >> ksr.request.expect.$n
print_dnskeys two-tone.test 1 2 $ALTERNATIVE_ALGORITHM_NUMBER ksr.keygen.out.expect.$ALTERNATIVE_ALGORITHM_NUMBER >> ksr.request.expect.$n
# Bundle 5: KSK-A1, KSK-B1, ZSK-A2, ZSK-B2
key=$(cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk1.id)
inception=$(cat $key.state | grep "Removed" | cut -d' ' -f 2-)
echo ";; KSR two-tone.test - bundle $inception" >> ksr.request.expect.$n
cat two-tone.test.ksk1 >> ksr.request.expect.$n
cat two-tone.test.ksk2 >> ksr.request.expect.$n
cat two-tone.test.$DEFAULT_ALGORITHM_NUMBER.zsk2 >> ksr.request.expect.$n
cat two-tone.test.$ALTERNATIVE_ALGORITHM_NUMBER.zsk2 >> ksr.request.expect.$n
# Check the KSR request against the expected request.
diff ksr.request.out.$n ksr.request.expect.$n > /dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))


echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
