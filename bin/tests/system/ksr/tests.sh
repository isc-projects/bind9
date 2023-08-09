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
# file, ksr.out.$n.
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

	for key in $(grep "K${zone}.+$pad+" ksr.out.$n)
	do
		grep "; Created:" "${dir}/${key}.key" > created.out || return 1
		created=$(awk '{print $3}' < created.out)
		# active: created + inception
		active=$(addtime $created $inception)
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

		cp ${dir}/${key}.key ${key}.key.expect
		cp ${dir}/${key}.private ${key}.private.expect
		cp ${dir}/${key}.state ${key}.state.expect
	done

	return 0
)


# Call the dnssec-ksr command:
# ksr <policy> [options] <command> <zone>
ksr () {
	$KSR -l named.conf -k "$@"
}

# Unknown action.
n=$((n+1))
echo_i "check that 'dnssec-ksr' errors on unknown action ($n)"
ret=0
ksr common foobar common.test > ksr.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: unknown command 'foobar'" ksr.out.$n > /dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Key generation.
set_zsk () {
	ALG=$1
	SIZE=$2
	LIFETIME=$3
}

n=$((n+1))
echo_i "check that 'dnssec-ksr' errors on missing end date ($n)"
ret=0
ksr common keygen common.test > ksr.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: keygen requires an end date" ksr.out.$n > /dev/null|| ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-ksr' pregenerates right amount of keys in the common case ($n)"
ret=0
ksr common -i now -e +1y keygen common.test > ksr.out.$n 2>&1 || ret=1
num=$(cat ksr.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
check_keys common.test "." || ret=1
cp ksr.out.$n ksr.out.expect
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-ksr' selects pregenerated keys for the same time bundle ($n)"
ret=0
ksr common -e +1y keygen common.test > ksr.out.$n 2>&1 || ret=1
diff ksr.out.expect ksr.out.$n > /dev/null|| ret=1
for key in $(cat ksr.out.$n)
do
	# Ensure the files are not modified.
	diff ${key}.key ${key}.key.expect > /dev/null || ret=1
	diff ${key}.private ${key}.private.expect > /dev/null || ret=1
	diff ${key}.state ${key}.state.expect > /dev/null || ret=1
done
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-ksr' selects generates only necessary keys for overlapping time bundle ($n)"
ret=0
ksr common -e +2y -v 1 keygen common.test > ksr.out.$n 2>&1 || ret=1
num=$(cat ksr.out.$n | wc -l)
[ $num -eq 4 ] || ret=1
# 2 selected, 2 generated
num=$(grep "Selecting" ksr.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
num=$(grep "Generating" ksr.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
check_keys "." || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-ksr' pregenerates keys in the given key-directory ($n)"
ret=0
ksr common -i now -e +1y -K keydir keygen common.test > ksr.out.$n 2>&1 || ret=1
num=$(cat ksr.out.$n | wc -l)
[ $num -eq 2 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 16070400
check_keys "keydir" || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-ksr' creates only one key for zsk with unlimited lifetime ($n)"
ret=0
ksr unlimited -e +2y keygen unlimited.test > ksr.out.$n 2>&1 || ret=1
num=$(cat ksr.out.$n | wc -l)
[ $num -eq 1 ] || ret=1
key=$(cat ksr.out.$n)
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
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-ksr' creates no keys for policy with csk ($n)"
ret=0
ksr csk -e +2y keygen csk.test > ksr.out.$n 2>&1 && ret=1
grep "dnssec-ksr: fatal: policy 'csk' has no zsks" ksr.out.$n > /dev/null || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-ksr' creates keys for different algorithms ($n)"
ret=0
ksr two-tone -e +1y keygen two-tone.test > ksr.out.$n 2>&1 || ret=1
# First algorithm keys have a lifetime of 3 months, so there should be 4 created keys.
alg=$(printf "%03d" "$DEFAULT_ALGORITHM_NUMBER")
num=$(grep "Ktwo-tone.test.+$alg+" ksr.out.$n | wc -l)
[ $num -eq 4 ] || ret=1
set_zsk $DEFAULT_ALGORITHM_NUMBER $DEFAULT_BITS 8035200
check_keys two-tone.test "." || ret=1
# Second algorithm keys have a lifetime of 5 months, so there should be 3 created keys.
# While only two time bundles of 5 months fit into one year, we need to create an
# extra key for the remainder of the bundle.
alg=$(printf "%03d" "$ALTERNATIVE_ALGORITHM_NUMBER")
num=$(grep "Ktwo-tone.test.+$alg+" ksr.out.$n | wc -l)
[ $num -eq 3 ] || ret=1
set_zsk $ALTERNATIVE_ALGORITHM_NUMBER $ALTERNATIVE_BITS 13392000
check_keys two-tone.test "." $ALTERNATIVE_ALGORITHM_NUMBER 13392000 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
