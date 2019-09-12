#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=conf.sh
SYSTEMTESTTOP=..
. "$SYSTEMTESTTOP/conf.sh"

set -e

status=0
n=0

################################################################################
# Utilities                                                                    #
################################################################################

# Get the key ids from key files for zone $2 in directory $1
# that matches algorithm $3.
get_keyids() {
	dir=$1
	zone=$2
	algorithm=$(printf "%03d" $3)
	start="${dir}/K${zone}.+${algorithm}+"
	end=".key"

	ls ${start}*${end} | sed "s/$dir\/K${zone}.+${algorithm}+\([0-9]\{5\}\)${end}/\1/"
}

# By default log errors and don't quit immediately.
_log=1
_continue=1
log_error() {
	test $_log -eq 1 && echo_i "error: $1"
	ret=$((ret+1))

	test $_continue -eq 1 || exit 1
}

# Check the created key in directory $1 for zone $2.
# $3: key role. Must be one of "csk", "ksk", or "zsk".
# $4: key identifier (zero padded)
# $5: algorithm number
# $6: algorithm (string format)
# $7: algorithm length
# $8: dnskey ttl
# $9: key lifetime
check_created_key() {
	dir=$1
	zone=$2
	role=$3
	key_idpad=$4
	key_id=$(echo $key_idpad | sed 's/^0*//')
	alg_num=$5
        alg_numpad=$(printf "%03d" $alg_num)
	alg_string=$6
	length=$7
	dnskey_ttl=$8
	lifetime=$9

	ksk="no"
	zsk="no"
	if [ "$role" == "ksk" ]; then
		role2="key-signing"
		ksk="yes"
		flags="257"
	elif [ "$role" == "zsk" ]; then
		role2="zone-signing"
		zsk="yes"
		flags="256"
	elif [ "$role" == "csk" ]; then
		role2="key-signing"
		zsk="yes"
		ksk="yes"
		flags="257"
	fi

	KEY_FILE="${dir}/K${zone}.+${alg_numpad}+${key_idpad}.key"
	PRIVATE_FILE="${dir}/K${zone}.+${alg_numpad}+${key_idpad}.private"
	STATE_FILE="${dir}/K${zone}.+${alg_numpad}+${key_idpad}.state"

	# Check the public key file. We expect three lines: a comment,
	# a "Created" line, and the DNSKEY record.
	lines=$(cat $KEY_FILE | wc -l)
	test "$lines" -eq 3 || log_error "bad public keyfile $KEY_FILE"
	grep "This is a ${role2} key, keyid ${key_id}, for ${zone}." $KEY_FILE > /dev/null || log_error "mismatch top comment in $KEY_FILE"
	grep "; Created:" $KEY_FILE > /dev/null || log_error "mismatch created comment in $KEY_FILE"
	grep "${zone}\. ${dnskey_ttl} IN DNSKEY ${flags} 3 ${alg_num}" $KEY_FILE > /dev/null || log_error "mismatch DNSKEY record in $KEY_FILE"
	# Now check the private key file.
	grep "Private-key-format: v1.3" $PRIVATE_FILE > /dev/null || log_error "mismatch private key format in $PRIVATE_FILE"
	grep "Algorithm: ${alg_num} (${alg_string})" $PRIVATE_FILE > /dev/null || log_error "mismatch algorithm in $PRIVATE_FILE"
	grep "Created:" $PRIVATE_FILE > /dev/null || log_error "mismatch created in $PRIVATE_FILE"
	# Now check the key state file. There should be seven lines:
	# a top comment, "Generated", "Lifetime", "Algorithm", "Length",
	# "KSK", and "ZSK".
	lines=$(cat $STATE_FILE | wc -l)
	test "$lines" -eq 7 || log_error "bad state keyfile $STATE_FILE"
	grep "This is the state of key ${key_id}, for ${zone}." $STATE_FILE > /dev/null || log_error "mismatch top comment in $STATE_FILE"
	# XXX: Could check if generated is ~now.
	grep "Generated: " $STATE_FILE > /dev/null || log_error "mismatch generated in $STATE_FILE"
	grep "Lifetime: ${lifetime}" $STATE_FILE > /dev/null || log_error "mismatch lifetime in $STATE_FILE"
	grep "Algorithm: ${alg_num}" $STATE_FILE > /dev/null || log_error "mismatch algorithm in $STATE_FILE"
	grep "Length: ${length}" $STATE_FILE > /dev/null || log_error "mismatch length in $STATE_FILE"
	grep "KSK: ${ksk}" $STATE_FILE > /dev/null || log_error "mismatch ksk in $STATE_FILE"
	grep "ZSK: ${zsk}" $STATE_FILE > /dev/null || log_error "mismatch zsk in $STATE_FILE"
}

################################################################################
# Tests                                                                        #
################################################################################

#
# dnssec-keygen
#
n=$((n+1))
echo_i "check that 'dnssec-keygen -k' (configured policy) creates valid files ($n)"
ret=0
$KEYGEN -K keys -k kasp -l kasp.conf kasp > keygen.out.kasp.test$n 2>/dev/null || ret=1
lines=$(cat keygen.out.kasp.test$n | wc -l)
test "$lines" -eq 4 || log_error "wrong number of keys created for policy kasp"
# Check one algorithm.
KEY_ID=$(get_keyids "keys" "kasp" "13")
echo_i "check key $KEY_ID..."
check_created_key "keys" "kasp" "csk" $KEY_ID "13" "ECDSAP256SHA256" "256" "200" "31536000"
# Temporarily don't log errors because we are searching multiple files.
_log=0
# Check the other algorithm.
KEY_IDS=$(get_keyids "keys" "kasp" "8")
for KEY_ID in $KEY_IDS; do
	echo_i "check key $KEY_ID..."
	# There are three key files with the same algorithm.
	# Check them until a match is found.
	ret=0 && check_created_key "keys" "kasp" "ksk" $KEY_ID "8" "RSASHA256" "2048" "200" "31536000"
	test "$ret" -gt 0 && ret=0 && check_created_key "keys" "kasp" "zsk" $KEY_ID "8" "RSASHA256" "1024" "200" "2592000"
	test "$ret" -gt 0 && ret=0 && check_created_key "keys" "kasp" "zsk" $KEY_ID "8" "RSASHA256" "2000" "200" "16070400"
	# If ret is non-zero, non of the files matched.
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
done
# Turn error logs on again.
_log=1

n=$((n+1))
echo_i "check that 'dnssec-keygen -k' (default policy) creates valid files ($n)"
ret=0
$KEYGEN -k _default kasp > keygen.out._default.test$n 2>/dev/null || ret=1
lines=$(cat keygen.out._default.test$n | wc -l)
test "$lines" -eq 1 || log_error "wrong number of keys created for policy _default"
KEY_ID=$(get_keyids "." "kasp" "13")
echo_i "check key $KEY_ID..."
check_created_key "." "kasp" "csk" $KEY_ID "13" "ECDSAP256SHA256" "256" "3600" "0"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-keygen -k' (default policy) creates valid files ($n)"
ret=0
$KEYGEN -k default kasp > keygen.out.default.test$n 2>/dev/null || ret=1
lines=$(cat keygen.out.default.test$n | wc -l)
test "$lines" -eq 1 || log_error "wrong number of keys created for policy default"
KEY_ID=$(get_keyids "." "kasp" "13")
echo_i "check key $KEY_ID..."
check_created_key "." "kasp" "csk" $KEY_ID "13" "ECDSAP256SHA256" "256" "3600" "0"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

#
# dnssec-settime
#
BASE_FILE="K${zone}.+${alg_numpad}+${key_idpad}"
KEY_FILE="${BASE_FILE}.key"
PRIVATE_FILE="${BASE_FILE}.private"
STATE_FILE="${BASE_FILE}.state"
CMP_FILE="${BASE_FILE}.cmp"

n=$((n+1))
echo_i "check that 'dnssec-settime' by default does not edit key state file ($n)"
ret=0
cp $STATE_FILE $CMP_FILE
$SETTIME -P +3600 $BASE_FILE >/dev/null || log_error "settime failed"
grep "; Publish: " $KEY_FILE > /dev/null || log_error "mismatch published in $KEY_FILE"
grep "Publish: " $PRIVATE_FILE > /dev/null || log_error "mismatch published in $PRIVATE_FILE"
$DIFF $CMP_FILE $STATE_FILE || log_error "unexpected file change in $STATE_FILE"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-settime -s' also sets time metadata in key state file ($n)"
ret=0
cp $STATE_FILE $CMP_FILE
now=$(date +%Y%m%d%H%M%S)
$SETTIME -s -P $now $BASE_FILE >/dev/null || log_error "settime failed"
grep "; Publish: $now" $KEY_FILE > /dev/null || log_error "mismatch published in $KEY_FILE"
grep "Publish: $now" $PRIVATE_FILE > /dev/null || log_error "mismatch published in $PRIVATE_FILE"
grep "Published: $now" $STATE_FILE > /dev/null || log_error "mismatch published in $STATE_FILE"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-settime -s' also unsets time metadata in key state file ($n)"
ret=0
cp $STATE_FILE $CMP_FILE
$SETTIME -s -P none $BASE_FILE >/dev/null || log_error "settime failed"
grep "; Publish:" $KEY_FILE > /dev/null && log_error "unexpected published in $KEY_FILE"
grep "Publish:" $PRIVATE_FILE > /dev/null && log_error "unexpected published in $PRIVATE_FILE"
grep "Published:" $STATE_FILE > /dev/null && log_error "unexpected published in $STATE_FILE"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

#
# named
#


echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1

