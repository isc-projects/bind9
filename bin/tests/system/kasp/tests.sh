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

status=0
n=0

###############################################################################
# Constants                                                                   #
###############################################################################
DEFAULT_TTL=300

###############################################################################
# Key properties                                                              #
###############################################################################
ID=0
EXPECT=1
ROLE=2
KSK=3
ZSK=4
LIFETIME=5
ALG_NUM=6
ALG_STR=7
ALG_LEN=8
PUBLISHED=9
ACTIVE=10
RETIRED=11
REVOKED=12
REMOVED=13
GOAL=14
STATE_DNSKEY=15
STATE_ZRRSIG=16
STATE_KRRSIG=17
STATE_DS=18
EXPECT_RRSIG=19

# Clear key state.
#
# This will update either the KEY1, KEY2, or KEY3 array.
key_clear() {
	_key=(	[$ID]="no" [$EXPECT]="no" \
		[$ROLE]="none" [$KSK]="no" [$ZSK]="no" \
		[$LIFETIME]="0" [$ALG_NUM]="0" \
		[$ALG_STR]="none" [$ALG_LEN]="0" \
		[$PUBLISHED]="none" [$ACTIVE]="none" \
		[$RETIRED]="none" [$REVOKED]="none" \
		[$REMOVED]="none" \
		[$GOAL]="none" [$STATE_DNSKEY]="none" \
		[$STATE_KRRSIG]="none" [$STATE_ZRRSIG]="none" \
		[$STATE_DS]="none" [$EXPECT_RRSIG]="no")

	if [ $1 == "KEY1" ]; then
		KEY1=(${_key[*]})
	elif [ $1 == "KEY2" ]; then
		KEY2=(${_key[*]})
	elif [ $1 == "KEY3" ]; then
		KEY3=(${_key[*]})
	fi
}

# Start clear.
key_clear "KEY1"
key_clear "KEY2"
key_clear "KEY3"

###############################################################################
# Utilities                                                                   #
###############################################################################

# Call dig with default options.
dig_with_opts() {
	"$DIG" +tcp +noadd +nosea +nostat +nocmd +dnssec -p "$PORT" "$@"
}

# RNDC.
rndccmd() {
    "$RNDC" -c "$SYSTEMTESTTOP/common/rndc.conf" -p "$CONTROLPORT" -s "$@"
}

# Print IDs of keys used for generating RRSIG records for RRsets of type $1
# found in dig output file $2.
get_keys_which_signed() {
	_qtype=$1
	_output=$2
	# The key ID is the 11th column of the RRSIG record line.
	awk -v qt="$_qtype" '$4 == "RRSIG" && $5 == qt {print $11}' < "$_output"
}

# Get the key ids from key files for zone $2 in directory $1
# that matches algorithm $3.
get_keyids() {
	_dir=$1
	_zone=$2
	_algorithm=$(printf "%03d" $3)
	_start="${_dir}/K${_zone}.+${_algorithm}+"
	_end=".key"

	ls ${_start}*${_end} | sed "s/$_dir\/K${_zone}.+${_algorithm}+\([0-9]\{5\}\)${_end}/\1/"
}

# By default log errors and don't quit immediately.
_log=1
log_error() {
	test $_log -eq 1 && echo_i "error: $1"
	ret=$((ret+1))
}

# Set zone properties for testing keys.
# $1: Key directory
# $2: Zone name
# $3: Policy name
# $4: DNSKEY TTL
# $5: Number of keys
#
# This will set the following environment variables for testing:
# DIR, ZONE, POLICY, DNSKEY_TTL, NUM_KEYS
zone_properties() {
	DIR=$1
	ZONE=$2
	POLICY=$3
	DNSKEY_TTL=$4
	NUM_KEYS=$5
}

# Set key properties for testing keys.
# $1: Key to update
# $2: Role
# $3: Lifetime
# $4: Algorithm (number)
# $5: Algorithm (string-format)
# $6: Algorithm length
# $7: Is signing
#
# This will update either the KEY1, KEY2 or KEY3 array.
key_properties() {
	if [ $1 == "KEY1" ]; then
		KEY1[$EXPECT]="yes"
		KEY1[$ROLE]=$2
		KEY1[$KSK]="no"
		KEY1[$ZSK]="no"
		test $2 == "ksk" && KEY1[$KSK]="yes"
		test $2 == "zsk" && KEY1[$ZSK]="yes"
		test $2 == "csk" && KEY1[$KSK]="yes"
		test $2 == "csk" && KEY1[$ZSK]="yes"
		KEY1[$LIFETIME]=$3
		KEY1[$ALG_NUM]=$4
		KEY1[$ALG_STR]=$5
		KEY1[$ALG_LEN]=$6
		KEY1[$EXPECT_RRSIG]=$7
	elif [ $1 == "KEY2" ]; then
		KEY2[$EXPECT]="yes"
		KEY2[$ROLE]=$2
		KEY2[$KSK]="no"
		KEY2[$ZSK]="no"
		test $2 == "ksk" && KEY2[$KSK]="yes"
		test $2 == "zsk" && KEY2[$ZSK]="yes"
		test $2 == "csk" && KEY2[$KSK]="yes"
		test $2 == "csk" && KEY2[$ZSK]="yes"
		KEY2[$LIFETIME]=$3
		KEY2[$ALG_NUM]=$4
		KEY2[$ALG_STR]=$5
		KEY2[$ALG_LEN]=$6
		KEY2[$EXPECT_RRSIG]=$7
	elif [ $1 == "KEY3" ]; then
		KEY3[$EXPECT]="yes"
		KEY3[$ROLE]=$2
		KEY3[$KSK]="no"
		KEY3[$ZSK]="no"
		test $2 == "ksk" && KEY3[$KSK]="yes"
		test $2 == "zsk" && KEY3[$ZSK]="yes"
		test $2 == "csk" && KEY3[$KSK]="yes"
		test $2 == "csk" && KEY3[$ZSK]="yes"
		KEY3[$LIFETIME]=$3
		KEY3[$ALG_NUM]=$4
		KEY3[$ALG_STR]=$5
		KEY3[$ALG_LEN]=$6
		KEY3[$EXPECT_RRSIG]=$7
	fi
}

# Set key timing metadata. Set to "none" to unset.
# These times are hard to test, so it is just an indication that we expect the
# respective timing metadata in the key files.
# $1: Key to update
# $2: Published
# $3: Active
# $4: Retired
# $5: Revoked
# $6: Removed
#
# This will update either the KEY1, KEY2 or KEY3 array.
key_timings() {
	if [ $1 == "KEY1" ]; then
		KEY1[$EXPECT]="yes"
		KEY1[$PUBLISHED]=$2
		KEY1[$ACTIVE]=$3
		KEY1[$RETIRED]=$4
		KEY1[$REVOKED]=$5
		KEY1[$REMOVED]=$6
	elif [ $1 == "KEY2" ]; then
		KEY2[$EXPECT]="yes"
		KEY2[$PUBLISHED]=$2
		KEY2[$ACTIVE]=$3
		KEY2[$RETIRED]=$4
		KEY2[$REVOKED]=$5
		KEY2[$REMOVED]=$6
	elif [ $1 == "KEY3" ]; then
		KEY3[$EXPECT]="yes"
		KEY3[$PUBLISHED]=$2
		KEY3[$ACTIVE]=$3
		KEY3[$RETIRED]=$4
		KEY3[$REVOKED]=$5
		KEY3[$REMOVED]=$6
	fi
}

# Set key state metadata. Set to "none" to unset.
# $1: Key to update
# $2: Goal state
# $3: DNSKEY state
# $4: RRSIG state (zsk)
# $5: RRSIG state (ksk)
# $6: DS state
#
# This will update either the KEY1, KEY2, OR KEY3 array.
key_states() {
	if [ $1 == "KEY1" ]; then
		KEY1[$EXPECT]="yes"
		KEY1[$GOAL]=$2
		KEY1[$STATE_DNSKEY]=$3
		KEY1[$STATE_ZRRSIG]=$4
		KEY1[$STATE_KRRSIG]=$5
		KEY1[$STATE_DS]=$6
	elif [ $1 == "KEY2" ]; then
		KEY2[$EXPECT]="yes"
		KEY2[$GOAL]=$2
		KEY2[$STATE_DNSKEY]=$3
		KEY2[$STATE_ZRRSIG]=$4
		KEY2[$STATE_KRRSIG]=$5
		KEY2[$STATE_DS]=$6
	elif [ $1 == "KEY3" ]; then
		KEY3[$EXPECT]="yes"
		KEY3[$GOAL]=$2
		KEY3[$STATE_DNSKEY]=$3
		KEY3[$STATE_ZRRSIG]=$4
		KEY3[$STATE_KRRSIG]=$5
		KEY3[$STATE_DS]=$6
	fi
}

# Check the key $1 with id $2.
# This requires environment variables to be set with 'zone_properties',
# 'key_properties', 'key_timings', and 'key_states'.
#
# This will set the following environment variables for testing:
# BASE_FILE="${_dir}/K${_zone}.+${_alg_numpad}+${_key_idpad}"
# KEY_FILE="${BASE_FILE}.key"
# PRIVATE_FILE="${BASE_FILE}.private"
# STATE_FILE="${BASE_FILE}.state"
# KEY_ID=$(echo $1 | sed 's/^0*//')
check_key() {
	if [ $1 == "KEY1" ]; then
		_key=(${KEY1[*]})
	elif [ $1 == "KEY2" ]; then
		_key=(${KEY2[*]})
	elif [ $1 == "KEY3" ]; then
		_key=(${KEY3[*]})
	fi

	_dir=$DIR
	_zone=$ZONE
	_role="${_key[$ROLE]}"
	_key_idpad=$2
	_key_id=$(echo $_key_idpad | sed 's/^0*//')
	_alg_num="${_key[$ALG_NUM]}"
        _alg_numpad=$(printf "%03d" $_alg_num)
	_alg_string="${_key[$ALG_STR]}"
	_length="${_key[$ALG_LEN]}"
	_dnskey_ttl=$DNSKEY_TTL
	_lifetime="${_key[$LIFETIME]}"

	_published="${_key[$PUBLISHED]}"
	_active="${_key[$ACTIVE]}"
	_retired="${_key[$RETIRED]}"
	_revoked="${_key[$REVOKED]}"
	_removed="${_key[$REMOVED]}"

	_goal="${_key[$GOAL]}"
	_state_dnskey="${_key[$STATE_DNSKEY]}"
	_state_zrrsig="${_key[$STATE_ZRRSIG]}"
	_state_krrsig="${_key[$STATE_KRRSIG]}"
	_state_ds="${_key[$STATE_DS]}"

	_ksk="no"
	_zsk="no"
	if [ "$_role" == "ksk" ]; then
		_role2="key-signing"
		_ksk="yes"
		_flags="257"
	elif [ "$_role" == "zsk" ]; then
		_role2="zone-signing"
		_zsk="yes"
		_flags="256"
	elif [ "$_role" == "csk" ]; then
		_role2="key-signing"
		_zsk="yes"
		_ksk="yes"
		_flags="257"
	fi

	BASE_FILE="${_dir}/K${_zone}.+${_alg_numpad}+${_key_idpad}"
	KEY_FILE="${BASE_FILE}.key"
	PRIVATE_FILE="${BASE_FILE}.private"
	STATE_FILE="${BASE_FILE}.state"
	KEY_ID="${_key_id}"

	test $_log -eq 1 && echo_i "check key $BASE_FILE"

	# Check the public key file.
	grep "This is a ${_role2} key, keyid ${_key_id}, for ${_zone}." $KEY_FILE > /dev/null || log_error "mismatch top comment in $KEY_FILE"
	grep "${_zone}\. ${_dnskey_ttl} IN DNSKEY ${_flags} 3 ${_alg_num}" $KEY_FILE > /dev/null || log_error "mismatch DNSKEY record in $KEY_FILE"
	# Now check the private key file.
	grep "Private-key-format: v1.3" $PRIVATE_FILE > /dev/null || log_error "mismatch private key format in $PRIVATE_FILE"
	grep "Algorithm: ${_alg_num} (${_alg_string})" $PRIVATE_FILE > /dev/null || log_error "mismatch algorithm in $PRIVATE_FILE"
	# Now check the key state file.
	grep "This is the state of key ${_key_id}, for ${_zone}." $STATE_FILE > /dev/null || log_error "mismatch top comment in $STATE_FILE"
	grep "Lifetime: ${_lifetime}" $STATE_FILE > /dev/null || log_error "mismatch lifetime in $STATE_FILE"
	grep "Algorithm: ${_alg_num}" $STATE_FILE > /dev/null || log_error "mismatch algorithm in $STATE_FILE"
	grep "Length: ${_length}" $STATE_FILE > /dev/null || log_error "mismatch length in $STATE_FILE"
	grep "KSK: ${_ksk}" $STATE_FILE > /dev/null || log_error "mismatch ksk in $STATE_FILE"
	grep "ZSK: ${_zsk}" $STATE_FILE > /dev/null || log_error "mismatch zsk in $STATE_FILE"

	# Check key states.
	if [ "$_goal" == "none" ]; then
		grep "GoalState: " $STATE_FILE > /dev/null && log_error "unexpected goal state in $STATE_FILE"
	else
		grep "GoalState: ${_goal}" $STATE_FILE > /dev/null || log_error "mismatch goal state in $STATE_FILE"
	fi

	if [ "$_state_dnskey" == "none" ]; then
		grep "DNSKEYState: " $STATE_FILE > /dev/null && log_error "unexpected dnskey state in $STATE_FILE"
		grep "DNSKEYChange: " $STATE_FILE > /dev/null && log_error "unexpected dnskey change in $STATE_FILE"
	else
		grep "DNSKEYState: ${_state_dnskey}" $STATE_FILE > /dev/null || log_error "mismatch dnskey state in $STATE_FILE"
		grep "DNSKEYChange: " $STATE_FILE > /dev/null || log_error "mismatch dnskey change in $STATE_FILE"
	fi

	if [ "$_state_zrrsig" == "none" ]; then
		grep "ZRRSIGState: " $STATE_FILE > /dev/null && log_error "unexpected zrrsig state in $STATE_FILE"
		grep "ZRRSIGChange: " $STATE_FILE > /dev/null && log_error "unexpected zrrsig change in $STATE_FILE"
	else
		grep "ZRRSIGState: ${_state_zrrsig}" $STATE_FILE > /dev/null || log_error "mismatch zrrsig state in $STATE_FILE"
		grep "ZRRSIGChange: " $STATE_FILE > /dev/null || log_error "mismatch zrrsig change in $STATE_FILE"
	fi

	if [ "$_state_krrsig" == "none" ]; then
		grep "KRRSIGState: " $STATE_FILE > /dev/null && log_error "unexpected krrsig state in $STATE_FILE"
		grep "KRRSIGChange: " $STATE_FILE > /dev/null && log_error "unexpected krrsig change in $STATE_FILE"
	else
		grep "KRRSIGState: ${_state_krrsig}" $STATE_FILE > /dev/null || log_error "mismatch krrsig state in $STATE_FILE"
		grep "KRRSIGChange: " $STATE_FILE > /dev/null || log_error "mismatch krrsig change in $STATE_FILE"
	fi

	if [ "$_state_ds" == "none" ]; then
		grep "DSState: " $STATE_FILE > /dev/null && log_error "unexpected ds state in $STATE_FILE"
		grep "DSChange: " $STATE_FILE > /dev/null && log_error "unexpected ds change in $STATE_FILE"
	else
		grep "DSState: ${_state_ds}" $STATE_FILE > /dev/null || log_error "mismatch ds state in $STATE_FILE"
		grep "DSChange: " $STATE_FILE > /dev/null || log_error "mismatch ds change in $STATE_FILE"
	fi

	# Check timing metadata.
	if [ "$_published" == "none" ]; then
		grep "; Publish:" $KEY_FILE > /dev/null && log_error "unexpected publish comment in $KEY_FILE"
		grep "Publish:" $PRIVATE_FILE > /dev/null && log_error "unexpected publish in $PRIVATE_FILE"
		grep "Published: " $STATE_FILE > /dev/null && log_error "unexpected publish in $STATE_FILE"
	else
		grep "; Publish:" $KEY_FILE > /dev/null || log_error "mismatch publish comment in $KEY_FILE ($KEY_PUBLISHED)"
		grep "Publish:" $PRIVATE_FILE > /dev/null || log_error "mismatch publish in $PRIVATE_FILE ($KEY_PUBLISHED)"
		grep "Published:" $STATE_FILE > /dev/null || log_error "mismatch publish in $STATE_FILE ($KEY_PUBLISHED)"
	fi

	if [ "$_active" == "none" ]; then
		grep "; Activate:" $KEY_FILE > /dev/null && log_error "unexpected active comment in $KEY_FILE"
		grep "Activate:" $PRIVATE_FILE > /dev/null && log_error "unexpected active in $PRIVATE_FILE"
		grep "Active: " $STATE_FILE > /dev/null && log_error "unexpected active in $STATE_FILE"
	else
		grep "; Activate:" $KEY_FILE > /dev/null || log_error "mismatch active comment in $KEY_FILE"
		grep "Activate:" $PRIVATE_FILE > /dev/null || log_error "mismatch active in $PRIVATE_FILE"
		grep "Active: " $STATE_FILE > /dev/null || log_error "mismatch active in $STATE_FILE"
	fi

	if [ "$_retired" == "none" ]; then
		grep "; Inactive:" $KEY_FILE > /dev/null && log_error "unexpected retired comment in $KEY_FILE"
		grep "Inactive:" $PRIVATE_FILE > /dev/null && log_error "unexpected retired in $PRIVATE_FILE"
		grep "Retired: " $STATE_FILE > /dev/null && log_error "unexpected retired in $STATE_FILE"
	else
		grep "; Inactive:" $KEY_FILE > /dev/null || log_error "mismatch retired comment in $KEY_FILE"
		grep "Inactive:" $PRIVATE_FILE > /dev/null || log_error "mismatch retired in $PRIVATE_FILE"
		grep "Retired: " $STATE_FILE > /dev/null || log_error "mismatch retired in $STATE_FILE"
	fi

	if [ "$_revoked" == "none" ]; then
		grep "; Revoke:" $KEY_FILE > /dev/null && log_error "unexpected revoked comment in $KEY_FILE"
		grep "Revoke:" $PRIVATE_FILE > /dev/null && log_error "unexpected revoked in $PRIVATE_FILE"
		grep "Revoked: " $STATE_FILE > /dev/null && log_error "unexpected revoked in $STATE_FILE"
	else
		grep "; Revoke:" $KEY_FILE > /dev/null || log_error "mismatch revoked comment in $KEY_FILE"
		grep "Revoke:" $PRIVATE_FILE > /dev/null || log_error "mismatch revoked in $PRIVATE_FILE"
		grep "Revoked: " $STATE_FILE > /dev/null || log_error "mismatch revoked in $STATE_FILE"
	fi

	if [ "$_removed" == "none" ]; then
		grep "; Delete:" $KEY_FILE > /dev/null && log_error "unexpected removed comment in $KEY_FILE"
		grep "Delete:" $PRIVATE_FILE > /dev/null && log_error "unexpected removed in $PRIVATE_FILE"
		grep "Removed: " $STATE_FILE > /dev/null && log_error "unexpected removed in $STATE_FILE"
	else
		grep "; Delete:" $KEY_FILE > /dev/null || log_error "mismatch removed comment in $KEY_FILE"
		grep "Delete:" $PRIVATE_FILE > /dev/null || log_error "mismatch removed in $PRIVATE_FILE"
		grep "Removed: " $STATE_FILE > /dev/null || log_error "mismatch removed in $STATE_FILE"
	fi

	grep "; Created:" $KEY_FILE > /dev/null || log_error "mismatch created comment in $KEY_FILE"
	grep "Created:" $PRIVATE_FILE > /dev/null || log_error "mismatch created in $PRIVATE_FILE"
	grep "Generated: " $STATE_FILE > /dev/null || log_error "mismatch generated in $STATE_FILE"
}

###############################################################################
# Tests                                                                       #
###############################################################################

#
# dnssec-keygen
#
zone_properties "keys" "kasp" "kasp" "200"

n=$((n+1))
echo_i "check that 'dnssec-keygen -k' (configured policy) creates valid files ($n)"
ret=0
$KEYGEN -K keys -k $POLICY -l kasp.conf $ZONE > keygen.out.$POLICY.test$n 2>/dev/null || ret=1
lines=$(cat keygen.out.$POLICY.test$n | wc -l)
test "$lines" -eq 4 || log_error "wrong number of keys created for policy kasp: $lines"
# Temporarily don't log errors because we are searching multiple files.
_log=0
# Check one algorithm.
key_properties "KEY1" "csk" "31536000" "13" "ECDSAP256SHA256" "256" "yes"
key_timings "KEY1" "none" "none" "none" "none" "none"
key_states "KEY1" "none" "none" "none" "none" "none"
id=$(get_keyids $DIR $ZONE "${KEY1[$ALG_NUM]}")
check_key "KEY1" $id
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))
# Check the other algorithm.
key_properties "KEY1" "ksk" "31536000" "8" "RSASHA256" "2048" "yes"
key_timings "KEY1" "none" "none" "none" "none" "none"
key_states "KEY1" "none" "none" "none" "none" "none"

key_properties "KEY2" "zsk" "2592000" "8" "RSASHA256" "1024" "yes"
key_timings "KEY2" "none" "none" "none" "none" "none"
key_states "KEY2" "none" "none" "none" "none" "none"

key_properties "KEY3" "zsk" "16070400" "8" "RSASHA256" "2000" "yes"
key_timings "KEY3" "none" "none" "none" "none" "none"
key_states "KEY3" "none" "none" "none" "none" "none"

ids=$(get_keyids $DIR $ZONE "${KEY1[$ALG_NUM]}")
for id in $ids; do
	# There are three key files with the same algorithm.
	# Check them until a match is found.
	ret=0 && check_key "KEY1" $id
	test "$ret" -eq 0 && continue

	ret=0 && check_key "KEY2" $id
	test "$ret" -eq 0 && continue

	ret=0 && check_key "KEY3" $id
	# If ret is still non-zero, non of the files matched.
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
done
# Turn error logs on again.
_log=1

n=$((n+1))
echo_i "check that 'dnssec-keygen -k' (default policy) creates valid files ($n)"
ret=0
zone_properties "." "kasp" "default" "3600"
key_properties "KEY1" "csk" "0" "13" "ECDSAP256SHA256" "256" "yes"
key_timings "KEY1" "none" "none" "none" "none" "none"
key_states "KEY1" "none" "none" "none" "none" "none"
$KEYGEN -k $POLICY $ZONE > keygen.out.$POLICY.test$n 2>/dev/null || ret=1
lines=$(cat keygen.out.default.test$n | wc -l)
test "$lines" -eq 1 || log_error "wrong number of keys created for policy default: $lines"
id=$(get_keyids $DIR $ZONE "${KEY1[$ALG_NUM]}")
check_key "KEY1" $id
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-keygen -k' (default policy) creates valid files ($n)"
ret=0
zone_properties "." "kasp" "default" "3600"
key_properties "KEY1" "csk" "0" "13" "ECDSAP256SHA256" "256" "yes"
key_timings "KEY1" "none" "none" "none" "none" "none"
key_states "KEY1" "none" "none" "none" "none" "none"
$KEYGEN -k $POLICY $ZONE > keygen.out.$POLICY.test$n 2>/dev/null || ret=1
lines=$(cat keygen.out.$POLICY.test$n | wc -l)
test "$lines" -eq 1 || log_error "wrong number of keys created for policy default: $lines"
id=$(get_keyids $DIR $ZONE "${KEY1[$ALG_NUM]}")
check_key "KEY1" $id
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

#
# dnssec-settime
#

# These test builds upon the latest created key with dnssec-keygen and uses the
# environment variables BASE_FILE, KEY_FILE, PRIVATE_FILE and STATE_FILE.
CMP_FILE="${BASE_FILE}.cmp"
n=$((n+1))
echo_i "check that 'dnssec-settime' by default does not edit key state file ($n)"
ret=0
cp $STATE_FILE $CMP_FILE
$SETTIME -P +3600 $BASE_FILE > /dev/null || log_error "settime failed"
grep "; Publish: " $KEY_FILE > /dev/null || log_error "mismatch published in $KEY_FILE"
grep "Publish: " $PRIVATE_FILE > /dev/null || log_error "mismatch published in $PRIVATE_FILE"
$DIFF $CMP_FILE $STATE_FILE || log_error "unexpected file change in $STATE_FILE"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-settime -s' also sets publish time metadata and states in key state file ($n)"
ret=0
cp $STATE_FILE $CMP_FILE
now=$(date +%Y%m%d%H%M%S)
$SETTIME -s -P $now -g "omnipresent" -k "rumoured" $now -z "omnipresent" $now -r "rumoured" $now -d "hidden" $now $BASE_FILE > /dev/null || log_error "settime failed"
key_timings "KEY1" "published" "none" "none" "none" "none"
key_states "KEY1" "omnipresent" "rumoured" "omnipresent" "rumoured" "hidden"
check_key "KEY1" $id
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-settime -s' also unsets publish time metadata and states in key state file ($n)"
ret=0
cp $STATE_FILE $CMP_FILE
$SETTIME -s -P "none" -g "none" -k "none" $now -z "none" $now -r "none" $now -d "none" $now $BASE_FILE > /dev/null || log_error "settime failed"
key_timings "KEY1" "none" "none" "none" "none" "none"
key_states "KEY1" "none" "none" "none" "none" "none"
check_key "KEY1" $id
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-settime -s' also sets active time metadata and states in key state file (uppercase) ($n)"
ret=0
cp $STATE_FILE $CMP_FILE
now=$(date +%Y%m%d%H%M%S)
$SETTIME -s -A $now -g "HIDDEN" -k "UNRETENTIVE" $now -z "UNRETENTIVE" $now -r "OMNIPRESENT" $now -d "OMNIPRESENT" $now $BASE_FILE > /dev/null || log_error "settime failed"
key_timings "KEY1" "none" "active" "none" "none" "none"
key_states "KEY1" "hidden" "unretentive" "unretentive" "omnipresent" "omnipresent"
check_key "KEY1" $id
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))


#
# named
#


echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
