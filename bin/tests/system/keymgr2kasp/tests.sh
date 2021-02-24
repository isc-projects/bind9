#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=conf.sh
. ../conf.sh

start_time="$(TZ=UTC date +%s)"
status=0
n=0

###############################################################################
# Constants                                                                   #
###############################################################################
DEFAULT_TTL=300

###############################################################################
# Query properties                                                            #
###############################################################################
TSIG=""
SHA1="FrSt77yPTFx6hTs4i2tKLB9LmE0="
SHA224="hXfwwwiag2QGqblopofai9NuW28q/1rH4CaTnA=="
SHA256="R16NojROxtxH/xbDl//ehDsHm5DjWTQ2YXV+hGC2iBY="
VIEW1="YPfMoAk6h+3iN8MDRQC004iSNHY="
VIEW2="4xILSZQnuO1UKubXHkYUsvBRPu8="

###############################################################################
# Key properties                                                              #
###############################################################################
# ID
# BASEFILE
# EXPECT
# ROLE
# KSK
# ZSK
# LIFETIME
# ALG_NUM
# ALG_STR
# ALG_LEN
# CREATED
# PUBLISHED
# ACTIVE
# RETIRED
# REVOKED
# REMOVED
# GOAL
# STATE_DNSKEY
# STATE_ZRRSIG
# STATE_KRRSIG
# STATE_DS
# EXPECT_ZRRSIG
# EXPECT_KRRSIG
# LEGACY

key_key() {
	echo "${1}__${2}"
}

key_get() {
	eval "echo \${$(key_key "$1" "$2")}"
}

key_set() {
	eval "$(key_key "$1" "$2")='$3'"
}

# Save certain values in the KEY array.
key_save()
{
	# Save key id.
	key_set "$1" ID "$KEY_ID"
	# Save base filename.
	key_set "$1" BASEFILE "$BASE_FILE"
	# Save creation date.
	key_set "$1" CREATED "${KEY_CREATED}"
}

# Clear key state.
#
# This will update either the KEY1, KEY2, or KEY3 array.
key_clear() {
	key_set "$1" "ID" 'no'
	key_set "$1" "IDPAD" 'no'
	key_set "$1" "EXPECT" 'no'
	key_set "$1" "ROLE" 'none'
	key_set "$1" "KSK" 'no'
	key_set "$1" "ZSK" 'no'
	key_set "$1" "LIFETIME" 'none'
	key_set "$1" "ALG_NUM" '0'
	key_set "$1" "ALG_STR" 'none'
	key_set "$1" "ALG_LEN" '0'
	key_set "$1" "CREATED" '0'
	key_set "$1" "PUBLISHED" 'none'
	key_set "$1" "SYNCPUBLISH" 'none'
	key_set "$1" "ACTIVE" 'none'
	key_set "$1" "RETIRED" 'none'
	key_set "$1" "REVOKED" 'none'
	key_set "$1" "REMOVED" 'none'
	key_set "$1" "GOAL" 'none'
	key_set "$1" "STATE_DNSKEY" 'none'
	key_set "$1" "STATE_KRRSIG" 'none'
	key_set "$1" "STATE_ZRRSIG" 'none'
	key_set "$1" "STATE_DS" 'none'
	key_set "$1" "EXPECT_ZRRSIG" 'no'
	key_set "$1" "EXPECT_KRRSIG" 'no'
	key_set "$1" "LEGACY" 'no'
}

# Start clear.
# There can be at most 4 keys at the same time during a rollover:
# 2x KSK, 2x ZSK
key_clear "KEY1"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

###############################################################################
# Utilities                                                                   #
###############################################################################

# Call dig with default options.
dig_with_opts() {

	if [ -n "$TSIG" ]; then
		"$DIG" +tcp +noadd +nosea +nostat +nocmd +dnssec -p "$PORT" -y "$TSIG" "$@"
	else
		"$DIG" +tcp +noadd +nosea +nostat +nocmd +dnssec -p "$PORT" "$@"
	fi
}

# RNDC.
rndccmd() {
	"$RNDC" -c ../common/rndc.conf -p "$CONTROLPORT" -s "$@"
}

# Print IDs of keys used for generating RRSIG records for RRsets of type $1
# found in dig output file $2.
get_keys_which_signed() {
	_qtype=$1
	_output=$2
	# The key ID is the 11th column of the RRSIG record line.
	awk -v qt="$_qtype" '$4 == "RRSIG" && $5 == qt {print $11}' < "$_output"
}

# Get the key ids from key files for zone $2 in directory $1.
get_keyids() {
	_dir=$1
	_zone=$2
	_regex="K${_zone}.+*+*.key"

	find "${_dir}" -mindepth 1 -maxdepth 1 -name "${_regex}" | sed "s,$_dir/K${_zone}.+\([0-9]\{3\}\)+\([0-9]\{5\}\).key,\2,"
}

# By default log errors and don't quit immediately.
_log=1
log_error() {
	test $_log -eq 1 && echo_i "error: $1"
	ret=$((ret+1))
}
# Set server key-directory ($1) and address ($2) for testing keys.
set_server() {
	DIR=$1
	SERVER=$2
}
# Set zone name for testing keys.
set_zone() {
	ZONE=$1
	DYNAMIC="no"
}
# By default zones are considered static.
# When testing dynamic zones, call 'set_dynamic' after 'set_zone'.
set_dynamic() {
	DYNAMIC="yes"
}

# Set policy settings (name $1, number of keys $2, dnskey ttl $3) for testing keys.
set_policy() {
	POLICY=$1
	NUM_KEYS=$2
	DNSKEY_TTL=$3
	CDS_DELETE="no"
}
# By default policies are considered to be secure.
# If a zone sets its policy to "none", call 'set_cdsdelete' to tell the system
# test to expect a CDS and CDNSKEY Delete record.
set_cdsdelete() {
	CDS_DELETE="yes"
}

# Set key properties for testing keys.
# $1: Key to update (KEY1, KEY2, ...)
# $2: Value
set_keyrole() {
	key_set "$1" "EXPECT" "yes"
	key_set "$1" "ROLE" "$2"
	key_set "$1" "KSK" "no"
	key_set "$1" "ZSK" "no"
	test "$2" = "ksk" && key_set "$1" "KSK" "yes"
	test "$2" = "zsk" && key_set "$1" "ZSK" "yes"
	test "$2" = "csk" && key_set "$1" "KSK" "yes"
	test "$2" = "csk" && key_set "$1" "ZSK" "yes"
}
set_keylifetime() {
	key_set "$1" "EXPECT" "yes"
	key_set "$1" "LIFETIME" "$2"
}
# The algorithm value consists of three parts:
# $2: Algorithm (number)
# $3: Algorithm (string-format)
# $4: Algorithm length
set_keyalgorithm() {
	key_set "$1" "EXPECT" "yes"
	key_set "$1" "ALG_NUM" "$2"
	key_set "$1" "ALG_STR" "$3"
	key_set "$1" "ALG_LEN" "$4"
}
set_keysigning() {
	key_set "$1" "EXPECT" "yes"
	key_set "$1" "EXPECT_KRRSIG" "$2"
}
set_zonesigning() {
	key_set "$1" "EXPECT" "yes"
	key_set "$1" "EXPECT_ZRRSIG" "$2"
}

# Set key timing metadata. Set to "none" to unset.
# $1: Key to update (KEY1, KEY2, ...)
# $2: Time to update (PUBLISHED, SYNCPUBLISH, ACTIVE, RETIRED, REVOKED, or REMOVED).
# $3: Value
set_keytime() {
	key_set "$1" "EXPECT" "yes"
	key_set "$1" "$2" "$3"
}

# Set key timing metadata to a value plus additional time.
# $1: Key to update (KEY1, KEY2, ...)
# $2: Time to update (PUBLISHED, SYNCPUBLISH, ACTIVE, RETIRED, REVOKED, or REMOVED).
# $3: Value
# $4: Additional time.
set_addkeytime() {
	echo_i "set_addkeytime $1 $2 $3 $4"


	if [ -x "$PYTHON" ]; then
		# Convert "%Y%m%d%H%M%S" format to epoch seconds.
		# Then, add the additional time (can be negative).
		_value=$3
		_plus=$4
		$PYTHON > python.out.$ZONE.$1.$2 <<EOF
from datetime import datetime
from datetime import timedelta
_now = datetime.strptime("$_value", "%Y%m%d%H%M%S")
_delta = timedelta(seconds=$_plus)
_then = _now + _delta
print(_then.strftime("%Y%m%d%H%M%S"));
EOF
		# Set the expected timing metadata.
		key_set "$1" "$2" $(cat python.out.$ZONE.$1.$2)
	fi
}

# Set key state metadata. Set to "none" to unset.
# $1: Key to update (KEY1, KEY2, ...)
# $2: Key state to update (GOAL, STATE_DNSKEY, STATE_ZRRSIG, STATE_KRRSIG, or STATE_DS)
# $3: Value
set_keystate() {
	key_set "$1" "EXPECT" "yes"
	key_set "$1" "$2" "$3"
}

# Check the key $1 with id $2.
# This requires environment variables to be set.
#
# This will set the following environment variables for testing:
# BASE_FILE="${_dir}/K${_zone}.+${_alg_numpad}+${_key_idpad}"
# KEY_FILE="${BASE_FILE}.key"
# PRIVATE_FILE="${BASE_FILE}.private"
# STATE_FILE="${BASE_FILE}.state"
# KEY_ID=$(echo $1 | sed 's/^0\{0,4\}//')
# KEY_CREATED (from the KEY_FILE)
check_key() {
	_dir="$DIR"
	_zone="$ZONE"
	_role=$(key_get "$1" ROLE)
	_key_idpad="$2"
	_key_id=$(echo "$_key_idpad" | sed 's/^0\{0,4\}//')
	_alg_num=$(key_get "$1" ALG_NUM)
	_alg_numpad=$(printf "%03d" "$_alg_num")
	_alg_string=$(key_get "$1" ALG_STR)
	_length=$(key_get "$1" "ALG_LEN")
	_dnskey_ttl="$DNSKEY_TTL"
	_lifetime=$(key_get "$1" LIFETIME)
	_legacy=$(key_get "$1" LEGACY)

	_published=$(key_get "$1" PUBLISHED)
	_active=$(key_get "$1" ACTIVE)
	_retired=$(key_get "$1" RETIRED)
	_revoked=$(key_get "$1" REVOKED)
	_removed=$(key_get "$1" REMOVED)

	_goal=$(key_get "$1" GOAL)
	_state_dnskey=$(key_get "$1" STATE_DNSKEY)
	_state_zrrsig=$(key_get "$1" STATE_ZRRSIG)
	_state_krrsig=$(key_get "$1" STATE_KRRSIG)
	_state_ds=$(key_get "$1" STATE_DS)

	_ksk="no"
	_zsk="no"
	if [ "$_role" = "ksk" ]; then
		_role2="key-signing"
		_ksk="yes"
		_flags="257"
	elif [ "$_role" = "zsk" ]; then
		_role2="zone-signing"
		_zsk="yes"
		_flags="256"
	elif [ "$_role" = "csk" ]; then
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

	# Check file existence.
	[ -s "$KEY_FILE" ] || ret=1
	[ -s "$PRIVATE_FILE" ] || ret=1
	if [ "$_legacy" = "no" ]; then
		[ -s "$STATE_FILE" ] || ret=1
	fi
	[ "$ret" -eq 0 ] || log_error "${BASE_FILE} files missing"
	[ "$ret" -eq 0 ] || return

	# Retrieve creation date.
	grep "; Created:" "$KEY_FILE" > "${ZONE}.${KEY_ID}.${_alg_num}.created" || log_error "mismatch created comment in $KEY_FILE"
	KEY_CREATED=$(awk '{print $3}' < "${ZONE}.${KEY_ID}.${_alg_num}.created")

	grep "Created: ${KEY_CREATED}" "$PRIVATE_FILE" > /dev/null || log_error "mismatch created in $PRIVATE_FILE"
	if [ "$_legacy" = "no" ]; then
		grep "Generated: ${KEY_CREATED}" "$STATE_FILE" > /dev/null || log_error "mismatch generated in $STATE_FILE"
	fi

	test $_log -eq 1 && echo_i "check key file $BASE_FILE"

	# Check the public key file.
	grep "This is a ${_role2} key, keyid ${_key_id}, for ${_zone}." "$KEY_FILE" > /dev/null || log_error "mismatch top comment in $KEY_FILE"
	grep "${_zone}\. ${_dnskey_ttl} IN DNSKEY ${_flags} 3 ${_alg_num}" "$KEY_FILE" > /dev/null || log_error "mismatch DNSKEY record in $KEY_FILE"
	# Now check the private key file.
	grep "Private-key-format: v1.3" "$PRIVATE_FILE" > /dev/null || log_error "mismatch private key format in $PRIVATE_FILE"
	grep "Algorithm: ${_alg_num} (${_alg_string})" "$PRIVATE_FILE" > /dev/null || log_error "mismatch algorithm in $PRIVATE_FILE"
	# Now check the key state file.
	if [ "$_legacy" = "no" ]; then
		grep "This is the state of key ${_key_id}, for ${_zone}." "$STATE_FILE" > /dev/null || log_error "mismatch top comment in $STATE_FILE"
		if [ "$_lifetime" = "none" ]; then
			grep "Lifetime: " "$STATE_FILE" > /dev/null && log_error "unexpected lifetime in $STATE_FILE"
		else
			grep "Lifetime: ${_lifetime}" "$STATE_FILE" > /dev/null || log_error "mismatch lifetime in $STATE_FILE"
		fi
		grep "Algorithm: ${_alg_num}" "$STATE_FILE" > /dev/null || log_error "mismatch algorithm in $STATE_FILE"
		grep "Length: ${_length}" "$STATE_FILE" > /dev/null || log_error "mismatch length in $STATE_FILE"
		grep "KSK: ${_ksk}" "$STATE_FILE" > /dev/null || log_error "mismatch ksk in $STATE_FILE"
		grep "ZSK: ${_zsk}" "$STATE_FILE" > /dev/null || log_error "mismatch zsk in $STATE_FILE"

		# Check key states.
		if [ "$_goal" = "none" ]; then
			grep "GoalState: " "$STATE_FILE" > /dev/null && log_error "unexpected goal state in $STATE_FILE"
		else
			grep "GoalState: ${_goal}" "$STATE_FILE" > /dev/null || log_error "mismatch goal state in $STATE_FILE"
		fi

		if [ "$_state_dnskey" = "none" ]; then
			grep "DNSKEYState: " "$STATE_FILE" > /dev/null && log_error "unexpected dnskey state in $STATE_FILE"
			grep "DNSKEYChange: " "$STATE_FILE" > /dev/null && log_error "unexpected dnskey change in $STATE_FILE"
		else
			grep "DNSKEYState: ${_state_dnskey}" "$STATE_FILE" > /dev/null || log_error "mismatch dnskey state in $STATE_FILE"
			grep "DNSKEYChange: " "$STATE_FILE" > /dev/null || log_error "mismatch dnskey change in $STATE_FILE"
		fi

		if [ "$_state_zrrsig" = "none" ]; then
			grep "ZRRSIGState: " "$STATE_FILE" > /dev/null && log_error "unexpected zrrsig state in $STATE_FILE"
			grep "ZRRSIGChange: " "$STATE_FILE" > /dev/null && log_error "unexpected zrrsig change in $STATE_FILE"
		else
			grep "ZRRSIGState: ${_state_zrrsig}" "$STATE_FILE" > /dev/null || log_error "mismatch zrrsig state in $STATE_FILE"
			grep "ZRRSIGChange: " "$STATE_FILE" > /dev/null || log_error "mismatch zrrsig change in $STATE_FILE"
		fi

		if [ "$_state_krrsig" = "none" ]; then
			grep "KRRSIGState: " "$STATE_FILE" > /dev/null && log_error "unexpected krrsig state in $STATE_FILE"
			grep "KRRSIGChange: " "$STATE_FILE" > /dev/null && log_error "unexpected krrsig change in $STATE_FILE"
		else
			grep "KRRSIGState: ${_state_krrsig}" "$STATE_FILE" > /dev/null || log_error "mismatch krrsig state in $STATE_FILE"
			grep "KRRSIGChange: " "$STATE_FILE" > /dev/null || log_error "mismatch krrsig change in $STATE_FILE"
		fi

		if [ "$_state_ds" = "none" ]; then
			grep "DSState: " "$STATE_FILE" > /dev/null && log_error "unexpected ds state in $STATE_FILE"
			grep "DSChange: " "$STATE_FILE" > /dev/null && log_error "unexpected ds change in $STATE_FILE"
		else
			grep "DSState: ${_state_ds}" "$STATE_FILE" > /dev/null || log_error "mismatch ds state in $STATE_FILE"
			grep "DSChange: " "$STATE_FILE" > /dev/null || log_error "mismatch ds change in $STATE_FILE"
		fi
	fi
}

# Check the key timing metadata for key $1.
check_timingmetadata() {
	_dir="$DIR"
	_zone="$ZONE"
	_key_idpad=$(key_get "$1" ID)
	_key_id=$(echo "$_key_idpad" | sed 's/^0\{0,4\}//')
	_alg_num=$(key_get "$1" ALG_NUM)
	_alg_numpad=$(printf "%03d" "$_alg_num")

	_published=$(key_get "$1" PUBLISHED)
	_active=$(key_get "$1" ACTIVE)
	_retired=$(key_get "$1" RETIRED)
	_revoked=$(key_get "$1" REVOKED)
	_removed=$(key_get "$1" REMOVED)

	_goal=$(key_get "$1" GOAL)
	_state_dnskey=$(key_get "$1" STATE_DNSKEY)
	_state_zrrsig=$(key_get "$1" STATE_ZRRSIG)
	_state_krrsig=$(key_get "$1" STATE_KRRSIG)
	_state_ds=$(key_get "$1" STATE_DS)

	_base_file=$(key_get "$1" BASEFILE)
	_key_file="${_base_file}.key"
	_private_file="${_base_file}.private"
	_state_file="${_base_file}.state"

	_published=$(key_get "$1" PUBLISHED)
	_syncpublish=$(key_get "$1" SYNCPUBLISH)
	_active=$(key_get "$1" ACTIVE)
	_retired=$(key_get "$1" RETIRED)
	_revoked=$(key_get "$1" REVOKED)
	_removed=$(key_get "$1" REMOVED)

	# Check timing metadata.
	n=$((n+1))
	echo_i "check key timing metadata for key $1 id ${_key_id} zone ${ZONE} ($n)"
	ret=0

	if [ "$_published" = "none" ]; then
		grep "; Publish:" "${_key_file}" > /dev/null && log_error "unexpected publish comment in ${_key_file}"
		grep "Publish:" "${_private_file}" > /dev/null && log_error "unexpected publish in ${_private_file}"
		if [ "$_legacy" = "no" ]; then
			grep "Published: " "${_state_file}" > /dev/null && log_error "unexpected publish in ${_state_file}"
		fi
	else
		grep "; Publish: $_published" "${_key_file}" > /dev/null || log_error "mismatch publish comment in ${_key_file} (expected ${_published})"
		grep "Publish: $_published" "${_private_file}" > /dev/null || log_error "mismatch publish in ${_private_file} (expected ${_published})"
		if [ "$_legacy" = "no" ]; then
			grep "Published: $_published" "${_state_file}" > /dev/null || log_error "mismatch publish in ${_state_file} (expected ${_published})"
		fi
	fi

	if [ "$_syncpublish" = "none" ]; then
		grep "; SyncPublish:" "${_key_file}" > /dev/null && log_error "unexpected syncpublish comment in ${_key_file}"
		grep "SyncPublish:" "${_private_file}" > /dev/null && log_error "unexpected syncpublish in ${_private_file}"
		if [ "$_legacy" = "no" ]; then
			grep "PublishCDS: " "${_state_file}" > /dev/null && log_error "unexpected syncpublish in ${_state_file}"
		fi
	else
		grep "; SyncPublish: $_syncpublish" "${_key_file}" > /dev/null || log_error "mismatch syncpublish comment in ${_key_file} (expected ${_syncpublish})"
		grep "SyncPublish: $_syncpublish" "${_private_file}" > /dev/null || log_error "mismatch syncpublish in ${_private_file} (expected ${_syncpublish})"
		if [ "$_legacy" = "no" ]; then
			grep "PublishCDS: $_syncpublish" "${_state_file}" > /dev/null || log_error "mismatch syncpublish in ${_state_file} (expected ${_syncpublish})"
		fi
	fi

	if [ "$_active" = "none" ]; then
		grep "; Activate:" "${_key_file}" > /dev/null && log_error "unexpected active comment in ${_key_file}"
		grep "Activate:" "${_private_file}" > /dev/null && log_error "unexpected active in ${_private_file}"
		if [ "$_legacy" = "no" ]; then
			grep "Active: " "${_state_file}" > /dev/null && log_error "unexpected active in ${_state_file}"
		fi
	else
		grep "; Activate: $_active" "${_key_file}" > /dev/null || log_error "mismatch active comment in ${_key_file} (expected ${_active})"
		grep "Activate: $_active" "${_private_file}" > /dev/null || log_error "mismatch active in ${_private_file} (expected ${_active})"
		if [ "$_legacy" = "no" ]; then
			grep "Active: $_active" "${_state_file}" > /dev/null || log_error "mismatch active in ${_state_file} (expected ${_active})"
		fi
	fi

	if [ "$_retired" = "none" ]; then
		grep "; Inactive:" "${_key_file}" > /dev/null && log_error "unexpected retired comment in ${_key_file}"
		grep "Inactive:" "${_private_file}" > /dev/null && log_error "unexpected retired in ${_private_file}"
		if [ "$_legacy" = "no" ]; then
			grep "Retired: " "${_state_file}" > /dev/null && log_error "unexpected retired in ${_state_file}"
		fi
	else
		grep "; Inactive: $_retired" "${_key_file}" > /dev/null || log_error "mismatch retired comment in ${_key_file} (expected ${_retired})"
		grep "Inactive: $_retired" "${_private_file}" > /dev/null || log_error "mismatch retired in ${_private_file} (expected ${_retired})"
		if [ "$_legacy" = "no" ]; then
			grep "Retired: $_retired" "${_state_file}" > /dev/null || log_error "mismatch retired in ${_state_file} (expected ${_retired})"
		fi
	fi

	if [ "$_revoked" = "none" ]; then
		grep "; Revoke:" "${_key_file}" > /dev/null && log_error "unexpected revoked comment in ${_key_file}"
		grep "Revoke:" "${_private_file}" > /dev/null && log_error "unexpected revoked in ${_private_file}"
		if [ "$_legacy" = "no" ]; then
			grep "Revoked: " "${_state_file}" > /dev/null && log_error "unexpected revoked in ${_state_file}"
		fi
	else
		grep "; Revoke: $_revoked" "${_key_file}" > /dev/null || log_error "mismatch revoked comment in ${_key_file} (expected ${_revoked})"
		grep "Revoke: $_revoked" "${_private_file}" > /dev/null || log_error "mismatch revoked in ${_private_file} (expected ${_revoked})"
		if [ "$_legacy" = "no" ]; then
			grep "Revoked: $_revoked" "${_state_file}" > /dev/null || log_error "mismatch revoked in ${_state_file} (expected ${_revoked})"
		fi
	fi

	if [ "$_removed" = "none" ]; then
		grep "; Delete:" "${_key_file}" > /dev/null && log_error "unexpected removed comment in ${_key_file}"
		grep "Delete:" "${_private_file}" > /dev/null && log_error "unexpected removed in ${_private_file}"
		if [ "$_legacy" = "no" ]; then
			grep "Removed: " "${_state_file}" > /dev/null && log_error "unexpected removed in ${_state_file}"
		fi
	else
		grep "; Delete: $_removed" "${_key_file}" > /dev/null || log_error "mismatch removed comment in ${_key_file} (expected ${_removed})"
		grep "Delete: $_removed" "${_private_file}" > /dev/null || log_error "mismatch removed in ${_private_file} (expected ${_removed})"
		if [ "$_legacy" = "no" ]; then
			grep "Removed: $_removed" "${_state_file}" > /dev/null || log_error "mismatch removed in ${_state_file} (expected ${_removed})"
		fi
	fi

	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
}

check_keytimes() {
	# The script relies on Python to set keytimes.
	if [ -x "$PYTHON" ]; then

		if [ "$(key_get KEY1 EXPECT)" = "yes" ]; then
			check_timingmetadata "KEY1"
		fi
		if [ "$(key_get KEY2 EXPECT)" = "yes" ]; then
			check_timingmetadata "KEY2"
		fi
		if [ "$(key_get KEY3 EXPECT)" = "yes" ]; then
			check_timingmetadata "KEY3"
		fi
		if [ "$(key_get KEY4 EXPECT)" = "yes" ]; then
			check_timingmetadata "KEY4"
		fi
	fi
}

# Check the key with key id $1 and see if it is unused.
# This requires environment variables to be set.
#
# This will set the following environment variables for testing:
# BASE_FILE="${_dir}/K${_zone}.+${_alg_numpad}+${_key_idpad}"
# KEY_FILE="${BASE_FILE}.key"
# PRIVATE_FILE="${BASE_FILE}.private"
# STATE_FILE="${BASE_FILE}.state"
# KEY_ID=$(echo $1 | sed 's/^0\{0,4\}//')
key_unused() {
	_dir=$DIR
	_zone=$ZONE
	_key_idpad=$1
	_key_id=$(echo "$_key_idpad" | sed 's/^0\{0,4\}//')
	_alg_num=$2
        _alg_numpad=$(printf "%03d" "$_alg_num")

	BASE_FILE="${_dir}/K${_zone}.+${_alg_numpad}+${_key_idpad}"
	KEY_FILE="${BASE_FILE}.key"
	PRIVATE_FILE="${BASE_FILE}.private"
	STATE_FILE="${BASE_FILE}.state"
	KEY_ID="${_key_id}"

	test $_log -eq 1 && echo_i "key unused $KEY_ID?"

	# Check file existence.
	[ -s "$KEY_FILE" ] || ret=1
	[ -s "$PRIVATE_FILE" ] || ret=1
	[ -s "$STATE_FILE" ] || ret=1
	[ "$ret" -eq 0 ] || return

	# Treat keys that have been removed from the zone as unused.
	_check_removed=1
	grep "; Created:" "$KEY_FILE" > created.key-${KEY_ID}.test${n} || _check_removed=0
	grep "; Delete:" "$KEY_FILE" > unused.key-${KEY_ID}.test${n} || _check_removed=0
	if [ "$_check_removed" -eq 1 ]; then
		_created=$(awk '{print $3}' < created.key-${KEY_ID}.test${n})
		_removed=$(awk '{print $3}' < unused.key-${KEY_ID}.test${n})
		[ "$_removed" -le "$_created" ] && return
	fi

	# If no timing metadata is set, this key is unused.
	grep "; Publish:" "$KEY_FILE" > /dev/null && log_error "unexpected publish comment in $KEY_FILE"
	grep "; Activate:" "$KEY_FILE" > /dev/null && log_error "unexpected active comment in $KEY_FILE"
	grep "; Inactive:" "$KEY_FILE" > /dev/null && log_error "unexpected retired comment in $KEY_FILE"
	grep "; Revoke:" "$KEY_FILE" > /dev/null && log_error "unexpected revoked comment in $KEY_FILE"
	grep "; Delete:" "$KEY_FILE" > /dev/null && log_error "unexpected removed comment in $KEY_FILE"

	grep "Publish:" "$PRIVATE_FILE" > /dev/null && log_error "unexpected publish in $PRIVATE_FILE"
	grep "Activate:" "$PRIVATE_FILE" > /dev/null && log_error "unexpected active in $PRIVATE_FILE"
	grep "Inactive:" "$PRIVATE_FILE" > /dev/null && log_error "unexpected retired in $PRIVATE_FILE"
	grep "Revoke:" "$PRIVATE_FILE" > /dev/null && log_error "unexpected revoked in $PRIVATE_FILE"
	grep "Delete:" "$PRIVATE_FILE" > /dev/null && log_error "unexpected removed in $PRIVATE_FILE"

	grep "Published: " "$STATE_FILE" > /dev/null && log_error "unexpected publish in $STATE_FILE"
	grep "Active: " "$STATE_FILE" > /dev/null && log_error "unexpected active in $STATE_FILE"
	grep "Retired: " "$STATE_FILE" > /dev/null && log_error "unexpected retired in $STATE_FILE"
	grep "Revoked: " "$STATE_FILE" > /dev/null && log_error "unexpected revoked in $STATE_FILE"
	grep "Removed: " "$STATE_FILE" > /dev/null && log_error "unexpected removed in $STATE_FILE"
}

# Test: dnssec-verify zone $1.
dnssec_verify()
{
	n=$((n+1))
	echo_i "dnssec-verify zone ${ZONE} ($n)"
	ret=0
	dig_with_opts "$ZONE" "@${SERVER}" AXFR > dig.out.axfr.test$n || log_error "dig ${ZONE} AXFR failed"
	$VERIFY -z -o "$ZONE" dig.out.axfr.test$n > /dev/null || log_error "dnssec verify zone $ZONE failed"
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
}

# Wait for the zone to be signed.
# The apex NSEC record indicates that it is signed.
_wait_for_nsec() {
	dig_with_opts "@${SERVER}" "$ZONE" NSEC > "dig.out.nsec.test$n" || return 1
	grep "NS SOA" "dig.out.nsec.test$n" > /dev/null || return 1
	grep "${ZONE}\..*IN.*RRSIG" "dig.out.nsec.test$n" > /dev/null || return 1
	return 0
}

wait_for_nsec() {
	n=$((n+1))
	ret=0
	echo_i "wait for ${ZONE} to be signed ($n)"
	retry_quiet 10 _wait_for_nsec  || log_error "wait for ${ZONE} to be signed failed"
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
}

# Default next key event threshold. May be extended by wait periods.
next_key_event_threshold=100

###############################################################################
# Tests                                                                       #
###############################################################################

_wait_for_done_apexnsec() {
	while read -r zone
	do
		dig_with_opts "$zone" @10.53.0.3 nsec > "dig.out.ns3.test$n.$zone" || return 1
		grep "NS SOA" "dig.out.ns3.test$n.$zone" > /dev/null || return 1
		grep "$zone\..*IN.*RRSIG" "dig.out.ns3.test$n.$zone" > /dev/null || return 1
	done < ns3/zones

	return 0
}

check_numkeys() {
	_numkeys=$(get_keyids "$DIR" "$ZONE" | wc -l)
	test "$_numkeys" -eq "$NUM_KEYS" || return 1
	return 0
}

# Check keys for a configured zone. This verifies:
# 1. The right number of keys exist in the key pool ($1).
# 2. The right number of keys is active. Checks KEY1, KEY2, KEY3, and KEY4.
#
# It is expected that KEY1, KEY2, KEY3, and KEY4 arrays are set correctly.
# Found key identifiers are stored in the right key array.
check_keys() {
	n=$((n+1))
	echo_i "check keys are created for zone ${ZONE} ($n)"
	ret=0

	echo_i "check number of keys for zone ${ZONE} in dir ${DIR} ($n)"
	retry_quiet 10 check_numkeys || ret=1
	if [ $ret -ne 0 ]; then
		_numkeys=$(get_keyids "$DIR" "$ZONE" | wc -l)
		log_error "bad number of key files ($_numkeys) for zone $ZONE (expected $NUM_KEYS)"
		status=$((status+ret))
	fi

	# Temporarily don't log errors because we are searching multiple files.
	_log=0

	# Clear key ids.
	key_set KEY1 ID "no"
	key_set KEY2 ID "no"
	key_set KEY3 ID "no"
	key_set KEY4 ID "no"

	# Check key files.
	_ids=$(get_keyids "$DIR" "$ZONE")
	for _id in $_ids; do
		# There are three key files with the same algorithm.
		# Check them until a match is found.
		echo_i "check key id $_id"

		if [ "no" = "$(key_get KEY1 ID)" ] && [ "$(key_get KEY1 EXPECT)" = "yes" ]; then
			ret=0
			check_key "KEY1" "$_id"
			test "$ret" -eq 0 && key_save KEY1 && continue
		fi
		if [ "no" = "$(key_get KEY2 ID)" ] && [ "$(key_get KEY2 EXPECT)" = "yes" ]; then
			ret=0
			check_key "KEY2" "$_id"
			test "$ret" -eq 0 && key_save KEY2 && continue
		fi
		if [ "no" = "$(key_get KEY3 ID)" ] && [ "$(key_get KEY3 EXPECT)" = "yes"  ]; then
			ret=0
			check_key "KEY3" "$_id"
			test "$ret" -eq 0 && key_save KEY3 && continue
		fi
		if [ "no" = "$(key_get KEY4 ID)" ] && [ "$(key_get KEY4 EXPECT)" = "yes"  ]; then
			ret=0
			check_key "KEY4" "$_id"
			test "$ret" -eq 0 && key_save KEY4 && continue
		fi

		# This may be an unused key. Assume algorithm of KEY1.
		ret=0 && key_unused "$_id" "$(key_get KEY1 ALG_NUM)"
		test "$ret" -eq 0 && continue

		# If ret is still non-zero, none of the files matched.
		test "$ret" -eq 0 || echo_i "failed"
		status=$((status+1))
	done

	# Turn error logs on again.
	_log=1

	ret=0
	if [ "$(key_get KEY1 EXPECT)" = "yes" ]; then
		echo_i "KEY1 ID $(key_get KEY1 ID)"
		test "no" = "$(key_get KEY1 ID)" && log_error "No KEY1 found for zone ${ZONE}"
	fi
	if [ "$(key_get KEY2 EXPECT)" = "yes" ]; then
		echo_i "KEY2 ID $(key_get KEY2 ID)"
		test "no" = "$(key_get KEY2 ID)" && log_error "No KEY2 found for zone ${ZONE}"
	fi
	if [ "$(key_get KEY3 EXPECT)" = "yes" ]; then
		echo_i "KEY3 ID $(key_get KEY3 ID)"
		test "no" = "$(key_get KEY3 ID)" && log_error "No KEY3 found for zone ${ZONE}"
	fi
	if [ "$(key_get KEY4 EXPECT)" = "yes" ]; then
		echo_i "KEY4 ID $(key_get KEY4 ID)"
		test "no" = "$(key_get KEY4 ID)" && log_error "No KEY4 found for zone ${ZONE}"
	fi
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
}

# Call rndc dnssec -status on server $1 for zone $2 and check output.
# This is a loose verification, it just tests if the right policy
# name is returned, and if all expected keys are listed.  The rndc
# dnssec -status output also lists whether a key is published,
# used for signing, is retired, or is removed, and if not when
# it is scheduled to do so, and it shows the states for the various
# DNSSEC records.
check_dnssecstatus() {
	_server=$1
	_policy=$2
	_zone=$3
	_view=$4

	n=$((n+1))
	echo_i "check rndc dnssec -status output for ${_zone} (policy: $_policy) ($n)"
	ret=0

	rndccmd $_server dnssec -status $_zone in $_view > rndc.dnssec.status.out.$_zone.$n || log_error "rndc dnssec -status zone ${_zone} failed"

	grep "dnssec-policy: ${_policy}" rndc.dnssec.status.out.$_zone.$n > /dev/null || log_error "bad dnssec status for signed zone ${_zone}"
	if [ "$(key_get KEY1 EXPECT)" = "yes" ]; then
		grep "key: $(key_get KEY1 ID)" rndc.dnssec.status.out.$_zone.$n > /dev/null || log_error "missing key $(key_get KEY1 ID) from dnssec status"
	fi
	if [ "$(key_get KEY2 EXPECT)" = "yes" ]; then
		grep "key: $(key_get KEY2 ID)" rndc.dnssec.status.out.$_zone.$n > /dev/null || log_error "missing key $(key_get KEY2 ID) from dnssec status"
	fi
	if [ "$(key_get KEY3 EXPECT)" = "yes" ]; then
		grep "key: $(key_get KEY3 ID)" rndc.dnssec.status.out.$_zone.$n > /dev/null || log_error "missing key $(key_get KEY3 ID) from dnssec status"
	fi
	if [ "$(key_get KEY4 EXPECT)" = "yes" ]; then
		grep "key: $(key_get KEY4 ID)" rndc.dnssec.status.out.$_zone.$n > /dev/null || log_error "missing key $(key_get KEY4 ID) from dnssec status"
	fi

	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
}

# Check if RRset of type $1 in file $2 is signed with the right keys.
# The right keys are the ones that expect a signature and matches the role $3.
check_signatures() {
	_qtype=$1
	_file=$2
	_role=$3

	if [ "$_role" = "KSK" ]; then
		_expect_type=EXPECT_KRRSIG
	elif [ "$_role" = "ZSK" ]; then
		_expect_type=EXPECT_ZRRSIG
	fi

	if [ "$(key_get KEY1 "$_expect_type")" = "yes" ] && [ "$(key_get KEY1 "$_role")" = "yes" ]; then
		get_keys_which_signed "$_qtype" "$_file" | grep "^$(key_get KEY1 ID)$" > /dev/null || log_error "${_qtype} RRset not signed with key $(key_get KEY1 ID)"
	elif [ "$(key_get KEY1 EXPECT)" = "yes" ]; then
		get_keys_which_signed "$_qtype" "$_file" | grep "^$(key_get KEY1 ID)$" > /dev/null && log_error "${_qtype} RRset signed unexpectedly with key $(key_get KEY1 ID)"
	fi

	if [ "$(key_get KEY2 "$_expect_type")" = "yes" ] && [ "$(key_get KEY2 "$_role")" = "yes" ]; then
		get_keys_which_signed "$_qtype" "$_file" | grep "^$(key_get KEY2 ID)$" > /dev/null || log_error "${_qtype} RRset not signed with key $(key_get KEY2 ID)"
	elif [ "$(key_get KEY2 EXPECT)" = "yes" ]; then
		get_keys_which_signed "$_qtype" "$_file" | grep "^$(key_get KEY2 ID)$" > /dev/null && log_error "${_qtype} RRset signed unexpectedly with key $(key_get KEY2 ID)"
	fi

	if [ "$(key_get KEY3 "$_expect_type")" = "yes" ] && [ "$(key_get KEY3 "$_role")" = "yes" ]; then
		get_keys_which_signed "$_qtype" "$_file" | grep "^$(key_get KEY3 ID)$" > /dev/null || log_error "${_qtype} RRset not signed with key $(key_get KEY3 ID)"
	elif [ "$(key_get KEY3 EXPECT)" = "yes" ]; then
		get_keys_which_signed "$_qtype" "$_file" | grep "^$(key_get KEY3 ID)$" > /dev/null && log_error "${_qtype} RRset signed unexpectedly with key $(key_get KEY3 ID)"
	fi

	if [ "$(key_get KEY4 "$_expect_type")" = "yes" ] && [ "$(key_get KEY4 "$_role")" = "yes" ]; then
		get_keys_which_signed "$_qtype" "$_file" | grep "^$(key_get KEY4 ID)$" > /dev/null || log_error "${_qtype} RRset not signed with key $(key_get KEY4 ID)"
	elif [ "$(key_get KEY4 EXPECT)" = "yes" ]; then
		get_keys_which_signed "$_qtype" "$_file" | grep "^$(key_get KEY4 ID)$" > /dev/null && log_error "${_qtype} RRset signed unexpectedly with key $(key_get KEY4 ID)"
	fi
}

response_has_cds_for_key() (
	awk -v zone="${ZONE%%.}." \
	    -v ttl="${DNSKEY_TTL}" \
	    -v qtype="CDS" \
	    -v keyid="$(key_get "${1}" ID)" \
	    -v keyalg="$(key_get "${1}" ALG_NUM)" \
	    -v hashalg="2" \
	    'BEGIN { ret=1; }
	     $1 == zone && $2 == ttl && $4 == qtype && $5 == keyid && $6 == keyalg && $7 == hashalg { ret=0; exit; }
	     END { exit ret; }' \
	    "$2"
)

response_has_cdnskey_for_key() (
	awk -v zone="${ZONE%%.}." \
	    -v ttl="${DNSKEY_TTL}" \
	    -v qtype="CDNSKEY" \
	    -v flags="257" \
	    -v keyalg="$(key_get "${1}" ALG_NUM)" \
	    'BEGIN { ret=1; }
	     $1 == zone && $2 == ttl && $4 == qtype && $5 == flags && $7 == keyalg { ret=0; exit; }
	     END { exit ret; }' \
	    "$2"
)

# Test CDS and CDNSKEY publication.
check_cds() {

	n=$((n+1))
	echo_i "check CDS and CDNSKEY rrset are signed correctly for zone ${ZONE} ($n)"
	ret=0

	dig_with_opts "$ZONE" "@${SERVER}" "CDS" > "dig.out.$DIR.test$n.cds" || log_error "dig ${ZONE} CDS failed"
	grep "status: NOERROR" "dig.out.$DIR.test$n.cds" > /dev/null || log_error "mismatch status in DNS response"

	dig_with_opts "$ZONE" "@${SERVER}" "CDNSKEY" > "dig.out.$DIR.test$n.cdnskey" || log_error "dig ${ZONE} CDNSKEY failed"
	grep "status: NOERROR" "dig.out.$DIR.test$n.cdnskey" > /dev/null || log_error "mismatch status in DNS response"

	if [ "$CDS_DELETE" = "no" ]; then
		grep "CDS.*0 0 0 00" "dig.out.$DIR.test$n.cds" > /dev/null && log_error "unexpected CDS DELETE record in DNS response"
		grep "CDNSKEY.*0 3 0 AA==" "dig.out.$DIR.test$n.cdnskey" > /dev/null && log_error "unexpected CDNSKEY DELETE record in DNS response"
	else
		grep "CDS.*0 0 0 00" "dig.out.$DIR.test$n.cds" > /dev/null || log_error "missing CDS DELETE record in DNS response"
		grep "CDNSKEY.*0 3 0 AA==" "dig.out.$DIR.test$n.cdnskey" > /dev/null || log_error "missing CDNSKEY DELETE record in DNS response"
	fi

	if [ "$(key_get KEY1 STATE_DS)" = "rumoured" ] || [ "$(key_get KEY1 STATE_DS)" = "omnipresent" ]; then
		response_has_cds_for_key KEY1 "dig.out.$DIR.test$n.cds" || log_error "missing CDS record in response for key $(key_get KEY1 ID)"
		check_signatures "CDS" "dig.out.$DIR.test$n.cds" "KSK"
		response_has_cdnskey_for_key KEY1 "dig.out.$DIR.test$n.cdnskey" || log_error "missing CDNSKEY record in response for key $(key_get KEY1 ID)"
		check_signatures "CDNSKEY" "dig.out.$DIR.test$n.cdnskey" "KSK"
	elif [ "$(key_get KEY1 EXPECT)" = "yes" ]; then
		response_has_cds_for_key KEY1 "dig.out.$DIR.test$n.cds" && log_error "unexpected CDS record in response for key $(key_get KEY1 ID)"
		# KEY1 should not have an associated CDNSKEY, but there may be
		# one for another key.  Since the CDNSKEY has no field for key
		# id, it is hard to check what key the CDNSKEY may belong to
		# so let's skip this check for now.
	fi

	if [ "$(key_get KEY2 STATE_DS)" = "rumoured" ] || [ "$(key_get KEY2 STATE_DS)" = "omnipresent" ]; then
		response_has_cds_for_key KEY2 "dig.out.$DIR.test$n.cds" || log_error "missing CDS record in response for key $(key_get KEY2 ID)"
		check_signatures "CDS" "dig.out.$DIR.test$n.cds" "KSK"
		response_has_cdnskey_for_key KEY2 "dig.out.$DIR.test$n.cdnskey" || log_error "missing CDNSKEY record in response for key $(key_get KEY2 ID)"
		check_signatures "CDNSKEY" "dig.out.$DIR.test$n.cdnskey" "KSK"
	elif [ "$(key_get KEY2 EXPECT)" = "yes" ]; then
		response_has_cds_for_key KEY2 "dig.out.$DIR.test$n.cds" && log_error "unexpected CDS record in response for key $(key_get KEY2 ID)"
		# KEY2 should not have an associated CDNSKEY, but there may be
		# one for another key.  Since the CDNSKEY has no field for key
		# id, it is hard to check what key the CDNSKEY may belong to
		# so let's skip this check for now.
	fi

	if [ "$(key_get KEY3 STATE_DS)" = "rumoured" ] || [ "$(key_get KEY3 STATE_DS)" = "omnipresent" ]; then
		response_has_cds_for_key KEY3 "dig.out.$DIR.test$n.cds" || log_error "missing CDS record in response for key $(key_get KEY3 ID)"
		check_signatures "CDS" "dig.out.$DIR.test$n.cds" "KSK"
		response_has_cdnskey_for_key KEY3 "dig.out.$DIR.test$n.cdnskey" || log_error "missing CDNSKEY record in response for key $(key_get KEY3 ID)"
		check_signatures "CDNSKEY" "dig.out.$DIR.test$n.cdnskey" "KSK"
	elif [ "$(key_get KEY3 EXPECT)" = "yes" ]; then
		response_has_cds_for_key KEY3 "dig.out.$DIR.test$n.cds" && log_error "unexpected CDS record in response for key $(key_get KEY3 ID)"
		# KEY3 should not have an associated CDNSKEY, but there may be
		# one for another key.  Since the CDNSKEY has no field for key
		# id, it is hard to check what key the CDNSKEY may belong to
		# so let's skip this check for now.
	fi

	if [ "$(key_get KEY4 STATE_DS)" = "rumoured" ] || [ "$(key_get KEY4 STATE_DS)" = "omnipresent" ]; then
		response_has_cds_for_key KEY4 "dig.out.$DIR.test$n.cds" || log_error "missing CDS record in response for key $(key_get KEY4 ID)"
		check_signatures "CDS" "dig.out.$DIR.test$n.cds" "KSK"
		response_has_cdnskey_for_key KEY4 "dig.out.$DIR.test$n.cdnskey" || log_error "missing CDNSKEY record in response for key $(key_get KEY4 ID)"
		check_signatures "CDNSKEY" "dig.out.$DIR.test$n.cdnskey" "KSK"
	elif [ "$(key_get KEY4 EXPECT)" = "yes" ]; then
		response_has_cds_for_key KEY4 "dig.out.$DIR.test$n.cds" && log_error "unexpected CDS record in response for key $(key_get KEY4 ID)"
		# KEY4 should not have an associated CDNSKEY, but there may be
		# one for another key.  Since the CDNSKEY has no field for key
		# id, it is hard to check what key the CDNSKEY may belong to
		# so let's skip this check for now.
	fi

	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
}

# Test the apex of a configured zone. This checks that the SOA and DNSKEY
# RRsets are signed correctly and with the appropriate keys.
check_apex() {
	# Test DNSKEY query.
	_qtype="DNSKEY"
	n=$((n+1))
	echo_i "check ${_qtype} rrset is signed correctly for zone ${ZONE} ($n)"
	ret=0
	dig_with_opts "$ZONE" "@${SERVER}" $_qtype > "dig.out.$DIR.test$n" || log_error "dig ${ZONE} ${_qtype} failed"
	grep "status: NOERROR" "dig.out.$DIR.test$n" > /dev/null || log_error "mismatch status in DNS response"

	if [ "$(key_get KEY1 STATE_DNSKEY)" = "rumoured" ] || [ "$(key_get KEY1 STATE_DNSKEY)" = "omnipresent" ]; then
		grep "${ZONE}\..*${DNSKEY_TTL}.*IN.*${_qtype}.*257.*.3.*$(key_get KEY1 ALG_NUM)" "dig.out.$DIR.test$n" > /dev/null || log_error "missing ${_qtype} record in response for key $(key_get KEY1 ID)"
		check_signatures $_qtype "dig.out.$DIR.test$n" "KSK"
		numkeys=$((numkeys+1))
	elif [ "$(key_get KEY1 EXPECT)" = "yes" ]; then
		grep "${ZONE}\.*${DNSKEY_TTL}.*IN.*${_qtype}.*257.*.3.*$(key_get KEY1 ALG_NUM)" "dig.out.$DIR.test$n" > /dev/null && log_error "unexpected ${_qtype} record in response for key $(key_get KEY1 ID)"
	fi

	if [ "$(key_get KEY2 STATE_DNSKEY)" = "rumoured" ] || [ "$(key_get KEY2 STATE_DNSKEY)" = "omnipresent" ]; then
		grep "${ZONE}\..*${DNSKEY_TTL}.*IN.*${_qtype}.*257.*.3.*$(key_get KEY2 ALG_NUM)" "dig.out.$DIR.test$n" > /dev/null || log_error "missing ${_qtype} record in response for key $(key_get KEY2 ID)"
		check_signatures $_qtype "dig.out.$DIR.test$n" "KSK"
		numkeys=$((numkeys+1))
	elif [ "$(key_get KEY2 EXPECT)" = "yes" ]; then
		grep "${ZONE}\.*${DNSKEY_TTL}.*IN.*${_qtype}.*257.*.3.*$(key_get KEY2 ALG_NUM)" "dig.out.$DIR.test$n" > /dev/null && log_error "unexpected ${_qtype} record in response for key $(key_get KEY2 ID)"
	fi

	if [ "$(key_get KEY3 STATE_DNSKEY)" = "rumoured" ] || [ "$(key_get KEY3 STATE_DNSKEY)" = "omnipresent" ]; then
		grep "${ZONE}\..*${DNSKEY_TTL}.*IN.*${_qtype}.*257.*.3.*$(key_get KEY3 ALG_NUM)" "dig.out.$DIR.test$n" > /dev/null || log_error "missing ${_qtype} record in response for key $(key_get KEY3 ID)"
		check_signatures $_qtype "dig.out.$DIR.test$n" "KSK"
		numkeys=$((numkeys+1))
	elif [ "$(key_get KEY3 EXPECT)" = "yes" ]; then
		grep "${ZONE}\..*${DNSKEY_TTL}.*IN.*${_qtype}.*257.*.3.*$(key_get KEY3 ALG_NUM)" "dig.out.$DIR.test$n" > /dev/null && log_error "unexpected ${_qtype} record in response for key $(key_get KEY3 ID)"
	fi

	if [ "$(key_get KEY4 STATE_DNSKEY)" = "rumoured" ] || [ "$(key_get KEY4 STATE_DNSKEY)" = "omnipresent" ]; then
		grep "${ZONE}\..*${DNSKEY_TTL}.*IN.*${_qtype}.*257.*.3.*$(key_get KEY4 ALG_NUM)" "dig.out.$DIR.test$n" > /dev/null || log_error "missing ${_qtype} record in response for key $(key_get KEY4 ID)"
		check_signatures $_qtype "dig.out.$DIR.test$n" "KSK"
		numkeys=$((numkeys+1))
	elif [ "$(key_get KEY4 EXPECT)" = "yes" ]; then
		grep "${ZONE}\..*${DNSKEY_TTL}.*IN.*${_qtype}.*257.*.3.*$(key_get KEY4 ALG_NUM)" "dig.out.$DIR.test$n" > /dev/null && log_error "unexpected ${_qtype} record in response for key $(key_get KEY4 ID)"
	fi

	lines=$(get_keys_which_signed $_qtype "dig.out.$DIR.test$n" | wc -l)
	check_signatures $_qtype "dig.out.$DIR.test$n" "KSK"
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))

	# Test SOA query.
	_qtype="SOA"
	n=$((n+1))
	echo_i "check ${_qtype} rrset is signed correctly for zone ${ZONE} ($n)"
	ret=0
	dig_with_opts "$ZONE" "@${SERVER}" $_qtype > "dig.out.$DIR.test$n" || log_error "dig ${ZONE} ${_qtype} failed"
	grep "status: NOERROR" "dig.out.$DIR.test$n" > /dev/null || log_error "mismatch status in DNS response"
	grep "${ZONE}\..*${DEFAULT_TTL}.*IN.*${_qtype}.*" "dig.out.$DIR.test$n" > /dev/null || log_error "missing ${_qtype} record in response"
	lines=$(get_keys_which_signed $_qtype "dig.out.$DIR.test$n" | wc -l)
	check_signatures $_qtype "dig.out.$DIR.test$n" "ZSK"
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))

	# Test CDS and CDNSKEY publication.
	check_cds
}

# Test an RRset below the apex and verify it is signed correctly.
check_subdomain() {
	_qtype="A"
	n=$((n+1))
	echo_i "check ${_qtype} a.${ZONE} rrset is signed correctly for zone ${ZONE} ($n)"
	ret=0
	dig_with_opts "a.$ZONE" "@${SERVER}" $_qtype > "dig.out.$DIR.test$n" || log_error "dig a.${ZONE} ${_qtype} failed"
	grep "status: NOERROR" "dig.out.$DIR.test$n" > /dev/null || log_error "mismatch status in DNS response"
	grep "a.${ZONE}\..*${DEFAULT_TTL}.*IN.*${_qtype}.*10\.0\.0\.1" "dig.out.$DIR.test$n" > /dev/null || log_error "missing a.${ZONE} ${_qtype} record in response"
	lines=$(get_keys_which_signed $_qtype "dig.out.$DIR.test$n" | wc -l)
	check_signatures $_qtype "dig.out.$DIR.test$n" "ZSK"
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
}

# Check if "CDS/CDNSKEY Published" is logged.
check_cdslog() {
	_dir=$1
	_zone=$2
	_key=$3

	_alg=$(key_get $_key ALG_STR)
	_id=$(key_get $_key ID)

	n=$((n+1))
	echo_i "check CDS/CDNSKEY publication is logged in ${_dir}/named.run for key ${_zone}/${_alg}/${_id} ($n)"
	ret=0

	grep "CDS for key ${_zone}/${_alg}/${_id} is now published" "${_dir}/named.run" > /dev/null || ret=1
	grep "CDNSKEY for key ${_zone}/${_alg}/${_id} is now published" "${_dir}/named.run" > /dev/null || ret=1

	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
}

set_retired_removed() {
	_Lkey=$2
	_Iret=$3

	_active=$(key_get $1 ACTIVE)
	set_addkeytime "${1}" "RETIRED" "${_active}"  "${_Lkey}"
	_retired=$(key_get $1 RETIRED)
	set_addkeytime "${1}" "REMOVED" "${_retired}" "${_Iret}"
}

rollover_predecessor_keytimes() {
	_addtime=$1

	_created=$(key_get KEY1 CREATED)

	set_addkeytime  "KEY1" "PUBLISHED"   "${_created}" "${_addtime}"
	set_addkeytime  "KEY1" "SYNCPUBLISH" "${_created}" "${_addtime}"
	set_addkeytime  "KEY1" "ACTIVE"      "${_created}" "${_addtime}"
	[ "$Lksk" = 0 ] || set_retired_removed "KEY1" "${Lksk}" "${IretKSK}"

	_created=$(key_get KEY2 CREATED)
	set_addkeytime  "KEY2" "PUBLISHED"   "${_created}" "${_addtime}"
	set_addkeytime  "KEY2" "ACTIVE"      "${_created}" "${_addtime}"
	[ "$Lzsk" = 0 ] || set_retired_removed "KEY2" "${Lzsk}" "${IretZSK}"
}

# Policy parameters.
# Lksk: unlimited
# Lzsk: unlimited
Lksk=0
Lzsk=0

#
# Testing good migration.
#
set_zone "migrate.kasp"
set_policy "none" "2" "7200"
set_server "ns3" "10.53.0.3"

init_migration_match() {
	key_clear        "KEY1"
	key_set          "KEY1" "LEGACY" "yes"
	set_keyrole      "KEY1" "ksk"
	set_keylifetime  "KEY1" "0"
	set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
	set_keysigning   "KEY1" "yes"
	set_zonesigning  "KEY1" "no"

	key_clear        "KEY2"
	key_set          "KEY2" "LEGACY" "yes"
	set_keyrole      "KEY2" "zsk"
	set_keylifetime  "KEY2" "5184000"
	set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
	set_keysigning   "KEY2" "no"
	set_zonesigning  "KEY2" "yes"

	key_clear        "KEY3"
	key_clear        "KEY4"

	set_keystate "KEY1" "GOAL"         "omnipresent"
	set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
	set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
	set_keystate "KEY1" "STATE_DS"     "rumoured"

	set_keystate "KEY2" "GOAL"         "omnipresent"
	set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
	set_keystate "KEY2" "STATE_ZRRSIG" "rumoured"
}
init_migration_match

# Make sure the zone is signed with legacy keys.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# These keys are immediately published and activated.
rollover_predecessor_keytimes 0
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Remember legacy key tags.
_migrate_ksk=$(key_get KEY1 ID)
_migrate_zsk=$(key_get KEY2 ID)

#
# Testing migration with unmatched existing keys (different algorithm).
#
set_zone "migrate-nomatch-algnum.kasp"
set_policy "none" "2" "300"
set_server "ns3" "10.53.0.3"

init_migration_nomatch_algnum() {
	key_clear        "KEY1"
	key_set          "KEY1" "LEGACY" "yes"
	set_keyrole      "KEY1" "ksk"
	set_keyalgorithm "KEY1" "5" "RSASHA1" "2048"
	set_keysigning   "KEY1" "yes"
	set_zonesigning  "KEY1" "no"

	key_clear        "KEY2"
	key_set          "KEY2" "LEGACY" "yes"
	set_keyrole      "KEY2" "zsk"
	set_keyalgorithm "KEY2" "5" "RSASHA1" "1024"
	set_keysigning   "KEY2" "no"
	set_zonesigning  "KEY2" "yes"

	key_clear        "KEY3"
	key_clear        "KEY4"

	set_keystate "KEY1" "GOAL"         "omnipresent"
	set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
	set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
	set_keystate "KEY1" "STATE_DS"     "omnipresent"

	set_keystate "KEY2" "GOAL"         "omnipresent"
	set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
	set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"
}
init_migration_nomatch_algnum

# Make sure the zone is signed with legacy keys.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# The KSK is immediately published and activated.
# -P     : now-3900s
# -P sync: now-3h
# -A     : now-3900s
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "PUBLISHED"   "${created}" -3900
set_addkeytime "KEY1" "ACTIVE"      "${created}" -3900
set_addkeytime "KEY1" "SYNCPUBLISH" "${created}" -10800
# The ZSK is immediately published and activated.
# -P: now-12h
# -A: now-12h
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED"   "${created}" -43200
set_addkeytime "KEY2" "ACTIVE"      "${created}" -43200
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Remember legacy key tags.
_migratenomatch_algnum_ksk=$(key_get KEY1 ID)
_migratenomatch_algnum_zsk=$(key_get KEY2 ID)

#
# Testing migration with unmatched existing keys (different length).
#
set_zone "migrate-nomatch-alglen.kasp"
set_policy "none" "2" "300"
set_server "ns3" "10.53.0.3"

init_migration_nomatch_alglen() {
	key_clear        "KEY1"
	key_set          "KEY1" "LEGACY" "yes"
	set_keyrole      "KEY1" "ksk"
	set_keyalgorithm "KEY1" "5" "RSASHA1" "1024"
	set_keysigning   "KEY1" "yes"
	set_zonesigning  "KEY1" "no"

	key_clear        "KEY2"
	key_set          "KEY2" "LEGACY" "yes"
	set_keyrole      "KEY2" "zsk"
	set_keyalgorithm "KEY2" "5" "RSASHA1" "1024"
	set_keysigning   "KEY2" "no"
	set_zonesigning  "KEY2" "yes"

	key_clear        "KEY3"
	key_clear        "KEY4"

	set_keystate "KEY1" "GOAL"         "omnipresent"
	set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
	set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
	set_keystate "KEY1" "STATE_DS"     "omnipresent"

	set_keystate "KEY2" "GOAL"         "omnipresent"
	set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
	set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"
}
init_migration_nomatch_alglen

# Make sure the zone is signed with legacy keys.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The KSK is immediately published and activated.
#   P     : now-3900s
#   P sync: now-3h
#   A     : now-3900s
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "PUBLISHED"   "${created}" -3900
set_addkeytime "KEY1" "ACTIVE"      "${created}" -3900
set_addkeytime "KEY1" "SYNCPUBLISH" "${created}" -10800
# - The ZSK is immediately published and activated.
#   P: now-12h
#   A: now-12h
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED"   "${created}" -43200
set_addkeytime "KEY2" "ACTIVE"      "${created}" -43200
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Remember legacy key tags.
_migratenomatch_alglen_ksk=$(key_get KEY1 ID)
_migratenomatch_alglen_zsk=$(key_get KEY2 ID)

# Reconfig.
echo_i "reconfig (migration to dnssec-policy)"
copy_setports ns3/named2.conf.in ns3/named.conf
rndc_reconfig ns3 10.53.0.3

# Calculate time passed to correctly check for next key events.
now="$(TZ=UTC date +%s)"
time_passed=$((now-start_time))
echo_i "${time_passed} seconds passed between start of tests and reconfig"

# Wait until we have seen "zone_rekey done:" message for this key.
_wait_for_done_signing() {
	_zone=$1

	_ksk=$(key_get $2 KSK)
	_zsk=$(key_get $2 ZSK)
	if [ "$_ksk" = "yes" ]; then
		_role="KSK"
		_expect_type=EXPECT_KRRSIG
	elif [ "$_zsk" = "yes" ]; then
		_role="ZSK"
		_expect_type=EXPECT_ZRRSIG
	fi

	if [ "$(key_get ${2} $_expect_type)" = "yes" ] && [ "$(key_get $2 $_role)" = "yes" ]; then
		_keyid=$(key_get $2 ID)
		_keyalg=$(key_get $2 ALG_STR)
		echo_i "wait for zone ${_zone} is done signing with $2 ${_zone}/${_keyalg}/${_keyid}"
		grep "zone_rekey done: key ${_keyid}/${_keyalg}" "${DIR}/named.run" > /dev/null || return 1
	fi

	return 0
}

wait_for_done_signing() {
	n=$((n+1))
	echo_i "wait for zone ${ZONE} is done signing ($n)"
	ret=0

	retry_quiet 30 _wait_for_done_signing ${ZONE} KEY1 || ret=1
	retry_quiet 30 _wait_for_done_signing ${ZONE} KEY2 || ret=1
	retry_quiet 30 _wait_for_done_signing ${ZONE} KEY3 || ret=1
	retry_quiet 30 _wait_for_done_signing ${ZONE} KEY4 || ret=1

	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
}

# Policy parameters.
# ZSK now has lifetime of 60 days (5184000 seconds).
# The key is removed after Iret = TTLsig + Dprp + Dsgn + retire-safety.
Lzsk=5184000
IretZSK=867900

#
# Testing good migration.
#
set_zone "migrate.kasp"
set_policy "migrate" "2" "7200"
set_server "ns3" "10.53.0.3"

# Key properties, timings and metadata should be the same as legacy keys above.
# However, because the zsk has a lifetime, kasp will set the retired time.
init_migration_match
key_set     "KEY1" "LEGACY"  "no"
key_set     "KEY2" "LEGACY"  "no"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
rollover_predecessor_keytimes 0
# - Key now has lifetime of 60 days (5184000 seconds).
#   The key is removed after Iret = TTLsig + Dprp + Dsgn + retire-safety.
#   TTLsig:        1d (86400 seconds)
#   Dprp:          5m (300 seconds)
#   Dsgn:          9d (777600 seconds)
#   retire-safety: 1h (3600 seconds)
#   IretZSK:       10d65m (867900 seconds)
active=$(key_get KEY2 ACTIVE)
set_addkeytime "KEY2" "RETIRED"     "${active}"  "${Lzsk}"
retired=$(key_get KEY2 RETIRED)
set_addkeytime "KEY2" "REMOVED"     "${retired}" "${IretZSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Check key tags, should be the same.
n=$((n+1))
echo_i "check that of zone ${ZONE} migration to dnssec-policy uses the same keys ($n)"
ret=0
[ $_migrate_ksk = $(key_get KEY1 ID) ] || log_error "mismatch ksk tag"
[ $_migrate_zsk = $(key_get KEY2 ID) ] || log_error "mismatch zsk tag"
status=$((status+ret))

# Test migration to dnssec-policy, existing keys do not match key algorithm.
set_zone "migrate-nomatch-algnum.kasp"
set_policy "migrate-nomatch-algnum" "4" "300"
set_server "ns3" "10.53.0.3"

# The legacy keys need to be retired, but otherwise stay present until the
# new keys are omnipresent, and can be used to construct a chain of trust.
init_migration_nomatch_algnum

key_set      "KEY1" "LEGACY"  "no"
set_keystate "KEY1" "GOAL"    "hidden"

key_set      "KEY2" "LEGACY"  "no"
set_keystate "KEY2" "GOAL"    "hidden"

set_keyrole      "KEY3" "ksk"
set_keylifetime  "KEY3" "0"
set_keyalgorithm "KEY3" "13" "ECDSAP256SHA256" "256"
set_keysigning   "KEY3" "yes"
set_zonesigning  "KEY3" "no"

set_keyrole      "KEY4" "zsk"
set_keylifetime  "KEY4" "5184000"
set_keyalgorithm "KEY4" "13" "ECDSAP256SHA256" "256"
set_keysigning   "KEY4" "no"
set_zonesigning  "KEY4" "yes"

set_keystate "KEY3" "GOAL"         "omnipresent"
set_keystate "KEY3" "STATE_DNSKEY" "rumoured"
set_keystate "KEY3" "STATE_KRRSIG" "rumoured"
set_keystate "KEY3" "STATE_DS"     "hidden"

set_keystate "KEY4" "GOAL"         "omnipresent"
set_keystate "KEY4" "STATE_DNSKEY" "rumoured"
set_keystate "KEY4" "STATE_ZRRSIG" "rumoured"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - KSK must be retired since it no longer matches the policy.
#   P     : now-3900s
#   P sync: now-3h
#   A     : now-3900s
# - The key is removed after the retire interval:
#   IretKSK = TTLds + DprpP + retire_safety.
#   TTLds:         2h (7200 seconds)
#   Dprp:          1h (3600 seconds)
#   retire-safety: 1h (3600 seconds)
#   IretKSK:       4h (14400 seconds)
IretKSK=14400
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "PUBLISHED"   "${created}" -3900
set_addkeytime "KEY1" "ACTIVE"      "${created}" -3900
set_addkeytime "KEY1" "SYNCPUBLISH" "${created}" -10800
keyfile=$(key_get KEY1 BASEFILE)
grep "; Inactive:" "${keyfile}.key" > retired.test${n}.ksk
retired=$(awk '{print $3}' < retired.test${n}.ksk)
set_keytime    "KEY1" "RETIRED" "${retired}"
set_addkeytime "KEY1" "REMOVED" "${retired}" "${IretKSK}"
# - ZSK must be retired since it no longer matches the policy.
#   P: now-12h
#   A: now-12h
# - The key is removed after the retire interval:
#   IretZSK = TTLsig + Dprp + Dsgn + retire-safety.
#   TTLsig:        11h (39600 seconds)
#   Dprp:          1h (3600 seconds)
#   Dsgn:          9d (777600 seconds)
#   retire-safety: 1h (3600 seconds)
#   IretZSK:       9d13h (824400 seconds)
IretZSK=824400
Lzsk=5184000
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED"   "${created}" -43200
set_addkeytime "KEY2" "ACTIVE"      "${created}" -43200
keyfile=$(key_get KEY2 BASEFILE)
grep "; Inactive:" "${keyfile}.key" > retired.test${n}.zsk
retired=$(awk '{print $3}' < retired.test${n}.zsk)
set_keytime    "KEY2" "RETIRED" "${retired}"
set_addkeytime "KEY2" "REMOVED" "${retired}" "${IretZSK}"
# - The new KSK is immediately published and activated.
created=$(key_get KEY3 CREATED)
set_keytime    "KEY3" "PUBLISHED"   "${created}"
set_keytime    "KEY3" "ACTIVE"      "${created}"
# - It takes TTLsig + Dprp + publish-safety hours to propagate the zone.
#   TTLsig:         11h (39600 seconds)
#   Dprp:           1h (3600 seconds)
#   publish-safety: 1h (3600 seconds)
#   Ipub:           13h (46800 seconds)
Ipub=46800
set_addkeytime "KEY3" "SYNCPUBLISH" "${created}" "${Ipub}"
# - The ZSK is immediately published and activated.
created=$(key_get KEY4 CREATED)
set_keytime    "KEY4" "PUBLISHED"   "${created}"
set_keytime    "KEY4" "ACTIVE"      "${created}"
active=$(key_get KEY4 ACTIVE)
set_addkeytime "KEY4" "RETIRED"     "${active}"  "${Lzsk}"
retired=$(key_get KEY4 RETIRED)
set_addkeytime "KEY4" "REMOVED"     "${retired}" "${IretZSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Check key tags, should be the same.
n=$((n+1))
echo_i "check that of zone ${ZONE} migration to dnssec-policy keeps existing keys ($n)"
ret=0
[ $_migratenomatch_algnum_ksk = $(key_get KEY1 ID) ] || log_error "mismatch ksk tag"
[ $_migratenomatch_algnum_zsk = $(key_get KEY2 ID) ] || log_error "mismatch zsk tag"
status=$((status+ret))

# Test migration to dnssec-policy, existing keys do not match key length.
set_zone "migrate-nomatch-alglen.kasp"
set_policy "migrate-nomatch-alglen" "4" "300"
set_server "ns3" "10.53.0.3"

# The legacy keys need to be retired, but otherwise stay present until the
# new keys are omnipresent, and can be used to construct a chain of trust.
init_migration_nomatch_alglen

key_set      "KEY1" "LEGACY"  "no"
set_keystate "KEY1" "GOAL"    "hidden"

key_set      "KEY2" "LEGACY"  "no"
set_keystate "KEY2" "GOAL"    "hidden"

set_keyrole      "KEY3" "ksk"
set_keylifetime  "KEY3" "0"
set_keyalgorithm "KEY3" "5" "RSASHA1" "2048"
set_keysigning   "KEY3" "yes"
set_zonesigning  "KEY3" "no"

set_keyrole      "KEY4" "zsk"
set_keylifetime  "KEY4" "5184000"
set_keyalgorithm "KEY4" "5" "RSASHA1" "2048"
set_keysigning   "KEY4" "no"
# This key is considered to be prepublished, so it is not yet signing.
set_zonesigning  "KEY4" "no"

set_keystate "KEY3" "GOAL"         "omnipresent"
set_keystate "KEY3" "STATE_DNSKEY" "rumoured"
set_keystate "KEY3" "STATE_KRRSIG" "rumoured"
set_keystate "KEY3" "STATE_DS"     "hidden"

set_keystate "KEY4" "GOAL"         "omnipresent"
set_keystate "KEY4" "STATE_DNSKEY" "rumoured"
set_keystate "KEY4" "STATE_ZRRSIG" "hidden"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - KSK must be retired since it no longer matches the policy.
#   P     : now-3900s
#   P sync: now-3h
#   A     : now-3900s
# - The key is removed after the retire interval:
#   IretKSK = TTLds + DprpP + retire_safety.
#   TTLds:         2h (7200 seconds)
#   Dprp:          1h (3600 seconds)
#   retire-safety: 1h (3600 seconds)
#   IretKSK:       4h (14400 seconds)
IretKSK=14400
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "PUBLISHED"   "${created}" -3900
set_addkeytime "KEY1" "ACTIVE"      "${created}" -3900
set_addkeytime "KEY1" "SYNCPUBLISH" "${created}" -10800
keyfile=$(key_get KEY1 BASEFILE)
grep "; Inactive:" "${keyfile}.key" > retired.test${n}.ksk
retired=$(awk '{print $3}' < retired.test${n}.ksk)
set_keytime    "KEY1" "RETIRED" "${retired}"
set_addkeytime "KEY1" "REMOVED" "${retired}" "${IretKSK}"
# - ZSK must be retired since it no longer matches the policy.
#   P: now-12h
#   A: now-12h
# - The key is removed after the retire interval:
#   IretZSK = TTLsig + Dprp + Dsgn + retire-safety.
#   TTLsig:         11h (39600 seconds)
#   Dprp:           1h (3600 seconds)
#   Dsgn:           9d (777600 seconds)
#   publish-safety: 1h (3600 seconds)
#   IretZSK:        9d13h (824400 seconds)
IretZSK=824400
Lzsk=5184000
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED"   "${created}" -43200
set_addkeytime "KEY2" "ACTIVE"      "${created}" -43200
keyfile=$(key_get KEY2 BASEFILE)
grep "; Inactive:" "${keyfile}.key" > retired.test${n}.zsk
retired=$(awk '{print $3}' < retired.test${n}.zsk)
set_keytime    "KEY2" "RETIRED" "${retired}"
set_addkeytime "KEY2" "REMOVED" "${retired}" "${IretZSK}"
# - The new KSK is immediately published and activated.
created=$(key_get KEY3 CREATED)
set_keytime    "KEY3" "PUBLISHED"   "${created}"
set_keytime    "KEY3" "ACTIVE"      "${created}"
# - It takes TTLsig + Dprp + publish-safety hours to propagate the zone.
#   TTLsig:         11h (39600 seconds)
#   Dprp:           1h (3600 seconds)
#   publish-safety: 1h (3600 seconds)
#   Ipub:           13h (46800 seconds)
Ipub=46800
set_addkeytime "KEY3" "SYNCPUBLISH" "${created}" "${Ipub}"
# - The ZSK is immediately published and activated.
created=$(key_get KEY4 CREATED)
set_keytime    "KEY4" "PUBLISHED"   "${created}"
set_keytime    "KEY4" "ACTIVE"      "${created}"
active=$(key_get KEY4 ACTIVE)
set_addkeytime "KEY4" "RETIRED"     "${active}"  "${Lzsk}"
retired=$(key_get KEY4 RETIRED)
set_addkeytime "KEY4" "REMOVED"     "${retired}" "${IretZSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Check key tags, should be the same.
n=$((n+1))
echo_i "check that of zone ${ZONE} migration to dnssec-policy keeps existing keys ($n)"
ret=0
[ $_migratenomatch_alglen_ksk = $(key_get KEY1 ID) ] || log_error "mismatch ksk tag"
[ $_migratenomatch_alglen_zsk = $(key_get KEY2 ID) ] || log_error "mismatch zsk tag"
status=$((status+ret))

#
# Testing good migration with views.
#
init_view_migration() {
	key_clear        "KEY1"
	key_set          "KEY1" "LEGACY" "yes"
	set_keyrole      "KEY1" "ksk"
	set_keylifetime  "KEY1" "0"
	set_keysigning   "KEY1" "yes"
	set_zonesigning  "KEY1" "no"

	key_clear        "KEY2"
	key_set          "KEY2" "LEGACY" "yes"
	set_keyrole      "KEY2" "zsk"
	set_keylifetime  "KEY2" "0"
	set_keysigning   "KEY2" "no"
	set_zonesigning  "KEY2" "yes"

	key_clear        "KEY3"
	key_clear        "KEY4"

	set_keystate "KEY1" "GOAL"         "omnipresent"
	set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
	set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
	set_keystate "KEY1" "STATE_DS"     "rumoured"

	set_keystate "KEY2" "GOAL"         "omnipresent"
	set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
	set_keystate "KEY2" "STATE_ZRRSIG" "rumoured"
}

set_keytimes_view_migration() {
	# Key is six months in use.
	created=$(key_get KEY1 CREATED)
	set_addkeytime "KEY1" "PUBLISHED"   "${created}" -16070400
	set_addkeytime "KEY1" "SYNCPUBLISH" "${created}" -16070400
	set_addkeytime "KEY1" "ACTIVE"      "${created}" -16070400
	created=$(key_get KEY2 CREATED)
	set_addkeytime "KEY2" "PUBLISHED"   "${created}" -16070400
	set_addkeytime "KEY2" "ACTIVE"      "${created}" -16070400
}

# Zone view.rsasha256.kasp (external)
set_zone "view-rsasha256.kasp"
set_policy "rsasha256" "2" "300"
set_server "ns4" "10.53.0.4"
init_view_migration
set_keyalgorithm "KEY1" "8" "RSASHA256" "2048"
set_keyalgorithm "KEY2" "8" "RSASHA256" "1024"
TSIG="hmac-sha1:external:$VIEW1"
wait_for_nsec
# Make sure the zone is signed with legacy keys.
check_keys
set_keytimes_view_migration
check_keytimes
dnssec_verify

n=$((n+1))
# check subdomain
echo_i "check TXT $ZONE (view ext) rrset is signed correctly ($n)"
ret=0
dig_with_opts "view.${ZONE}" "@${SERVER}" TXT > "dig.out.$DIR.test$n.txt" || log_error "dig view.${ZONE} TXT failed"
grep "status: NOERROR" "dig.out.$DIR.test$n.txt" > /dev/null || log_error "mismatch status in DNS response"
grep "view.${ZONE}\..*${DEFAULT_TTL}.*IN.*TXT.*external" "dig.out.$DIR.test$n.txt" > /dev/null || log_error "missing view.${ZONE} TXT record in response"
check_signatures TXT "dig.out.$DIR.test$n.txt" "ZSK"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Remember legacy key tags.
_migrate_ext8_ksk=$(key_get KEY1 ID)
_migrate_ext8_zsk=$(key_get KEY2 ID)

# Zone view.rsasha256.kasp (internal)
set_zone "view-rsasha256.kasp"
set_policy "rsasha256" "2" "300"
set_server "ns4" "10.53.0.4"
init_view_migration
set_keyalgorithm "KEY1" "8" "RSASHA256" "2048"
set_keyalgorithm "KEY2" "8" "RSASHA256" "1024"
TSIG="hmac-sha1:internal:$VIEW2"
wait_for_nsec
# Make sure the zone is signed with legacy keys.
check_keys
set_keytimes_view_migration
check_keytimes
dnssec_verify

n=$((n+1))
# check subdomain
echo_i "check TXT $ZONE (view int) rrset is signed correctly ($n)"
ret=0
dig_with_opts "view.${ZONE}" "@${SERVER}" TXT > "dig.out.$DIR.test$n.txt" || log_error "dig view.${ZONE} TXT failed"
grep "status: NOERROR" "dig.out.$DIR.test$n.txt" > /dev/null || log_error "mismatch status in DNS response"
grep "view.${ZONE}\..*${DEFAULT_TTL}.*IN.*TXT.*internal" "dig.out.$DIR.test$n.txt" > /dev/null || log_error "missing view.${ZONE} TXT record in response"
check_signatures TXT "dig.out.$DIR.test$n.txt" "ZSK"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Remember legacy key tags.
_migrate_int8_ksk=$(key_get KEY1 ID)
_migrate_int8_zsk=$(key_get KEY2 ID)

# Reconfig dnssec-policy.
echo_i "reconfig to switch to dnssec-policy"
copy_setports ns4/named2.conf.in ns4/named.conf
rndc_reconfig ns4 10.53.0.4

# Calculate time passed to correctly check for next key events.
now="$(TZ=UTC date +%s)"
time_passed=$((now-start_time))
echo_i "${time_passed} seconds passed between start of tests and reconfig"

#
# Testing migration (RSASHA256, views).
#
set_zone "view-rsasha256.kasp"
set_policy "rsasha256" "3" "300"
set_server "ns4" "10.53.0.4"
init_migration_match
set_keyalgorithm "KEY1" "8" "RSASHA256" "2048"
set_keyalgorithm "KEY2" "8" "RSASHA256" "1024"
# Key properties, timings and metadata should be the same as legacy keys above.
# However, because the keys have a lifetime, kasp will set the retired time.
key_set          "KEY1" "LEGACY" "no"
set_keylifetime  "KEY1" "31536000"
set_keystate     "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate     "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate     "KEY1" "STATE_DS"     "omnipresent"

key_set          "KEY2" "LEGACY" "no"
set_keylifetime  "KEY2" "8035200"
set_keystate     "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate     "KEY2" "STATE_ZRRSIG" "omnipresent"
# The ZSK needs to be replaced.
set_keystate     "KEY2" "GOAL" "hidden"
set_keystate     "KEY3" "GOAL" "omnipresent"
set_keyrole      "KEY3" "zsk"
set_keylifetime  "KEY3" "8035200"
set_keyalgorithm "KEY3" "8" "RSASHA256" "1024"
set_keysigning   "KEY3" "no"
set_zonesigning  "KEY3" "no" # not yet
set_keystate     "KEY3" "STATE_DNSKEY" "rumoured"
set_keystate     "KEY3" "STATE_ZRRSIG" "hidden"

# Various signing policy checks (external).
TSIG="hmac-sha1:external:$VIEW1"
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE" "external-view"
set_keytimes_view_migration

# Set expected key times:
published=$(key_get KEY1 PUBLISHED)
set_keytime "KEY1" "ACTIVE"      "${published}"
set_keytime "KEY1" "SYNCPUBLISH" "${published}"
# Lifetime: 1 year (8035200 seconds)
active=$(key_get KEY1 ACTIVE)
set_addkeytime "KEY1" "RETIRED" "${active}"  "31536000"
# Retire interval:
# DS TTL:                  1d
# Parent zone propagation: 3h
# Retire safety:           1h
# Total:                   100800 seconds
retired=$(key_get KEY1 RETIRED)
set_addkeytime "KEY1" "REMOVED" "${retired}" "100800"

published=$(key_get KEY2 PUBLISHED)
set_keytime "KEY2" "ACTIVE" "${published}"
# Lifetime: 3 months (8035200 seconds)
active=$(key_get KEY2 ACTIVE)
set_addkeytime "KEY2" "RETIRED" "${active}" "8035200"
# Retire interval:
# Sign delay:             9d (14-5)
# Max zone TTL:           1d
# Retire safety:          1h
# Zone propagation delay: 300s
# Total:                  867900 seconds
retired=$(key_get KEY2 RETIRED)
set_addkeytime "KEY2" "REMOVED" "${retired}" "867900"

created=$(key_get KEY3 CREATED)
set_keytime    "KEY3" "PUBLISHED" "${created}"
# Publication interval:
# DNSKEY TTL:             300s
# Publish safety:         1h
# Zone propagation delay: 300s
# Total:                  4200 seconds
set_addkeytime "KEY3" "ACTIVE" "${created}" "4200"
# Lifetime: 3 months (8035200 seconds)
active=$(key_get KEY3 ACTIVE)
set_addkeytime "KEY3" "RETIRED" "${active}" "8035200"
# Retire interval:
# Sign delay:             9d (14-5)
# Max zone TTL:           1d
# Retire safety:          1h
# Zone propagation delay: 300s
# Total:                  867900 seconds
retired=$(key_get KEY3 RETIRED)
set_addkeytime "KEY3" "REMOVED" "${retired}" "867900"

# Continue signing policy checks.
check_keytimes
check_apex
dnssec_verify

# Various signing policy checks (external).
TSIG="hmac-sha1:internal:$VIEW2"
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE" "internal-view"
set_keytimes_view_migration
check_keytimes
check_apex
dnssec_verify

# Check key tags, should be the same.
n=$((n+1))
echo_i "check that of zone ${ZONE} migration to dnssec-policy uses the same keys ($n)"
ret=0
[ $_migrate_ext8_ksk = $_migrate_int8_ksk ] || log_error "mismatch ksk tag"
[ $_migrate_ext8_zsk = $_migrate_int8_zsk ] || log_error "mismatch zsk tag"
[ $_migrate_ext8_ksk = $(key_get KEY1 ID) ] || log_error "mismatch ksk tag"
[ $_migrate_ext8_zsk = $(key_get KEY2 ID) ] || log_error "mismatch zsk tag"
status=$((status+ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
