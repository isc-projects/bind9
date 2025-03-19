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
# shellcheck source=kasp.sh
. ../kasp.sh

start_time="$(TZ=UTC date +%s)"
status=0
n=0

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
  "$RNDC" -c ../_common/rndc.conf -p "$CONTROLPORT" -s "$@"
}

# Log error and increment failure rate.
log_error() {
  echo_i "error: $1"
  ret=$((ret + 1))
}

# Default next key event threshold. May be extended by wait periods.
next_key_event_threshold=100

###############################################################################
# Tests                                                                       #
###############################################################################

#
# named
#

# The NSEC record at the apex of the zone and its RRSIG records are
# added as part of the last step in signing a zone.  We wait for the
# NSEC records to appear before proceeding with a counter to prevent
# infinite loops if there is an error.
n=$((n + 1))
echo_i "waiting for kasp signing changes to take effect ($n)"
ret=0

_wait_for_done_apexnsec() {
  while read -r zone; do
    dig_with_opts "$zone" @10.53.0.3 nsec >"dig.out.ns3.test$n.$zone" || return 1
    grep "NS SOA" "dig.out.ns3.test$n.$zone" >/dev/null || return 1
    grep "$zone\..*IN.*RRSIG" "dig.out.ns3.test$n.$zone" >/dev/null || return 1
  done <ns3/zones

  while read -r zone; do
    dig_with_opts "$zone" @10.53.0.6 nsec >"dig.out.ns6.test$n.$zone" || return 1
    grep "NS SOA" "dig.out.ns6.test$n.$zone" >/dev/null || return 1
    grep "$zone\..*IN.*RRSIG" "dig.out.ns6.test$n.$zone" >/dev/null || return 1
  done <ns6/zones

  return 0
}
retry_quiet 30 _wait_for_done_apexnsec || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

set_keytimes_csk_policy() {
  # The first key is immediately published and activated.
  created=$(key_get KEY1 CREATED)
  set_keytime "KEY1" "PUBLISHED" "${created}"
  set_keytime "KEY1" "ACTIVE" "${created}"
  # The DS can be published if the DNSKEY and RRSIG records are
  # OMNIPRESENT.  This happens after max-zone-ttl (1d) plus
  # zone-propagation-delay (300s) = 86400 + 300 = 86700.
  set_addkeytime "KEY1" "SYNCPUBLISH" "${created}" 86700
  # Key lifetime is unlimited, so not setting RETIRED and REMOVED.
}

# Set keytimes for dnssec-policy with various algorithms.
# These all use the same time values.
set_keytimes_algorithm_policy() {
  # The first KSK is immediately published and activated.
  created=$(key_get KEY1 CREATED)
  set_keytime "KEY1" "PUBLISHED" "${created}"
  set_keytime "KEY1" "ACTIVE" "${created}"
  # Key was pregenerated.
  if [ "$1" = "pregenerated" ]; then
    keyfile=$(key_get KEY1 BASEFILE)
    grep "; Publish:" "${keyfile}.key" >published.test${n}.key1
    published=$(awk '{print $3}' <published.test${n}.key1)
    set_keytime "KEY1" "PUBLISHED" "${published}"
    set_keytime "KEY1" "ACTIVE" "${published}"
  fi
  published=$(key_get KEY1 PUBLISHED)

  # The DS can be published if the DNSKEY and RRSIG records are
  # OMNIPRESENT.  This happens after max-zone-ttl (1d) plus
  # zone-propagation-delay (300s) = 86400 + 300 = 86700.
  set_addkeytime "KEY1" "SYNCPUBLISH" "${published}" 86700
  # Key lifetime is 10 years, 315360000 seconds.
  set_addkeytime "KEY1" "RETIRED" "${published}" 315360000
  # The key is removed after the retire time plus DS TTL (1d),
  # parent propagation delay (1h), and retire safety (1h) =
  # 86400 + 3600 + 3600 = 93600.
  retired=$(key_get KEY1 RETIRED)
  set_addkeytime "KEY1" "REMOVED" "${retired}" 93600

  # The first ZSKs are immediately published and activated.
  created=$(key_get KEY2 CREATED)
  set_keytime "KEY2" "PUBLISHED" "${created}"
  set_keytime "KEY2" "ACTIVE" "${created}"
  # Key was pregenerated.
  if [ "$1" = "pregenerated" ]; then
    keyfile=$(key_get KEY2 BASEFILE)
    grep "; Publish:" "${keyfile}.key" >published.test${n}.key2
    published=$(awk '{print $3}' <published.test${n}.key2)
    set_keytime "KEY2" "PUBLISHED" "${published}"
    set_keytime "KEY2" "ACTIVE" "${published}"
  fi
  published=$(key_get KEY2 PUBLISHED)

  # Key lifetime for KSK2 is 5 years, 157680000 seconds.
  set_addkeytime "KEY2" "RETIRED" "${published}" 157680000
  # The key is removed after the retire time plus max zone ttl (1d), zone
  # propagation delay (300s), retire safety (1h), and sign delay
  # (signature validity minus refresh, 9d) =
  # 86400 + 300 + 3600 + 777600 = 867900.
  retired=$(key_get KEY2 RETIRED)
  set_addkeytime "KEY2" "REMOVED" "${retired}" 867900

  # Second ZSK (KEY3).
  created=$(key_get KEY3 CREATED)
  set_keytime "KEY3" "PUBLISHED" "${created}"
  set_keytime "KEY3" "ACTIVE" "${created}"
  # Key was pregenerated.
  if [ "$1" = "pregenerated" ]; then
    keyfile=$(key_get KEY3 BASEFILE)
    grep "; Publish:" "${keyfile}.key" >published.test${n}.key3
    published=$(awk '{print $3}' <published.test${n}.key3)
    set_keytime "KEY3" "PUBLISHED" "${published}"
    set_keytime "KEY3" "ACTIVE" "${published}"
  fi
  published=$(key_get KEY3 PUBLISHED)

  # Key lifetime for KSK3 is 1 year, 31536000 seconds.
  set_addkeytime "KEY3" "RETIRED" "${published}" 31536000
  retired=$(key_get KEY3 RETIRED)
  set_addkeytime "KEY3" "REMOVED" "${retired}" 867900
}

# TODO: we might want to test:
# - configuring a zone with too many active keys (should trigger retire).
# - configuring a zone with keys not matching the policy.

# Set key times for 'autosign' policy.
set_keytimes_autosign_policy() {
  # The KSK was published six months ago (with settime).
  created=$(key_get KEY1 CREATED)
  set_addkeytime "KEY1" "PUBLISHED" "${created}" -15552000
  set_addkeytime "KEY1" "ACTIVE" "${created}" -15552000
  set_addkeytime "KEY1" "SYNCPUBLISH" "${created}" -15552000
  # Key lifetime is 2 years, 63072000 seconds.
  active=$(key_get KEY1 ACTIVE)
  set_addkeytime "KEY1" "RETIRED" "${active}" 63072000
  # The key is removed after the retire time plus DS TTL (1d),
  # parent propagation delay (1h), retire safety (1h) =
  # 86400 + 3600 + 3600 = 93600
  retired=$(key_get KEY1 RETIRED)
  set_addkeytime "KEY1" "REMOVED" "${retired}" 93600

  # The ZSK was published six months ago (with settime).
  created=$(key_get KEY2 CREATED)
  set_addkeytime "KEY2" "PUBLISHED" "${created}" -15552000
  set_addkeytime "KEY2" "ACTIVE" "${created}" -15552000
  # Key lifetime for KSK2 is 1 year, 31536000 seconds.
  active=$(key_get KEY2 ACTIVE)
  set_addkeytime "KEY2" "RETIRED" "${active}" 31536000
  # The key is removed after the retire time plus:
  # TTLsig (RRSIG TTL):       1 day (86400 seconds)
  # Dprp (propagation delay): 5 minutes (300 seconds)
  # retire-safety:            1 hour (3600 seconds)
  # Dsgn (sign delay):        7 days (604800 seconds)
  # Iret:                     695100 seconds.
  retired=$(key_get KEY2 RETIRED)
  set_addkeytime "KEY2" "REMOVED" "${retired}" 695100
}

_check_next_key_event() {
  _expect=$1

  grep "zone ${ZONE}.*: next key event in .* seconds" "${DIR}/named.run" >"keyevent.out.$ZONE.test$n" || return 1

  # Get the latest next key event.
  if [ "${DYNAMIC}" = "yes" ]; then
    _time=$(awk '{print $9}' <"keyevent.out.$ZONE.test$n" | tail -1)
  else
    # inline-signing zone adds "(signed)"
    _time=$(awk '{print $10}' <"keyevent.out.$ZONE.test$n" | tail -1)
  fi

  # The next key event time must within threshold of the
  # expected time.
  _expectmin=$((_expect - next_key_event_threshold))
  _expectmax=$((_expect + next_key_event_threshold))

  test $_expectmin -le "$_time" || return 1
  test $_expectmax -ge "$_time" || return 1

  return 0
}

check_next_key_event() {
  n=$((n + 1))
  echo_i "check next key event for zone ${ZONE} ($n)"
  ret=0

  retry_quiet 3 _check_next_key_event $1 || log_error "bad next key event time for zone ${ZONE} (expect ${_expect})"
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

}

set_retired_removed() {
  _Lkey=$2
  _Iret=$3

  _active=$(key_get $1 ACTIVE)
  set_addkeytime "${1}" "RETIRED" "${_active}" "${_Lkey}"
  _retired=$(key_get $1 RETIRED)
  set_addkeytime "${1}" "REMOVED" "${_retired}" "${_Iret}"
}

rollover_predecessor_keytimes() {
  _addtime=$1

  _created=$(key_get KEY1 CREATED)
  set_addkeytime "KEY1" "PUBLISHED" "${_created}" "${_addtime}"
  set_addkeytime "KEY1" "SYNCPUBLISH" "${_created}" "${_addtime}"
  set_addkeytime "KEY1" "ACTIVE" "${_created}" "${_addtime}"
  [ "$Lksk" = 0 ] || set_retired_removed "KEY1" "${Lksk}" "${IretKSK}"

  _created=$(key_get KEY2 CREATED)
  set_addkeytime "KEY2" "PUBLISHED" "${_created}" "${_addtime}"
  set_addkeytime "KEY2" "ACTIVE" "${_created}" "${_addtime}"
  [ "$Lzsk" = 0 ] || set_retired_removed "KEY2" "${Lzsk}" "${IretZSK}"
}

csk_rollover_predecessor_keytimes() {
  _addtime=$1

  _created=$(key_get KEY1 CREATED)
  set_addkeytime "KEY1" "PUBLISHED" "${_created}" "${_addtime}"
  set_addkeytime "KEY1" "SYNCPUBLISH" "${_created}" "${_addtime}"
  set_addkeytime "KEY1" "ACTIVE" "${_created}" "${_addtime}"
  [ "$Lcsk" = 0 ] || set_retired_removed "KEY1" "${Lcsk}" "${IretCSK}"
}

#
# Testing algorithm rollover.
#
Lksk=0
Lzsk=0
IretKSK=0
IretZSK=0

#
# Zone: step1.algorithm-roll.kasp
#
set_zone "step1.algorithm-roll.kasp"
set_policy "rsasha256" "2" "3600"
set_server "ns6" "10.53.0.6"
# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "8" "RSASHA256" "2048"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

key_clear "KEY2"
set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "0"
set_keyalgorithm "KEY2" "8" "RSASHA256" "2048"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"
key_clear "KEY3"
key_clear "KEY4"

# The KSK (KEY1) and ZSK (KEY2) start in OMNIPRESENT.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# These keys are immediately published and activated.
rollover_predecessor_keytimes 0
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the successor keys need to be published.
# Since the lifetime of the keys are unlimited, so default to loadkeys
# interval.
check_next_key_event 3600

#
# Zone: step1.csk-algorithm-roll.kasp
#
set_zone "step1.csk-algorithm-roll.kasp"
set_policy "csk-algoroll" "1" "3600"
set_server "ns6" "10.53.0.6"
# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "8" "RSASHA256" "2048"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"
# The CSK (KEY1) starts in OMNIPRESENT.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_ZRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# This key is immediately published and activated.
Lcsk=0
IretCSK=0
csk_rollover_predecessor_keytimes 0
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the successor keys need to be published.
# Since the lifetime of the keys are unlimited, so default to loadkeys
# interval.
check_next_key_event 3600

# Reconfig dnssec-policy (triggering algorithm roll and other dnssec-policy
# changes).
echo_i "reconfig dnssec-policy to trigger algorithm rollover"
copy_setports ns6/named2.conf.in ns6/named.conf
rndc_reconfig ns6 10.53.0.6

# Calculate time passed to correctly check for next key events.
now="$(TZ=UTC date +%s)"
time_passed=$((now - start_time))
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
    grep "zone_rekey done: key ${_keyid}/${_keyalg}" "${DIR}/named.run" >/dev/null || return 1
  fi

  return 0
}

wait_for_done_signing() {
  n=$((n + 1))
  echo_i "wait for zone ${ZONE} is done signing ($n)"
  ret=0

  retry_quiet 30 _wait_for_done_signing ${ZONE} KEY1 || ret=1
  retry_quiet 30 _wait_for_done_signing ${ZONE} KEY2 || ret=1
  retry_quiet 30 _wait_for_done_signing ${ZONE} KEY3 || ret=1
  retry_quiet 30 _wait_for_done_signing ${ZONE} KEY4 || ret=1

  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
}

#
# Testing KSK/ZSK algorithm rollover.
#

# Policy parameters.
# Lksk: unlimited
# Lzsk: unlimited
Lksk=0
Lzsk=0

#
# Zone: step1.algorithm-roll.kasp
#
set_zone "step1.algorithm-roll.kasp"
set_policy "ecdsa256" "4" "3600"
set_server "ns6" "10.53.0.6"
# Old RSASHA1 keys.
key_clear "KEY1"
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "8" "RSASHA256" "2048"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

key_clear "KEY2"
set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "0"
set_keyalgorithm "KEY2" "8" "RSASHA256" "2048"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"
# New ECDSAP256SHA256 keys.
key_clear "KEY3"
set_keyrole "KEY3" "ksk"
set_keylifetime "KEY3" "0"
set_keyalgorithm "KEY3" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY3" "yes"
set_zonesigning "KEY3" "no"

key_clear "KEY4"
set_keyrole "KEY4" "zsk"
set_keylifetime "KEY4" "0"
set_keyalgorithm "KEY4" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY4" "no"
set_zonesigning "KEY4" "yes"
# The RSAHSHA1 keys are outroducing.
set_keystate "KEY1" "GOAL" "hidden"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"
set_keystate "KEY2" "GOAL" "hidden"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"
# The ECDSAP256SHA256 keys are introducing.
set_keystate "KEY3" "GOAL" "omnipresent"
set_keystate "KEY3" "STATE_DNSKEY" "rumoured"
set_keystate "KEY3" "STATE_KRRSIG" "rumoured"
set_keystate "KEY3" "STATE_DS" "hidden"
set_keystate "KEY4" "GOAL" "omnipresent"
set_keystate "KEY4" "STATE_DNSKEY" "rumoured"
set_keystate "KEY4" "STATE_ZRRSIG" "rumoured"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys are published and activated.
rollover_predecessor_keytimes 0
# - KSK must be retired since it no longer matches the policy.
keyfile=$(key_get KEY1 BASEFILE)
grep "; Inactive:" "${keyfile}.key" >retired.test${n}.ksk
retired=$(awk '{print $3}' <retired.test${n}.ksk)
set_keytime "KEY1" "RETIRED" "${retired}"
# - The key is removed after the retire interval:
#   IretKSK = TTLds + DprpP + retire-safety
#   TTLds:         2h (7200 seconds)
#   DprpP:         1h (3600 seconds)
#   retire-safety: 2h (7200 seconds)
#   IretKSK:       5h (18000 seconds)
IretKSK=18000
set_addkeytime "KEY1" "REMOVED" "${retired}" "${IretKSK}"
# - ZSK must be retired since it no longer matches the policy.
keyfile=$(key_get KEY2 BASEFILE)
grep "; Inactive:" "${keyfile}.key" >retired.test${n}.zsk
retired=$(awk '{print $3}' <retired.test${n}.zsk)
set_keytime "KEY2" "RETIRED" "${retired}"
# - The key is removed after the retire interval:
#   IretZSK = TTLsig + Dprp + Dsgn + retire-safety
#   TTLsig:        6h (21600 seconds)
#   Dprp:          1h (3600 seconds)
#   Dsgn:          25d (2160000 seconds)
#   retire-safety: 2h (7200 seconds)
#   IretZSK:       25d9h (2192400 seconds)
IretZSK=2192400
set_addkeytime "KEY2" "REMOVED" "${retired}" "${IretZSK}"
# - The new KSK is published and activated.
created=$(key_get KEY3 CREATED)
set_keytime "KEY3" "PUBLISHED" "${created}"
set_keytime "KEY3" "ACTIVE" "${created}"
# - It takes TTLsig + Dprp to propagate the zone.
#   TTLsig:         6h (39600 seconds)
#   Dprp:           1h (3600 seconds)
#   Ipub:           7h (25200 seconds)
Ipub=25200
set_addkeytime "KEY3" "SYNCPUBLISH" "${created}" "${Ipub}"
# - The new ZSK is published and activated.
created=$(key_get KEY4 CREATED)
set_keytime "KEY4" "PUBLISHED" "${created}"
set_keytime "KEY4" "ACTIVE" "${created}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the ecdsa256 keys have been propagated.
# This is the DNSKEY TTL plus publish safety plus zone propagation delay:
# 3 times an hour: 10800 seconds.
check_next_key_event 10800

#
# Zone: step2.algorithm-roll.kasp
#
set_zone "step2.algorithm-roll.kasp"
set_policy "ecdsa256" "4" "3600"
set_server "ns6" "10.53.0.6"
# The RSAHSHA1 keys are outroducing, but need to stay present until the new
# algorithm chain of trust has been established. Thus the properties, timings
# and states of the KEY1 and KEY2 are the same as above.

# The ECDSAP256SHA256 keys are introducing. The DNSKEY RRset is omnipresent,
# but the zone signatures are not.
set_keystate "KEY3" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY3" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY4" "STATE_DNSKEY" "omnipresent"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys were activated three hours ago (10800 seconds).
rollover_predecessor_keytimes -10800
# - KSK must be retired since it no longer matches the policy.
created=$(key_get KEY1 CREATED)
set_keytime "KEY1" "RETIRED" "${created}"
set_addkeytime "KEY1" "REMOVED" "${created}" "${IretKSK}"
# - ZSK must be retired since it no longer matches the policy.
created=$(key_get KEY2 CREATED)
set_keytime "KEY2" "RETIRED" "${created}"
set_addkeytime "KEY2" "REMOVED" "${created}" "${IretZSK}"
# - The new keys are published 3 hours ago.
created=$(key_get KEY3 CREATED)
set_addkeytime "KEY3" "PUBLISHED" "${created}" -10800
set_addkeytime "KEY3" "ACTIVE" "${created}" -10800
published=$(key_get KEY3 PUBLISHED)
set_addkeytime "KEY3" "SYNCPUBLISH" "${published}" "${Ipub}"

created=$(key_get KEY4 CREATED)
set_addkeytime "KEY4" "PUBLISHED" "${created}" -10800
set_addkeytime "KEY4" "ACTIVE" "${created}" -10800

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when all zone signatures are signed with the new
# algorithm.  This is the max-zone-ttl plus zone propagation delay
# 6h + 1h.  But three hours have already passed (the time it took to
# make the DNSKEY omnipresent), so the next event should be scheduled
# in 4 hour: 14400 seconds.  Prevent intermittent
# false positives on slow platforms by subtracting the number of seconds
# which passed between key creation and invoking 'rndc reconfig'.
next_time=$((14400 - time_passed))
check_next_key_event $next_time

#
# Zone: step3.algorithm-roll.kasp
#
set_zone "step3.algorithm-roll.kasp"
set_policy "ecdsa256" "4" "3600"
set_server "ns6" "10.53.0.6"
# The ECDSAP256SHA256 keys are introducing.
set_keystate "KEY4" "STATE_ZRRSIG" "omnipresent"
# The DS can be swapped.
set_keystate "KEY1" "STATE_DS" "unretentive"
set_keystate "KEY3" "STATE_DS" "rumoured"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# Check that CDS publication is logged.
check_cdslog "$DIR" "$ZONE" KEY3

# Set expected key times:
# - The old keys were activated 7 hours ago (25200 seconds).
rollover_predecessor_keytimes -25200
# - And retired 3 hours ago (10800 seconds).
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "RETIRED" "${created}" -10800
retired=$(key_get KEY1 RETIRED)
set_addkeytime "KEY1" "REMOVED" "${retired}" "${IretKSK}"

created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "RETIRED" "${created}" -10800
retired=$(key_get KEY2 RETIRED)
set_addkeytime "KEY2" "REMOVED" "${retired}" "${IretZSK}"
# - The new keys are published 7 hours ago.
created=$(key_get KEY3 CREATED)
set_addkeytime "KEY3" "PUBLISHED" "${created}" -25200
set_addkeytime "KEY3" "ACTIVE" "${created}" -25200
published=$(key_get KEY3 PUBLISHED)
set_addkeytime "KEY3" "SYNCPUBLISH" "${published}" ${Ipub}

created=$(key_get KEY4 CREATED)
set_addkeytime "KEY4" "PUBLISHED" "${created}" -25200
set_addkeytime "KEY4" "ACTIVE" "${created}" -25200

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Tell named we "saw" the parent swap the DS and see if the next key event is
# scheduled at the correct time.
rndc_checkds "$SERVER" "$DIR" KEY1 "now" "withdrawn" "$ZONE"
rndc_checkds "$SERVER" "$DIR" KEY3 "now" "published" "$ZONE"
# Next key event is when the DS becomes OMNIPRESENT. This happens after the
# parent propagation delay, and DS TTL:
# 1h + 2h = 3h = 10800 seconds.
check_next_key_event 10800

#
# Zone: step4.algorithm-roll.kasp
#
set_zone "step4.algorithm-roll.kasp"
set_policy "ecdsa256" "4" "3600"
set_server "ns6" "10.53.0.6"
# The old DS is HIDDEN, we can remove the old algorithm DNSKEY/RRSIG records.
set_keysigning "KEY1" "no"
set_keystate "KEY1" "STATE_DNSKEY" "unretentive"
set_keystate "KEY1" "STATE_KRRSIG" "unretentive"
set_keystate "KEY1" "STATE_DS" "hidden"

set_zonesigning "KEY2" "no"
set_keystate "KEY2" "GOAL" "hidden"
set_keystate "KEY2" "STATE_DNSKEY" "unretentive"
set_keystate "KEY2" "STATE_ZRRSIG" "unretentive"
# The ECDSAP256SHA256 DS is now OMNIPRESENT.
set_keystate "KEY3" "STATE_DS" "omnipresent"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys were activated 36 hours ago (129600 seconds).
rollover_predecessor_keytimes -129600
# - And retired 33 hours ago (118800 seconds).
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "RETIRED" "${created}" -118800
retired=$(key_get KEY1 RETIRED)
set_addkeytime "KEY1" "REMOVED" "${retired}" "${IretKSK}"

created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "RETIRED" "${created}" -118800
retired=$(key_get KEY2 RETIRED)
set_addkeytime "KEY2" "REMOVED" "${retired}" "${IretZSK}"

# - The new keys are published 36 hours ago.
created=$(key_get KEY3 CREATED)
set_addkeytime "KEY3" "PUBLISHED" "${created}" -129600
set_addkeytime "KEY3" "ACTIVE" "${created}" -129600
published=$(key_get KEY3 PUBLISHED)
set_addkeytime "KEY3" "SYNCPUBLISH" "${published}" ${Ipub}

created=$(key_get KEY4 CREATED)
set_addkeytime "KEY4" "PUBLISHED" "${created}" -129600
set_addkeytime "KEY4" "ACTIVE" "${created}" -129600

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the old DNSKEY becomes HIDDEN.  This happens after the
# DNSKEY TTL plus zone propagation delay (2h).
check_next_key_event 7200

#
# Zone: step5.algorithm-roll.kasp
#
set_zone "step5.algorithm-roll.kasp"
set_policy "ecdsa256" "4" "3600"
set_server "ns6" "10.53.0.6"
# The DNSKEY becomes HIDDEN.
set_keystate "KEY1" "STATE_DNSKEY" "hidden"
set_keystate "KEY1" "STATE_KRRSIG" "hidden"
set_keystate "KEY2" "STATE_DNSKEY" "hidden"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys were activated 38 hours ago (136800 seconds)
rollover_predecessor_keytimes -136800
# - And retired 35 hours ago (126000 seconds).
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "RETIRED" "${created}" -126000
retired=$(key_get KEY1 RETIRED)
set_addkeytime "KEY1" "REMOVED" "${retired}" "${IretKSK}"

created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "RETIRED" "${created}" -126000
retired=$(key_get KEY2 RETIRED)
set_addkeytime "KEY2" "REMOVED" "${retired}" "${IretZSK}"

# The new keys are published 40 hours ago.
created=$(key_get KEY3 CREATED)
set_addkeytime "KEY3" "PUBLISHED" "${created}" -136800
set_addkeytime "KEY3" "ACTIVE" "${created}" -136800
published=$(key_get KEY3 PUBLISHED)
set_addkeytime "KEY3" "SYNCPUBLISH" "${published}" ${Ipub}

created=$(key_get KEY4 CREATED)
set_addkeytime "KEY4" "PUBLISHED" "${created}" -136800
set_addkeytime "KEY4" "ACTIVE" "${created}" -136800

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the RSASHA1 signatures become HIDDEN.  This happens
# after the max-zone-ttl plus zone propagation delay (6h + 1h)
# minus the time already passed since the UNRETENTIVE state has
# been reached (2h): 7h - 2h = 5h = 18000 seconds. Prevent intermittent
# false positives on slow platforms by subtracting the number of seconds
# which passed between key creation and invoking 'rndc reconfig'.
next_time=$((18000 - time_passed))
check_next_key_event $next_time

#
# Zone: step6.algorithm-roll.kasp
#
set_zone "step6.algorithm-roll.kasp"
set_policy "ecdsa256" "4" "3600"
set_server "ns6" "10.53.0.6"
# The old zone signatures (KEY2) should now also be HIDDEN.
set_keystate "KEY2" "STATE_ZRRSIG" "hidden"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys were activated 45 hours ago (162000 seconds)
rollover_predecessor_keytimes -162000
# - And retired 42 hours ago (151200 seconds).
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "RETIRED" "${created}" -151200
retired=$(key_get KEY1 RETIRED)
set_addkeytime "KEY1" "REMOVED" "${retired}" "${IretKSK}"

created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "RETIRED" "${created}" -151200
retired=$(key_get KEY2 RETIRED)
set_addkeytime "KEY2" "REMOVED" "${retired}" "${IretZSK}"

# The new keys are published 47 hours ago.
created=$(key_get KEY3 CREATED)
set_addkeytime "KEY3" "PUBLISHED" "${created}" -162000
set_addkeytime "KEY3" "ACTIVE" "${created}" -162000
published=$(key_get KEY3 PUBLISHED)
set_addkeytime "KEY3" "SYNCPUBLISH" "${published}" ${Ipub}

created=$(key_get KEY4 CREATED)
set_addkeytime "KEY4" "PUBLISHED" "${created}" -162000
set_addkeytime "KEY4" "ACTIVE" "${created}" -162000

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is never since we established the policy and the keys have
# an unlimited lifetime.  Fallback to the default loadkeys interval.
check_next_key_event 3600

#
# Testing CSK algorithm rollover.
#

# Policy parameters.
# Lcsk: unlimited
Lcksk=0

#
# Zone: step1.csk-algorithm-roll.kasp
#
set_zone "step1.csk-algorithm-roll.kasp"
set_policy "csk-algoroll" "2" "3600"
set_server "ns6" "10.53.0.6"
# Old RSASHA1 key.
key_clear "KEY1"
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "8" "RSASHA256" "2048"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
# New ECDSAP256SHA256 key.
key_clear "KEY2"
set_keyrole "KEY2" "csk"
set_keylifetime "KEY2" "0"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "yes"
set_zonesigning "KEY2" "yes"
key_clear "KEY3"
key_clear "KEY4"
# The RSAHSHA1 key is outroducing.
set_keystate "KEY1" "GOAL" "hidden"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_ZRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"
# The ECDSAP256SHA256 key is introducing.
set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
set_keystate "KEY2" "STATE_KRRSIG" "rumoured"
set_keystate "KEY2" "STATE_ZRRSIG" "rumoured"
set_keystate "KEY2" "STATE_DS" "hidden"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - CSK must be retired since it no longer matches the policy.
csk_rollover_predecessor_keytimes 0
keyfile=$(key_get KEY1 BASEFILE)
grep "; Inactive:" "${keyfile}.key" >retired.test${n}.ksk
retired=$(awk '{print $3}' <retired.test${n}.ksk)
set_keytime "KEY1" "RETIRED" "${retired}"
# - The key is removed after the retire interval:
#   IretZSK = TTLsig + Dprp + Dsgn + retire-safety
#   TTLsig:        6h (21600 seconds)
#   Dprp:          1h (3600 seconds)
#   Dsgn:          25d (2160000 seconds)
#   retire-safety: 2h (7200 seconds)
#   IretZSK:       25d9h (2192400 seconds)
IretCSK=2192400
set_addkeytime "KEY1" "REMOVED" "${retired}" "${IretCSK}"
# - The new CSK is published and activated.
created=$(key_get KEY2 CREATED)
set_keytime "KEY2" "PUBLISHED" "${created}"
set_keytime "KEY2" "ACTIVE" "${created}"
# - It takes TTLsig + Dprp + publish-safety hours to propagate the zone.
#   TTLsig:         6h (39600 seconds)
#   Dprp:           1h (3600 seconds)
#   Ipub:           7h (25200 seconds)
Ipub=25200
set_addkeytime "KEY2" "SYNCPUBLISH" "${created}" "${Ipub}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the new key has been propagated.
# This is the DNSKEY TTL plus publish safety plus zone propagation delay:
# 3 times an hour: 10800 seconds.
check_next_key_event 10800

#
# Zone: step2.csk-algorithm-roll.kasp
#
set_zone "step2.csk-algorithm-roll.kasp"
set_policy "csk-algoroll" "2" "3600"
set_server "ns6" "10.53.0.6"
# The RSAHSHA1 key is outroducing, but need to stay present until the new
# algorithm chain of trust has been established. Thus the properties, timings
# and states of KEY1 is the same as above.
#
# The ECDSAP256SHA256 keys are introducing. The DNSKEY RRset is omnipresent,
# but the zone signatures are not.
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_KRRSIG" "omnipresent"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old key was activated three hours ago (10800 seconds).
csk_rollover_predecessor_keytimes -10800
# - CSK must be retired since it no longer matches the policy.
created=$(key_get KEY1 CREATED)
set_keytime "KEY1" "RETIRED" "${created}"
set_addkeytime "KEY1" "REMOVED" "${created}" "${IretCSK}"
# - The new key was published 3 hours ago.
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED" "${created}" -10800
set_addkeytime "KEY2" "ACTIVE" "${created}" -10800
published=$(key_get KEY2 PUBLISHED)
set_addkeytime "KEY2" "SYNCPUBLISH" "${published}" "${Ipub}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when all zone signatures are signed with the new algorithm.
# This is the max-zone-ttl plus zone propagation delay: 6h + 1h.  But three
# hours have already passed (the time it took to make the DNSKEY omnipresent),
# so the next event should be scheduled in 4 hour: 14400 seconds.  Prevent
# intermittent false positives on slow platforms by subtracting the number of
# seconds which passed between key creation and invoking 'rndc reconfig'.
next_time=$((14400 - time_passed))
check_next_key_event $next_time

#
# Zone: step3.csk-algorithm-roll.kasp
#
set_zone "step3.csk-algorithm-roll.kasp"
set_policy "csk-algoroll" "2" "3600"
set_server "ns6" "10.53.0.6"
# The RSAHSHA1 key is outroducing, and it is time to swap the DS.
# The ECDSAP256SHA256 key is introducing. The DNSKEY RRset and all signatures
# are now omnipresent, so the DS can be introduced.
set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"
# The old DS (KEY1) can be withdrawn and the new DS (KEY2) can be introduced.
set_keystate "KEY1" "STATE_DS" "unretentive"
set_keystate "KEY2" "STATE_DS" "rumoured"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# Check that CDS publication is logged.
check_cdslog "$DIR" "$ZONE" KEY2

# Set expected key times:
# - The old key was activated 7 hours ago (25200 seconds).
csk_rollover_predecessor_keytimes -25200
# - And was retired 3 hours ago (10800 seconds).
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "RETIRED" "${created}" -10800
retired=$(key_get KEY1 RETIRED)
set_addkeytime "KEY1" "REMOVED" "${retired}" "${IretCSK}"
# - The new key was published 9 hours ago.
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED" "${created}" -25200
set_addkeytime "KEY2" "ACTIVE" "${created}" -25200
published=$(key_get KEY2 PUBLISHED)
set_addkeytime "KEY2" "SYNCPUBLISH" "${published}" "${Ipub}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# We ignore any parent registration delay, so set the DS publish time to now.
rndc_checkds "$SERVER" "$DIR" KEY1 "now" "withdrawn" "$ZONE"
rndc_checkds "$SERVER" "$DIR" KEY2 "now" "published" "$ZONE"
# Next key event is when the DS becomes OMNIPRESENT. This happens after the
# parent propagation delay, and DS TTL:
# 1h + 2h = 3h = 10800 seconds.
check_next_key_event 10800

#
# Zone: step4.csk-algorithm-roll.kasp
#
set_zone "step4.csk-algorithm-roll.kasp"
set_policy "csk-algoroll" "2" "3600"
set_server "ns6" "10.53.0.6"
# The old DS is HIDDEN, we can remove the old algorithm DNSKEY/RRSIG records.
set_keysigning "KEY1" "no"
set_zonesigning "KEY1" "no"
set_keystate "KEY1" "STATE_DNSKEY" "unretentive"
set_keystate "KEY1" "STATE_KRRSIG" "unretentive"
set_keystate "KEY1" "STATE_ZRRSIG" "unretentive"
set_keystate "KEY1" "STATE_DS" "hidden"
# The ECDSAP256SHA256 DS is now OMNIPRESENT.
set_keystate "KEY2" "STATE_DS" "omnipresent"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys were activated 36 hours ago (129600 seconds).
csk_rollover_predecessor_keytimes -129600
# - And retired 33 hours ago (118800 seconds).
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "RETIRED" "${created}" -118800
retired=$(key_get KEY1 RETIRED)
set_addkeytime "KEY1" "REMOVED" "${retired}" "${IretCSK}"
# - The new key was published 36 hours ago.
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED" "${created}" -129600
set_addkeytime "KEY2" "ACTIVE" "${created}" -129600
published=$(key_get KEY2 PUBLISHED)
set_addkeytime "KEY2" "SYNCPUBLISH" "${published}" ${Ipub}

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the old DNSKEY becomes HIDDEN.  This happens after the
# DNSKEY TTL plus zone propagation delay (2h).
check_next_key_event 7200

#
# Zone: step5.csk-algorithm-roll.kasp
#
set_zone "step5.csk-algorithm-roll.kasp"
set_policy "csk-algoroll" "2" "3600"
set_server "ns6" "10.53.0.6"
# The DNSKEY becomes HIDDEN.
set_keystate "KEY1" "STATE_DNSKEY" "hidden"
set_keystate "KEY1" "STATE_KRRSIG" "hidden"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old key was activated 38 hours ago (136800 seconds)
csk_rollover_predecessor_keytimes -136800
# - And retired 35 hours ago (126000 seconds).
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "RETIRED" "${created}" -126000
retired=$(key_get KEY1 RETIRED)
set_addkeytime "KEY1" "REMOVED" "${retired}" "${IretCSK}"
# - The new key was published 38 hours ago.
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED" "${created}" -136800
set_addkeytime "KEY2" "ACTIVE" "${created}" -136800
published=$(key_get KEY2 PUBLISHED)
set_addkeytime "KEY2" "SYNCPUBLISH" "${published}" ${Ipub}

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the RSASHA1 signatures become HIDDEN.  This happens
# after the max-zone-ttl plus zone propagation delay (6h + 1h) minus the
# time already passed since the UNRETENTIVE state has been reached (2h):
# 7h - 2h = 5h = 18000 seconds.  Prevent intermittent false positives on slow
# platforms by subtracting the number of seconds which passed between key
# creation and invoking 'rndc reconfig'.
next_time=$((18000 - time_passed))
check_next_key_event $next_time

#
# Zone: step6.csk-algorithm-roll.kasp
#
set_zone "step6.csk-algorithm-roll.kasp"
set_policy "csk-algoroll" "2" "3600"
set_server "ns6" "10.53.0.6"
# The zone signatures should now also be HIDDEN.
set_keystate "KEY1" "STATE_ZRRSIG" "hidden"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys were activated 45 hours ago (162000 seconds)
csk_rollover_predecessor_keytimes -162000
# - And retired 42 hours ago (151200 seconds).
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "RETIRED" "${created}" -151200
retired=$(key_get KEY1 RETIRED)
set_addkeytime "KEY1" "REMOVED" "${retired}" "${IretCSK}"
# - The new key was published 47 hours ago.
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED" "${created}" -162000
set_addkeytime "KEY2" "ACTIVE" "${created}" -162000
published=$(key_get KEY2 PUBLISHED)
set_addkeytime "KEY2" "SYNCPUBLISH" "${published}" ${Ipub}

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is never since we established the policy and the keys have
# an unlimited lifetime.  Fallback to the default loadkeys interval.
check_next_key_event 3600

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
