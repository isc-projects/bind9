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

# Key properties.
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
# DNSKEY, RRSIG (ksk), RRSIG (zsk) are published. DS needs to wait.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_ZRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"

#
# Zone: checkds-ksk.kasp.
#
key_clear "KEY1"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

set_zone "checkds-ksk.kasp"
set_policy "checkds-ksk" "2" "303"
set_server "ns3" "10.53.0.3"

# Key properties.
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "0"
set_keyalgorithm "KEY2" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"
# DNSKEY, RRSIG (ksk), RRSIG (zsk) are published. DS needs to wait.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
set_keystate "KEY2" "STATE_ZRRSIG" "rumoured"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

basefile=$(key_get KEY1 BASEFILE)

_wait_for_metadata() {
  _expr=$1
  _file=$2
  grep "$_expr" $_file >/dev/null || return 1
  return 0
}

n=$((n + 1))
echo_i "checkds publish correctly sets DSPublish for zone $ZONE ($n)"
now=$(date +%Y%m%d%H%M%S)
rndc_checkds "$SERVER" "$DIR" "-" "$now" "published" "$ZONE"
retry_quiet 3 _wait_for_metadata "DSPublish: $now" "${basefile}.state" || log_error "bad DSPublish in ${basefile}.state"
# DS State should be forced into RUMOURED.
set_keystate "KEY1" "STATE_DS" "rumoured"
check_keys
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "checkds withdraw correctly sets DSRemoved for zone $ZONE ($n)"
now=$(date +%Y%m%d%H%M%S)
rndc_checkds "$SERVER" "$DIR" "-" "$now" "withdrawn" "$ZONE"
retry_quiet 3 _wait_for_metadata "DSRemoved: $now" "${basefile}.state" || log_error "bad DSRemoved in ${basefile}.state"
# DS State should be forced into UNRETENTIVE.
set_keystate "KEY1" "STATE_DS" "unretentive"
check_keys
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

#
# Zone: checkds-doubleksk.kasp.
#
key_clear "KEY1"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

set_zone "checkds-doubleksk.kasp"
set_policy "checkds-doubleksk" "3" "303"
set_server "ns3" "10.53.0.3"
# Key properties.
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

set_keyrole "KEY2" "ksk"
set_keylifetime "KEY2" "0"
set_keyalgorithm "KEY2" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY2" "yes"
set_zonesigning "KEY2" "no"

set_keyrole "KEY3" "zsk"
set_keylifetime "KEY3" "0"
set_keyalgorithm "KEY3" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY3" "no"
set_zonesigning "KEY3" "yes"
# DNSKEY, RRSIG (ksk), RRSIG (zsk) are published. DS needs to wait.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
set_keystate "KEY2" "STATE_KRRSIG" "rumoured"
set_keystate "KEY2" "STATE_DS" "hidden"

set_keystate "KEY3" "GOAL" "omnipresent"
set_keystate "KEY3" "STATE_DNSKEY" "rumoured"
set_keystate "KEY3" "STATE_ZRRSIG" "rumoured"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

basefile1=$(key_get KEY1 BASEFILE)
basefile2=$(key_get KEY2 BASEFILE)

n=$((n + 1))
echo_i "checkds published does not set DSPublish for zone $ZONE (multiple KSK) ($n)"
rndc_checkds "$SERVER" "$DIR" "-" "20200102121314" "published" "$ZONE"
grep "DSPublish:" "${basefile1}.state" >/dev/null && log_error "DSPublish incorrectly set in ${basefile1}"
grep "DSPublish:" "${basefile2}.state" >/dev/null && log_error "DSPublish incorrectly set in ${basefile2}"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "checkds withdrawn does not set DSRemoved for zone $ZONE (multiple KSK) ($n)"
rndc_checkds "$SERVER" "$DIR" "-" "20190102121314" "withdrawn" "$ZONE"
grep "DSRemoved:" "${basefile1}.state" >/dev/null && log_error "DSRemoved incorrectly set in ${basefile1}"
grep "DSRemoved:" "${basefile2}.state" >/dev/null && log_error "DSRemoved incorrectly set in ${basefile2}"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "checkds published does not set DSPublish for zone $ZONE (wrong algorithm) ($n)"
rndccmd "$SERVER" dnssec -checkds -key $(key_get KEY1 ID) -alg 8 "published" "$ZONE" >rndc.dnssec.checkds.out.$ZONE.$n
grep "DSPublish:" "${basefile1}.state" >/dev/null && log_error "DSPublish incorrectly set in ${basefile1}"
grep "DSPublish:" "${basefile2}.state" >/dev/null && log_error "DSPublish incorrectly set in ${basefile2}"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "checkds withdrawn does not set DSRemoved for zone $ZONE (wrong algorithm) ($n)"
rndccmd "$SERVER" dnssec -checkds -key $(key_get KEY1 ID) -alg RSASHA256 "withdrawn" "$ZONE" >rndc.dnssec.checkds.out.$ZONE.$n
grep "DSRemoved:" "${basefile1}.state" >/dev/null && log_error "DSRemoved incorrectly set in ${basefile1}"
grep "DSRemoved:" "${basefile2}.state" >/dev/null && log_error "DSRemoved incorrectly set in ${basefile2}"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "checkds published -key correctly sets DSPublish for key $(key_get KEY1 ID) zone $ZONE (multiple KSK) ($n)"
rndc_checkds "$SERVER" "$DIR" KEY1 "20190102121314" "published" "$ZONE"
retry_quiet 3 _wait_for_metadata "DSPublish: 20190102121314" "${basefile1}.state" || log_error "bad DSPublish in ${basefile1}.state"
grep "DSPublish:" "${basefile2}.state" >/dev/null && log_error "DSPublish incorrectly set in ${basefile2}"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "checkds withdrawn -key correctly sets DSRemoved for key $(key_get KEY2 ID) zone $ZONE (multiple KSK) ($n)"
rndc_checkds "$SERVER" "$DIR" KEY2 "20200102121314" "withdrawn" "$ZONE"
grep "DSRemoved:" "${basefile1}.state" >/dev/null && log_error "DSPublish incorrectly set in ${basefile1}"
retry_quiet 3 _wait_for_metadata "DSRemoved: 20200102121314" "${basefile2}.state" || log_error "bad DSRemoved in ${basefile2}.state"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

#
# Zone: checkds-csk.kasp.
#
key_clear "KEY1"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

set_zone "checkds-csk.kasp"
set_policy "checkds-csk" "1" "303"
set_server "ns3" "10.53.0.3"
# Key properties.
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
# DNSKEY, RRSIG (ksk), RRSIG (zsk) are published. DS needs to wait.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_ZRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

basefile=$(key_get KEY1 BASEFILE)

n=$((n + 1))
echo_i "checkds publish correctly sets DSPublish for zone $ZONE ($n)"
rndc_checkds "$SERVER" "$DIR" "-" "20190102121314" "published" "$ZONE"
retry_quiet 3 _wait_for_metadata "DSPublish: 20190102121314" "${basefile}.state" || log_error "bad DSPublish in ${basefile}.state"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "checkds withdraw correctly sets DSRemoved for zone $ZONE ($n)"
rndc_checkds "$SERVER" "$DIR" "-" "20200102121314" "withdrawn" "$ZONE"
retry_quiet 3 _wait_for_metadata "DSRemoved: 20200102121314" "${basefile}.state" || log_error "bad DSRemoved in ${basefile}.state"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

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

#
# Zone: rsasha1.kasp.
#
if [ $RSASHA1_SUPPORTED = 1 ]; then
  set_zone "rsasha1.kasp"
  set_policy "rsasha1" "3" "1234"
  set_server "ns3" "10.53.0.3"
  # Key properties.
  key_clear "KEY1"
  set_keyrole "KEY1" "ksk"
  set_keylifetime "KEY1" "315360000"
  set_keyalgorithm "KEY1" "5" "RSASHA1" "2048"
  set_keysigning "KEY1" "yes"
  set_zonesigning "KEY1" "no"

  key_clear "KEY2"
  set_keyrole "KEY2" "zsk"
  set_keylifetime "KEY2" "157680000"
  set_keyalgorithm "KEY2" "5" "RSASHA1" "2048"
  set_keysigning "KEY2" "no"
  set_zonesigning "KEY2" "yes"

  key_clear "KEY3"
  set_keyrole "KEY3" "zsk"
  set_keylifetime "KEY3" "31536000"
  set_keyalgorithm "KEY3" "5" "RSASHA1" "2000"
  set_keysigning "KEY3" "no"
  set_zonesigning "KEY3" "yes"

  # KSK: DNSKEY, RRSIG (ksk) published. DS needs to wait.
  # ZSK: DNSKEY, RRSIG (zsk) published.
  set_keystate "KEY1" "GOAL" "omnipresent"
  set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
  set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
  set_keystate "KEY1" "STATE_DS" "hidden"

  set_keystate "KEY2" "GOAL" "omnipresent"
  set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
  set_keystate "KEY2" "STATE_ZRRSIG" "rumoured"

  set_keystate "KEY3" "GOAL" "omnipresent"
  set_keystate "KEY3" "STATE_DNSKEY" "rumoured"
  set_keystate "KEY3" "STATE_ZRRSIG" "rumoured"
  # Three keys only.
  key_clear "KEY4"

  check_keys
  check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
  set_keytimes_algorithm_policy
  check_keytimes
  check_apex
  check_subdomain
  dnssec_verify
fi

#
# Zone: unlimited.kasp.
#
set_zone "unlimited.kasp"
set_policy "unlimited" "1" "1234"
set_server "ns3" "10.53.0.3"
key_clear "KEY1"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"
# Key properties.
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
# DNSKEY, RRSIG (ksk), RRSIG (zsk) are published. DS needs to wait.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_ZRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_csk_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: keystore.kasp.
#
set_zone "keystore.kasp"
set_policy "keystore" "2" "303"
set_server "ns3" "10.53.0.3"
# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "0"
set_keydir "KEY1" "ns3/ksk"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

key_clear "KEY2"
set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "0"
set_keydir "KEY2" "ns3/zsk"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"

# KSK: DNSKEY, RRSIG (ksk) published. DS needs to wait.
# ZSK: DNSKEY, RRSIG (zsk) published.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
set_keystate "KEY2" "STATE_ZRRSIG" "rumoured"
# Two keys only.
key_clear "KEY3"
key_clear "KEY4"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# Reuse set_keytimes_csk_policy to set the KEY1 keytimes.
set_keytimes_csk_policy
created=$(key_get KEY2 CREATED)
set_keytime "KEY2" "PUBLISHED" "${created}"
set_keytime "KEY2" "ACTIVE" "${created}"
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: inherit.kasp.
#
set_zone "inherit.kasp"
set_policy "rsasha256" "3" "1234"
set_server "ns3" "10.53.0.3"

# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "315360000"
set_keyalgorithm "KEY1" "8" "RSASHA256" "2048"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

key_clear "KEY2"
set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "157680000"
set_keyalgorithm "KEY2" "8" "RSASHA256" "2048"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"

key_clear "KEY3"
set_keyrole "KEY3" "zsk"
set_keylifetime "KEY3" "31536000"
set_keyalgorithm "KEY3" "8" "RSASHA256" "3072"
set_keysigning "KEY3" "no"
set_zonesigning "KEY3" "yes"
# KSK: DNSKEY, RRSIG (ksk) published. DS needs to wait.
# ZSK: DNSKEY, RRSIG (zsk) published.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
set_keystate "KEY2" "STATE_ZRRSIG" "rumoured"

set_keystate "KEY3" "GOAL" "omnipresent"
set_keystate "KEY3" "STATE_DNSKEY" "rumoured"
set_keystate "KEY3" "STATE_ZRRSIG" "rumoured"
# Three keys only.
key_clear "KEY4"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_algorithm_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: dnssec-keygen.kasp.
#
set_zone "dnssec-keygen.kasp"
set_policy "rsasha256" "3" "1234"
set_server "ns3" "10.53.0.3"
# Key properties, timings and states same as above.

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_algorithm_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: some-keys.kasp.
#
set_zone "some-keys.kasp"
set_policy "rsasha256" "3" "1234"
set_server "ns3" "10.53.0.3"
# Key properties, timings and states same as above.

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_algorithm_policy "pregenerated"
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: pregenerated.kasp.
#
# There are more pregenerated keys than needed, hence the number of keys is
# six, not three.
set_zone "pregenerated.kasp"
set_policy "rsasha256" "6" "1234"
set_server "ns3" "10.53.0.3"
# Key properties, timings and states same as above.

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_algorithm_policy "pregenerated"
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: rumoured.kasp.
#
# There are three keys in rumoured state.
set_zone "rumoured.kasp"
set_policy "rsasha256" "3" "1234"
set_server "ns3" "10.53.0.3"
# Key properties, timings and states same as above.

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_algorithm_policy
# Activation date is a day later.
set_addkeytime "KEY1" "ACTIVE" $(key_get KEY1 ACTIVE) 86400
set_addkeytime "KEY1" "RETIRED" $(key_get KEY1 RETIRED) 86400
set_addkeytime "KEY1" "REMOVED" $(key_get KEY1 REMOVED) 86400
set_addkeytime "KEY2" "ACTIVE" $(key_get KEY2 ACTIVE) 86400
set_addkeytime "KEY2" "RETIRED" $(key_get KEY2 RETIRED) 86400
set_addkeytime "KEY2" "REMOVED" $(key_get KEY2 REMOVED) 86400
set_addkeytime "KEY3" "ACTIVE" $(key_get KEY3 ACTIVE) 86400
set_addkeytime "KEY3" "RETIRED" $(key_get KEY3 RETIRED) 86400
set_addkeytime "KEY3" "REMOVED" $(key_get KEY3 REMOVED) 86400
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: secondary.kasp.
#
set_zone "secondary.kasp"
set_policy "rsasha256" "3" "1234"
set_server "ns3" "10.53.0.3"
# Key properties, timings and states same as above.

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_algorithm_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Update zone.
n=$((n + 1))
echo_i "check that we correctly sign the zone after IXFR for zone ${ZONE} ($n)"
ret=0
cp ns2/secondary.kasp.db.in2 ns2/secondary.kasp.db
rndccmd 10.53.0.2 reload "$ZONE" >/dev/null || log_error "rndc reload zone ${ZONE} failed"

_wait_for_done_subdomains() {
  ret=0
  dig_with_opts "a.${ZONE}" "@${SERVER}" A >"dig.out.$DIR.test$n.a" || return 1
  grep "status: NOERROR" "dig.out.$DIR.test$n.a" >/dev/null || return 1
  grep "a.${ZONE}\..*${DEFAULT_TTL}.*IN.*A.*10\.0\.0\.11" "dig.out.$DIR.test$n.a" >/dev/null || return 1
  check_signatures $_qtype "dig.out.$DIR.test$n.a" "ZSK"
  if [ $ret -gt 0 ]; then return $ret; fi

  dig_with_opts "d.${ZONE}" "@${SERVER}" A >"dig.out.$DIR.test$n.d" || return 1
  grep "status: NOERROR" "dig.out.$DIR.test$n.d" >/dev/null || return 1
  grep "d.${ZONE}\..*${DEFAULT_TTL}.*IN.*A.*10\.0\.0\.4" "dig.out.$DIR.test$n.d" >/dev/null || return 1
  check_signatures $_qtype "dig.out.$DIR.test$n.d" "ZSK"
  return $ret
}
retry_quiet 5 _wait_for_done_subdomains || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# TODO: we might want to test:
# - configuring a zone with too many active keys (should trigger retire).
# - configuring a zone with keys not matching the policy.

#
# Zone: rsasha1-nsec3.kasp.
#
if [ $RSASHA1_SUPPORTED = 1 ]; then
  set_zone "rsasha1-nsec3.kasp"
  set_policy "rsasha1-nsec3" "3" "1234"
  set_server "ns3" "10.53.0.3"
  # Key properties.
  set_keyalgorithm "KEY1" "7" "NSEC3RSASHA1" "2048"
  set_keyalgorithm "KEY2" "7" "NSEC3RSASHA1" "2048"
  set_keyalgorithm "KEY3" "7" "NSEC3RSASHA1" "2000"
  # Key timings and states same as above.

  check_keys
  check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
  set_keytimes_algorithm_policy
  check_keytimes
  check_apex
  check_subdomain
  dnssec_verify
fi

#
# Zone: rsasha256.kasp.
#
set_zone "rsasha256.kasp"
set_policy "rsasha256" "3" "1234"
set_server "ns3" "10.53.0.3"
# Key properties.
set_keyalgorithm "KEY1" "8" "RSASHA256" "2048"
set_keyalgorithm "KEY2" "8" "RSASHA256" "2048"
set_keyalgorithm "KEY3" "8" "RSASHA256" "3072"
# Key timings and states same as above.

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_algorithm_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: rsasha512.kasp.
#
set_zone "rsasha512.kasp"
set_policy "rsasha512" "3" "1234"
set_server "ns3" "10.53.0.3"
# Key properties.
set_keyalgorithm "KEY1" "10" "RSASHA512" "2048"
set_keyalgorithm "KEY2" "10" "RSASHA512" "2048"
set_keyalgorithm "KEY3" "10" "RSASHA512" "3072"
# Key timings and states same as above.

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_algorithm_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: ecdsa256.kasp.
#
set_zone "ecdsa256.kasp"
set_policy "ecdsa256" "3" "1234"
set_server "ns3" "10.53.0.3"
# Key properties.
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keyalgorithm "KEY2" "13" "ECDSAP256SHA256" "256"
set_keyalgorithm "KEY3" "13" "ECDSAP256SHA256" "256"
# Key timings and states same as above.

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_algorithm_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: ecdsa512.kasp.
#
set_zone "ecdsa384.kasp"
set_policy "ecdsa384" "3" "1234"
set_server "ns3" "10.53.0.3"
# Key properties.
set_keyalgorithm "KEY1" "14" "ECDSAP384SHA384" "384"
set_keyalgorithm "KEY2" "14" "ECDSAP384SHA384" "384"
set_keyalgorithm "KEY3" "14" "ECDSAP384SHA384" "384"
# Key timings and states same as above.

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_algorithm_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: ed25519.kasp.
#
if [ $ED25519_SUPPORTED = 1 ]; then
  set_zone "ed25519.kasp"
  set_policy "ed25519" "3" "1234"
  set_server "ns3" "10.53.0.3"
  # Key properties.
  set_keyalgorithm "KEY1" "15" "ED25519" "256"
  set_keyalgorithm "KEY2" "15" "ED25519" "256"
  set_keyalgorithm "KEY3" "15" "ED25519" "256"
  # Key timings and states same as above.

  check_keys
  check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
  set_keytimes_algorithm_policy
  check_keytimes
  check_apex
  check_subdomain
  dnssec_verify
fi

#
# Zone: ed448.kasp.
#
if [ $ED448_SUPPORTED = 1 ]; then
  set_zone "ed448.kasp"
  set_policy "ed448" "3" "1234"
  set_server "ns3" "10.53.0.3"
  # Key properties.
  set_keyalgorithm "KEY1" "16" "ED448" "456"
  set_keyalgorithm "KEY2" "16" "ED448" "456"
  set_keyalgorithm "KEY3" "16" "ED448" "456"
  # Key timings and states same as above.

  check_keys
  check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
  set_keytimes_algorithm_policy
  check_keytimes
  check_apex
  check_subdomain
  dnssec_verify
fi

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

#
# Zone: expired-sigs.autosign.
#
set_zone "expired-sigs.autosign"
set_policy "autosign" "2" "300"
set_server "ns3" "10.53.0.3"
# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "63072000"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

key_clear "KEY2"
set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "31536000"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"

# Both KSK and ZSK stay OMNIPRESENT.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"
# Expect only two keys.
key_clear "KEY3"
key_clear "KEY4"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_autosign_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Verify all signatures have been refreshed.
check_rrsig_refresh() {
  # Apex.
  _qtypes="DNSKEY SOA NS NSEC"
  for _qtype in $_qtypes; do
    n=$((n + 1))
    echo_i "check ${_qtype} rrsig is refreshed correctly for zone ${ZONE} ($n)"
    ret=0
    dig_with_opts "$ZONE" "@${SERVER}" "$_qtype" >"dig.out.$DIR.test$n" || log_error "dig ${ZONE} ${_qtype} failed"
    grep "status: NOERROR" "dig.out.$DIR.test$n" >/dev/null || log_error "mismatch status in DNS response"
    grep "${ZONE}\..*IN.*RRSIG.*${_qtype}.*${ZONE}" "dig.out.$DIR.test$n" >"rrsig.out.$ZONE.$_qtype" || log_error "missing RRSIG (${_qtype}) record in response"
    # If this exact RRSIG is also in the zone file it is not refreshed.
    _rrsig=$(cat "rrsig.out.$ZONE.$_qtype")
    grep "${_rrsig}" "${DIR}/${ZONE}.db" >/dev/null && log_error "RRSIG (${_qtype}) not refreshed in zone ${ZONE}"
    test "$ret" -eq 0 || echo_i "failed"
    status=$((status + ret))
  done

  # Below apex.
  _labels="a b c ns3"
  for _label in $_labels; do
    _qtypes="A NSEC"
    for _qtype in $_qtypes; do
      n=$((n + 1))
      echo_i "check ${_label} ${_qtype} rrsig is refreshed correctly for zone ${ZONE} ($n)"
      ret=0
      dig_with_opts "${_label}.${ZONE}" "@${SERVER}" "$_qtype" >"dig.out.$DIR.test$n" || log_error "dig ${_label}.${ZONE} ${_qtype} failed"
      grep "status: NOERROR" "dig.out.$DIR.test$n" >/dev/null || log_error "mismatch status in DNS response"
      grep "${ZONE}\..*IN.*RRSIG.*${_qtype}.*${ZONE}" "dig.out.$DIR.test$n" >"rrsig.out.$ZONE.$_qtype" || log_error "missing RRSIG (${_qtype}) record in response"
      _rrsig=$(cat "rrsig.out.$ZONE.$_qtype")
      grep "${_rrsig}" "${DIR}/${ZONE}.db" >/dev/null && log_error "RRSIG (${_qtype}) not refreshed in zone ${ZONE}"
      test "$ret" -eq 0 || echo_i "failed"
      status=$((status + ret))
    done
  done
}

check_rrsig_refresh

#
# Zone: dnskey-ttl-mismatch.autosign
#
set_zone "dnskey-ttl-mismatch.autosign"
set_policy "autosign" "2" "300"
set_server "ns3" "10.53.0.3"
# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "63072000"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

key_clear "KEY2"
set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "31536000"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"

# Both KSK and ZSK stay OMNIPRESENT.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"
# Expect only two keys.
key_clear "KEY3"
key_clear "KEY4"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_autosign_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: fresh-sigs.autosign.
#
set_zone "fresh-sigs.autosign"
set_policy "autosign" "2" "300"
set_server "ns3" "10.53.0.3"
# Key properties, timings and states same as above.

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_autosign_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Verify signature reuse.
check_rrsig_reuse() {
  # Apex.
  _qtypes="NS NSEC"
  for _qtype in $_qtypes; do
    n=$((n + 1))
    echo_i "check ${_qtype} rrsig is reused correctly for zone ${ZONE} ($n)"
    ret=0
    dig_with_opts "$ZONE" "@${SERVER}" "$_qtype" >"dig.out.$DIR.test$n" || log_error "dig ${ZONE} ${_qtype} failed"
    grep "status: NOERROR" "dig.out.$DIR.test$n" >/dev/null || log_error "mismatch status in DNS response"
    grep "${ZONE}\..*IN.*RRSIG.*${_qtype}.*${ZONE}" "dig.out.$DIR.test$n" >"rrsig.out.$ZONE.$_qtype" || log_error "missing RRSIG (${_qtype}) record in response"
    # If this exact RRSIG is also in the signed zone file it is not refreshed.
    _rrsig=$(awk '{print $5, $6, $7, $8, $9, $10, $11, $12, $13, $14;}' <"rrsig.out.$ZONE.$_qtype")
    $CHECKZONE -f raw -F text -s full -o zone.out.${ZONE}.test$n "${ZONE}" "${DIR}/${ZONE}.db.signed" >/dev/null
    grep "${_rrsig}" zone.out.${ZONE}.test$n >/dev/null || log_error "RRSIG (${_qtype}) not reused in zone ${ZONE}"
    test "$ret" -eq 0 || echo_i "failed"
    status=$((status + ret))
  done

  # Below apex.
  _labels="a b c ns3"
  for _label in $_labels; do
    _qtypes="A NSEC"
    for _qtype in $_qtypes; do
      n=$((n + 1))
      echo_i "check ${_label} ${_qtype} rrsig is reused correctly for zone ${ZONE} ($n)"
      ret=0
      dig_with_opts "${_label}.${ZONE}" "@${SERVER}" "$_qtype" >"dig.out.$DIR.test$n" || log_error "dig ${_label}.${ZONE} ${_qtype} failed"
      grep "status: NOERROR" "dig.out.$DIR.test$n" >/dev/null || log_error "mismatch status in DNS response"
      grep "${ZONE}\..*IN.*RRSIG.*${_qtype}.*${ZONE}" "dig.out.$DIR.test$n" >"rrsig.out.$ZONE.$_qtype" || log_error "missing RRSIG (${_qtype}) record in response"
      # If this exact RRSIG is also in the signed zone file it is not refreshed.
      _rrsig=$(awk '{print $5, $6, $7, $8, $9, $10, $11, $12, $13, $14;}' <"rrsig.out.$ZONE.$_qtype")
      $CHECKZONE -f raw -F text -s full -o zone.out.${ZONE}.test$n "${ZONE}" "${DIR}/${ZONE}.db.signed" >/dev/null
      grep "${_rrsig}" zone.out.${ZONE}.test$n >/dev/null || log_error "RRSIG (${_qtype}) not reused in zone ${ZONE}"
      test "$ret" -eq 0 || echo_i "failed"
      status=$((status + ret))
    done
  done
}

check_rrsig_reuse

#
# Zone: unfresh-sigs.autosign.
#
set_zone "unfresh-sigs.autosign"
set_policy "autosign" "2" "300"
set_server "ns3" "10.53.0.3"
# Key properties, timings and states same as above.

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_autosign_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify
check_rrsig_refresh

#
# Zone: ksk-missing.autosign.
#
set_zone "ksk-missing.autosign"
set_policy "autosign" "2" "300"
set_server "ns3" "10.53.0.3"
# Key properties, timings and states same as above.
# Skip checking the private file, because it is missing.
key_set "KEY1" "PRIVATE" "no"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

# Restore the PRIVATE variable.
key_set "KEY1" "PRIVATE" "yes"

#
# Zone: zsk-missing.autosign.
#
set_zone "zsk-missing.autosign"
set_policy "autosign" "2" "300"
set_server "ns3" "10.53.0.3"
# Key properties, timings and states same as above.
# Skip checking the private file, because it is missing.
key_set "KEY2" "PRIVATE" "no"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# For the apex, we expect the SOA to be signed with the KSK because the ZSK is
# offline. Temporary treat KEY1 as a zone signing key too.
set_keyrole "KEY1" "csk"
set_zonesigning "KEY1" "yes"
set_zonesigning "KEY2" "no"
check_apex
set_keyrole "KEY1" "ksk"
set_zonesigning "KEY1" "no"
set_zonesigning "KEY2" "yes"
check_subdomain
dnssec_verify

# Restore the PRIVATE variable.
key_set "KEY2" "PRIVATE" "yes"

#
# Zone: zsk-retired.autosign.
#
set_zone "zsk-retired.autosign"
set_policy "autosign" "3" "300"
set_server "ns3" "10.53.0.3"
# The third key is not yet expected to be signing.
set_keyrole "KEY3" "zsk"
set_keylifetime "KEY3" "31536000"
set_keyalgorithm "KEY3" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY3" "no"
set_zonesigning "KEY3" "no"
# The ZSK goal is set to HIDDEN but records stay OMNIPRESENT until the new ZSK
# is active.
set_keystate "KEY2" "GOAL" "hidden"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"
# A new ZSK should be introduced, so expect a key with goal OMNIPRESENT,
# the DNSKEY introduced (RUMOURED) and the signatures HIDDEN.
set_keystate "KEY3" "GOAL" "omnipresent"
set_keystate "KEY3" "STATE_DNSKEY" "rumoured"
set_keystate "KEY3" "STATE_ZRRSIG" "hidden"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_autosign_policy

# The old ZSK is retired.
created=$(key_get KEY2 CREATED)
set_keytime "KEY2" "RETIRED" "${created}"
set_addkeytime "KEY2" "REMOVED" "${created}" 695100
# The new ZSK is immediately published.
created=$(key_get KEY3 CREATED)
set_keytime "KEY3" "PUBLISHED" "${created}"
# And becomes active after Ipub:
# DNSKEY TTL:            300 seconds
# zone-propagation-delay 5 minutes (300 seconds)
# publish-safety:        1 hour (3600 seconds)
# Ipub:                  4200 seconds
published=$(key_get KEY3 PUBLISHED)
set_addkeytime "KEY3" "ACTIVE" "${published}" 4200
# Lzsk:                  1 year (31536000 seconds)
active=$(key_get KEY3 ACTIVE)
set_addkeytime "KEY3" "RETIRED" "${active}" 31536000
# Iret:                  695100 seconds.
retired=$(key_get KEY3 RETIRED)
set_addkeytime "KEY3" "REMOVED" "${retired}" 695100

check_keytimes
check_apex
check_subdomain
dnssec_verify
check_rrsig_refresh

# Load again, make sure the purged key is not an issue when verifying keys.
echo_i "load keys for $ZONE, making sure a recently purged key is not an issue when verifying keys ($n)"
ret=0
rndccmd 10.53.0.3 loadkeys "$ZONE" >/dev/null || log_error "rndc loadkeys zone ${ZONE} failed"
wait_for_log 3 "keymgr: $ZONE done" $DIR/named.run || ret=1
grep "zone $ZONE/IN (signed): zone_rekey:zone_verifykeys failed: some key files are missing" $DIR/named.run && ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

#
# Zone: legacy-keys.kasp.
#
set_zone "legacy-keys.kasp"
# This zone has two active keys and two old keys left in key directory, so
# expect 4 key files.
set_policy "migrate-to-dnssec-policy" "4" "1234"
set_server "ns3" "10.53.0.3"

# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "16070400"
set_keyalgorithm "KEY1" "8" "RSASHA256" "2048"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

key_clear "KEY2"
set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "16070400"
set_keyalgorithm "KEY2" "8" "RSASHA256" "2048"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"
# KSK: DNSKEY, RRSIG (ksk) published. DS needs to wait.
# ZSK: DNSKEY, RRSIG (zsk) published.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
set_keystate "KEY2" "STATE_ZRRSIG" "rumoured"
# Two keys only.
key_clear "KEY3"
key_clear "KEY4"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Make sure the correct legacy keys were used (and not the removed predecessor
# keys).
n=$((n + 1))
echo_i "check correct keys were used when migrating zone ${ZONE} to dnssec-policy ($n)"
ret=0
kskfile=$(cat ns3/legacy-keys.kasp.ksk)
basefile=$(key_get KEY1 BASEFILE)
echo_i "filename: $basefile (expect $kskfile)"
test "$DIR/$kskfile" = "$basefile" || ret=1
zskfile=$(cat ns3/legacy-keys.kasp.zsk)
basefile=$(key_get KEY2 BASEFILE)
echo_i "filename: $basefile (expect $zskfile)"
test "$DIR/$zskfile" = "$basefile" || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# KSK times.
created=$(key_get KEY1 CREATED)
keyfile=$(key_get KEY1 BASEFILE)
grep "; Publish:" "${keyfile}.key" >published.test${n}.key1
published=$(awk '{print $3}' <published.test${n}.key1)
set_keytime "KEY1" "PUBLISHED" "${published}"
set_keytime "KEY1" "ACTIVE" "${published}"
published=$(key_get KEY1 PUBLISHED)
# The DS can be published if the zone is fully signed.
# This happens after max-zone-ttl (1d) plus
# zone-propagation-delay (300s) = 86400 + 300 = 86700.
set_addkeytime "KEY1" "SYNCPUBLISH" "${published}" 86700
# Key lifetime is 6 months, 315360000 seconds.
set_addkeytime "KEY1" "RETIRED" "${published}" 16070400
# The key is removed after the retire time plus DS TTL (1d), parent
# propagation delay (1h), and retire safety (1h) = 86400 + 3600 + 3600 = 93600.
retired=$(key_get KEY1 RETIRED)
set_addkeytime "KEY1" "REMOVED" "${retired}" 93600

# ZSK times.
created=$(key_get KEY2 CREATED)
keyfile=$(key_get KEY2 BASEFILE)
grep "; Publish:" "${keyfile}.key" >published.test${n}.key2
published=$(awk '{print $3}' <published.test${n}.key2)
set_keytime "KEY2" "PUBLISHED" "${published}"
set_keytime "KEY2" "ACTIVE" "${published}"
published=$(key_get KEY2 PUBLISHED)
# Key lifetime is 6 months, 315360000 seconds.
set_addkeytime "KEY2" "RETIRED" "${published}" 16070400
# The key is removed after the retire time plus max zone ttl (1d), zone
# propagation delay (300s), retire safety (1h), and sign delay (signature
# validity minus refresh, 9d) = 86400 + 300 + 3600 + 777600 = 867900.
retired=$(key_get KEY2 RETIRED)
set_addkeytime "KEY2" "REMOVED" "${retired}" 867900

check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone: keyfiles-missing.autosign.
#
set_zone "keyfiles-missing.autosign"
set_policy "autosign" "2" "300"
set_server "ns3" "10.53.0.3"
# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "63072000"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

key_clear "KEY2"
set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "31536000"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"

# Both KSK and ZSK stay OMNIPRESENT.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_autosign_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify
# All good, now remove key files and reload keys.
rm_keyfiles() {
  _basefile=$(key_get "$1" BASEFILE)
  echo_i "remove key files $_basefile"
  _keyfile="${_basefile}.key"
  _privatefile="${_basefile}.private"
  _statefile="${_basefile}.state"
  rm -f $_keyfile
  rm -f $_privatefile
  rm -f $_statefile
}
rm_keyfiles "KEY1"
rm_keyfiles "KEY2"

rndccmd 10.53.0.3 loadkeys "$ZONE" >/dev/null || log_error "rndc loadkeys zone ${ZONE} failed"
wait_for_log 3 "zone $ZONE/IN (signed): zone_rekey:zone_verifykeys failed: some key files are missing" $DIR/named.run || ret=1
# Check keys again, make sure no new keys are created.
set_policy "autosign" "0" "300"
key_clear "KEY1"
key_clear "KEY2"
check_keys
# Zone is still signed correctly.
dnssec_verify

#
# Test dnssec-policy inheritance.
#

# These zones should be unsigned:
# ns2/unsigned.tld
# ns4/none.inherit.signed
# ns4/none.override.signed
# ns4/inherit.none.signed
# ns4/none.none.signed
# ns5/inherit.inherit.unsigned
# ns5/none.inherit.unsigned
# ns5/none.override.unsigned
# ns5/inherit.none.unsigned
# ns5/none.none.unsigned
key_clear "KEY1"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

set_zone "unsigned.tld"
set_policy "none" "0" "0"
set_server "ns2" "10.53.0.2"
TSIG=""
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain

set_zone "none.inherit.signed"
set_policy "none" "0" "0"
set_server "ns4" "10.53.0.4"
TSIG="hmac-sha1:sha1:$SHA1"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain

set_zone "none.override.signed"
set_policy "none" "0" "0"
set_server "ns4" "10.53.0.4"
TSIG="hmac-sha224:sha224:$SHA224"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain

set_zone "inherit.none.signed"
set_policy "none" "0" "0"
set_server "ns4" "10.53.0.4"
TSIG="hmac-sha256:sha256:$SHA256"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain

set_zone "none.none.signed"
set_policy "none" "0" "0"
set_server "ns4" "10.53.0.4"
TSIG="hmac-sha256:sha256:$SHA256"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain

set_zone "inherit.inherit.unsigned"
set_policy "none" "0" "0"
set_server "ns5" "10.53.0.5"
TSIG="hmac-sha1:sha1:$SHA1"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain

set_zone "none.inherit.unsigned"
set_policy "none" "0" "0"
set_server "ns5" "10.53.0.5"
TSIG="hmac-sha1:sha1:$SHA1"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain

set_zone "none.override.unsigned"
set_policy "none" "0" "0"
set_server "ns5" "10.53.0.5"
TSIG="hmac-sha224:sha224:$SHA224"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain

set_zone "inherit.none.unsigned"
set_policy "none" "0" "0"
set_server "ns5" "10.53.0.5"
TSIG="hmac-sha256:sha256:$SHA256"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain

set_zone "none.none.unsigned"
set_policy "none" "0" "0"
set_server "ns5" "10.53.0.5"
TSIG="hmac-sha256:sha256:$SHA256"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain

# These zones should be signed with the default policy:
# ns2/signed.tld
# ns4/override.inherit.signed
# ns4/inherit.override.signed
# ns5/override.inherit.signed
# ns5/inherit.override.signed
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"

set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_ZRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"

set_zone "signed.tld"
set_policy "default" "1" "3600"
set_server "ns2" "10.53.0.2"
TSIG=""
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_csk_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

set_zone "override.inherit.signed"
set_policy "default" "1" "3600"
set_server "ns4" "10.53.0.4"
TSIG="hmac-sha1:sha1:$SHA1"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_csk_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

set_zone "inherit.override.signed"
set_policy "default" "1" "3600"
set_server "ns4" "10.53.0.4"
TSIG="hmac-sha224:sha224:$SHA224"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_csk_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

set_zone "override.inherit.unsigned"
set_policy "default" "1" "3600"
set_server "ns5" "10.53.0.5"
TSIG="hmac-sha1:sha1:$SHA1"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_csk_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

set_zone "inherit.override.unsigned"
set_policy "default" "1" "3600"
set_server "ns5" "10.53.0.5"
TSIG="hmac-sha224:sha224:$SHA224"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_csk_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

# These zones should be signed with the test policy:
# ns4/inherit.inherit.signed
# ns4/override.override.signed
# ns4/override.none.signed
# ns5/override.override.unsigned
# ns5/override.none.unsigned
# ns4/example.net (both views)
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "14" "ECDSAP384SHA384" "384"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"

set_zone "inherit.inherit.signed"
set_policy "test" "1" "3600"
set_server "ns4" "10.53.0.4"
TSIG="hmac-sha1:sha1:$SHA1"
wait_for_nsec
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_csk_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

set_zone "override.override.signed"
set_policy "test" "1" "3600"
set_server "ns4" "10.53.0.4"
TSIG="hmac-sha224:sha224:$SHA224"
wait_for_nsec
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_csk_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

set_zone "override.none.signed"
set_policy "test" "1" "3600"
set_server "ns4" "10.53.0.4"
TSIG="hmac-sha256:sha256:$SHA256"
wait_for_nsec
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_csk_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

set_zone "override.override.unsigned"
set_policy "test" "1" "3600"
set_server "ns5" "10.53.0.5"
TSIG="hmac-sha224:sha224:$SHA224"
wait_for_nsec
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_csk_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

set_zone "override.none.unsigned"
set_policy "test" "1" "3600"
set_server "ns5" "10.53.0.5"
TSIG="hmac-sha256:sha256:$SHA256"
wait_for_nsec
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_csk_policy
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Test with views.
set_zone "example.net"
set_server "ns4" "10.53.0.4"
TSIG="$DEFAULT_HMAC:keyforview1:$VIEW1"
wait_for_nsec
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE" "example1"
set_keytimes_csk_policy
check_keytimes
check_apex
dnssec_verify
# check zonestatus
n=$((n + 1))
echo_i "check $ZONE (view example1) zonestatus ($n)"
ret=0
check_isdynamic "$SERVER" "$ZONE" "example1" || log_error "zone not dynamic"
check_inlinesigning "$SERVER" "$ZONE" "example1" && log_error "inline-signing enabled, expected disabled"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# check subdomain
n=$((n + 1))
echo_i "check TXT example.net (view example1) rrset is signed correctly ($n)"
ret=0
dig_with_opts "view.${ZONE}" "@${SERVER}" TXT >"dig.out.$DIR.test$n.txt" || log_error "dig view.${ZONE} TXT failed"
grep "status: NOERROR" "dig.out.$DIR.test$n.txt" >/dev/null || log_error "mismatch status in DNS response"
grep "view.${ZONE}\..*${DEFAULT_TTL}.*IN.*TXT.*view1" "dig.out.$DIR.test$n.txt" >/dev/null || log_error "missing view.${ZONE} TXT record in response"
check_signatures TXT "dig.out.$DIR.test$n.txt" "ZSK"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

TSIG="$DEFAULT_HMAC:keyforview2:$VIEW2"
wait_for_nsec
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE" "example2"
check_apex
dnssec_verify
# check zonestatus
n=$((n + 1))
echo_i "check $ZONE (view example2) zonestatus ($n)"
ret=0
check_isdynamic "$SERVER" "$ZONE" "example2" && log_error "zone dynamic, but not expected"
check_inlinesigning "$SERVER" "$ZONE" "example2" || log_error "inline-signing disabled, expected enabled"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# check subdomain
n=$((n + 1))
echo_i "check TXT example.net (view example2) rrset is signed correctly ($n)"
ret=0
dig_with_opts "view.${ZONE}" "@${SERVER}" TXT >"dig.out.$DIR.test$n.txt" || log_error "dig view.${ZONE} TXT failed"
grep "status: NOERROR" "dig.out.$DIR.test$n.txt" >/dev/null || log_error "mismatch status in DNS response"
grep "view.${ZONE}\..*${DEFAULT_TTL}.*IN.*TXT.*view2" "dig.out.$DIR.test$n.txt" >/dev/null || log_error "missing view.${ZONE} TXT record in response"
check_signatures TXT "dig.out.$DIR.test$n.txt" "ZSK"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

TSIG="$DEFAULT_HMAC:keyforview3:$VIEW3"
wait_for_nsec
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE" "example3"
check_apex
dnssec_verify
# check zonestatus
n=$((n + 1))
echo_i "check $ZONE (view example3) zonestatus ($n)"
ret=0
check_isdynamic "$SERVER" "$ZONE" "example3" && log_error "zone dynamic, but not expected"
check_inlinesigning "$SERVER" "$ZONE" "example3" || log_error "inline-signing disabled, expected enabled"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# check subdomain
n=$((n + 1))
echo_i "check TXT example.net (view example3) rrset is signed correctly ($n)"
ret=0
dig_with_opts "view.${ZONE}" "@${SERVER}" TXT >"dig.out.$DIR.test$n.txt" || log_error "dig view.${ZONE} TXT failed"
grep "status: NOERROR" "dig.out.$DIR.test$n.txt" >/dev/null || log_error "mismatch status in DNS response"
grep "view.${ZONE}\..*${DEFAULT_TTL}.*IN.*TXT.*view2" "dig.out.$DIR.test$n.txt" >/dev/null || log_error "missing view.${ZONE} TXT record in response"
check_signatures TXT "dig.out.$DIR.test$n.txt" "ZSK"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

# Clear TSIG.
TSIG=""

#
# Testing RFC 8901 Multi-Signer Model 2.
#
set_zone "multisigner-model2.kasp"
set_policy "multisigner-model2" "2" "3600"
set_server "ns3" "10.53.0.3"
key_clear "KEY1"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

# Key properties.
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "0"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"

set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"
set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
set_keystate "KEY2" "STATE_ZRRSIG" "rumoured"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

# Check that the ZSKs from the other providers are published.
zsks_are_published() {
  num=$1
  dig_with_opts +short "$ZONE" "@${SERVER}" DNSKEY >"dig.out.$DIR.test$n" || return 1
  # We should have three ZSKs.
  lines=$(grep "256 3 13" dig.out.$DIR.test$n | wc -l)
  test "$lines" -eq $num || return 1
  # And one KSK.
  lines=$(grep "257 3 13" dig.out.$DIR.test$n | wc -l)
  test "$lines" -eq 1 || return 1
}
n=$((n + 1))
echo_i "check initial number of ZSKs (one from us and one from another provider) for zone ${ZONE} ($n)"
ret=0
retry_quiet 10 zsks_are_published 2 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "update zone with ZSK from another provider for zone ${ZONE} ($n)"
ret=0
(
  echo zone ${ZONE}
  echo server 10.53.0.3 "$PORT"
  echo update add $(cat "${DIR}/${ZONE}.zsk2")
  echo send
) | $NSUPDATE
retry_quiet 10 zsks_are_published 3 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "remove ZSKs from the other providers for zone ${ZONE} ($n)"
ret=0
(
  echo zone ${ZONE}
  echo server 10.53.0.3 "$PORT"
  echo update del $(cat "${DIR}/${ZONE}.zsk1")
  echo update del $(cat "${DIR}/${ZONE}.zsk2")
  echo send
) | $NSUPDATE
retry_quiet 10 zsks_are_published 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

#
# A zone transitioning from single-signed to multi-signed.
# We should have the old omnipresent keys outside of the
# desired key range and the new keys in the desired key range
# KEY1 and KEY2 are the new keys. KEY3 and KEY4 are the old keys.
#
set_zone "single-to-multisigner.kasp"
set_policy "multisigner-model2" "4" "3600"
set_server "ns3" "10.53.0.3"
key_clear "KEY1"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

# Key properties.
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "0"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "no" # waiting for DNSKEY to be omnipresent

set_keyrole "KEY3" "ksk"
set_keyalgorithm "KEY3" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY3" "yes"
set_zonesigning "KEY3" "no"

set_keyrole "KEY4" "zsk"
set_keyalgorithm "KEY4" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY4" "no"
set_zonesigning "KEY4" "yes"

set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
set_keystate "KEY2" "STATE_ZRRSIG" "hidden" # waiting for DNSKEY to be omnipresent

set_keystate "KEY3" "GOAL" "hidden"
set_keystate "KEY3" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY3" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY3" "STATE_DS" "omnipresent"

set_keystate "KEY4" "GOAL" "hidden"
set_keystate "KEY4" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY4" "STATE_ZRRSIG" "omnipresent"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

# KEY1 tag range 32768 65535
# KEY2 tag range 32768 65535
# KEY3 tag range 0 32767
# KEY4 tag range 0 32767
n=$((n + 1))
echo_i "check that the key IDs are in the expected ranges ($n)"
ret=0
test $(key_get KEY1 ID) -ge 32768 -a $(key_get KEY1 ID) -le 65535 || ret=1
test $(key_get KEY2 ID) -ge 32768 -a $(key_get KEY2 ID) -le 65535 || ret=1
test $(key_get KEY3 ID) -ge 0 -a $(key_get KEY3 ID) -le 32767 || ret=1
test $(key_get KEY4 ID) -ge 0 -a $(key_get KEY4 ID) -le 32767 || ret=1

test $(key_get KEY1 RID) -ge 32768 -a $(key_get KEY1 RID) -le 65535 || ret=1
test $(key_get KEY2 RID) -ge 32768 -a $(key_get KEY2 RID) -le 65535 || ret=1
test $(key_get KEY3 RID) -ge 0 -a $(key_get KEY3 RID) -le 32767 || ret=1
test $(key_get KEY4 RID) -ge 0 -a $(key_get KEY4 RID) -le 32767 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

#
# Testing manual rollover.
#
set_zone "manual-rollover.kasp"
set_policy "manual-rollover" "2" "3600"
set_server "ns3" "10.53.0.3"
key_clear "KEY1"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"
# Key properties.
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "0"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"
# During set up everything was set to OMNIPRESENT.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# The first keys were published and activated a day ago.
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "PUBLISHED" "${created}" -86400
set_addkeytime "KEY1" "SYNCPUBLISH" "${created}" -86400
set_addkeytime "KEY1" "ACTIVE" "${created}" -86400
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED" "${created}" -86400
set_addkeytime "KEY2" "ACTIVE" "${created}" -86400
# Key lifetimes are unlimited, so not setting RETIRED and REMOVED.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Schedule KSK rollover in six months (15552000 seconds).
active=$(key_get KEY1 ACTIVE)
set_addkeytime "KEY1" "RETIRED" "${active}" 15552000
retired=$(key_get KEY1 RETIRED)
rndc_rollover "$SERVER" "$DIR" $(key_get KEY1 ID) "${retired}" "$ZONE"
set_addkeytime "KEY1" "RETIRED" "${active}" 15559500
retired=$(key_get KEY1 RETIRED)
# Retire interval of this policy is 26h (93600 seconds).
set_addkeytime "KEY1" "REMOVED" "${retired}" 93600

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Schedule KSK rollover now.
set_policy "manual-rollover" "3" "3600"
set_keystate "KEY1" "GOAL" "hidden"
created=$(key_get KEY1 CREATED)
set_keytime "KEY1" "RETIRED" "${created}"
rndc_rollover "$SERVER" "$DIR" $(key_get KEY1 ID) "${created}" "$ZONE"
# New key is introduced.
set_keyrole "KEY3" "ksk"
set_keylifetime "KEY3" "0"
set_keyalgorithm "KEY3" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY3" "yes"
set_zonesigning "KEY3" "no"

set_keystate "KEY3" "GOAL" "omnipresent"
set_keystate "KEY3" "STATE_DNSKEY" "rumoured"
set_keystate "KEY3" "STATE_KRRSIG" "rumoured"
set_keystate "KEY3" "STATE_DS" "hidden"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

# Schedule ZSK rollover now.
set_policy "manual-rollover" "4" "3600"
set_keystate "KEY2" "GOAL" "hidden"
created=$(key_get KEY2 CREATED)
set_keytime "KEY2" "RETIRED" "${created}"
rndc_rollover "$SERVER" "$DIR" $(key_get KEY2 ID) "${created}" "$ZONE"
# New key is introduced.
set_keyrole "KEY4" "zsk"
set_keylifetime "KEY4" "0"
set_keyalgorithm "KEY4" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY4" "no"
set_zonesigning "KEY4" "no" # not yet, first prepublish DNSKEY.

set_keystate "KEY4" "GOAL" "omnipresent"
set_keystate "KEY4" "STATE_DNSKEY" "rumoured"
set_keystate "KEY4" "STATE_ZRRSIG" "hidden"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

# Try to schedule a ZSK rollover for an inactive key (should fail).
n=$((n + 1))
echo_i "check that rndc dnssec -rollover fails if key is inactive ($n)"
ret=0
rndccmd "$SERVER" dnssec -rollover -key $(key_get KEY4 ID) "$ZONE" >rndc.dnssec.rollover.out.$ZONE.$n || ret=1
grep "key is not actively signing" rndc.dnssec.rollover.out.$ZONE.$n >/dev/null || log_error "bad error message"
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

#
# Testing DNSSEC introduction.
#

#
# Zone: step1.enable-dnssec.autosign.
#
set_zone "step1.enable-dnssec.autosign"
set_policy "enable-dnssec" "1" "300"
set_server "ns3" "10.53.0.3"
# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
# The DNSKEY and signatures are introduced first, the DS remains hidden.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_ZRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"
# This policy lists only one key (CSK).
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The first key is immediately published and activated.
created=$(key_get KEY1 CREATED)
set_keytime "KEY1" "PUBLISHED" "${created}"
set_keytime "KEY1" "ACTIVE" "${created}"
# - The DS can be published if the DNSKEY and RRSIG records are
#   OMNIPRESENT.  This happens after max-zone-ttl (12h) plus
#   plus zone-propagation-delay (5m) =
#   43200 + 300 = 43500.
set_addkeytime "KEY1" "SYNCPUBLISH" "${created}" 43500
# - Key lifetime is unlimited, so not setting RETIRED and REMOVED.

# Various signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

_check_next_key_event() {
  _expect=$1

  grep "zone ${ZONE}.*: next key event in .* seconds" "${DIR}/named.run" >"keyevent.out.$ZONE.test$n" || return 1

  # Get the latest next key event.
  if [ "${DYNAMIC}" = "yes" ]; then
    _time=$(awk '{print $8}' <"keyevent.out.$ZONE.test$n" | tail -1)
  else
    # inline-signing zone adds "(signed)"
    _time=$(awk '{print $9}' <"keyevent.out.$ZONE.test$n" | tail -1)
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

# Next key event is when the DNSKEY RRset becomes OMNIPRESENT: DNSKEY TTL plus
# publish safety plus the zone propagation delay: 900 seconds.
check_next_key_event 900

#
# Zone: step2.enable-dnssec.autosign.
#
set_zone "step2.enable-dnssec.autosign"
set_policy "enable-dnssec" "1" "300"
set_server "ns3" "10.53.0.3"
# The DNSKEY is omnipresent, but the zone signatures not yet.
# Thus, the DS remains hidden.
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The key was published and activated 900 seconds ago (with settime).
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "PUBLISHED" "${created}" -900
set_addkeytime "KEY1" "ACTIVE" "${created}" -900
set_addkeytime "KEY1" "SYNCPUBLISH" "${created}" 42600

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the zone signatures become OMNIPRESENT: max-zone-ttl
# plus zone propagation delay plus retire safety minus the already elapsed
# 900 seconds: 12h + 300s + 20m - 900 = 43500 - 900 = 42600 seconds
check_next_key_event 42600

#
# Zone: step3.enable-dnssec.autosign.
#
set_zone "step3.enable-dnssec.autosign"
set_policy "enable-dnssec" "1" "300"
set_server "ns3" "10.53.0.3"
# All signatures should be omnipresent, so the DS can be submitted.
set_keystate "KEY1" "STATE_ZRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "rumoured"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The key was published and activated 43500 seconds ago (with settime).
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "PUBLISHED" "${created}" -43500
set_addkeytime "KEY1" "ACTIVE" "${created}" -43500
set_keytime "KEY1" "SYNCPUBLISH" "${created}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify
# Check that CDS publication is logged.
check_cdslog "$DIR" "$ZONE" KEY1

# The DS can be introduced. We ignore any parent registration delay, so set
# the DS publish time to now.
rndc_checkds "$SERVER" "$DIR" KEY1 "now" "published" "$ZONE"
# Next key event is when the DS can move to the OMNIPRESENT state.  This occurs
# when the parent propagation delay have passed, plus the DS TTL and retire
# safety delay:  1h + 2h = 3h = 10800 seconds
check_next_key_event 10800

#
# Zone: step4.enable-dnssec.autosign.
#
set_zone "step4.enable-dnssec.autosign"
set_policy "enable-dnssec" "1" "300"
set_server "ns3" "10.53.0.3"
# The DS is omnipresent.
set_keystate "KEY1" "STATE_DS" "omnipresent"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The key was published and activated 56700 seconds ago (with settime).
created=$(key_get KEY1 CREATED)
set_addkeytime "KEY1" "PUBLISHED" "${created}" -56700
set_addkeytime "KEY1" "ACTIVE" "${created}" -56700
set_addkeytime "KEY1" "SYNCPUBLISH" "${created}" -12000

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is never, the zone dnssec-policy has been established. So we
# fall back to the default loadkeys interval.
check_next_key_event 3600

#
# Testing ZSK Pre-Publication rollover.
#

# Policy parameters.
# Lksk:      2 years (63072000 seconds)
# Lzsk:      30 days (2592000 seconds)
# Iret(KSK): DS TTL (1d) + DprpP (1h) + retire-safety (2d)
# Iret(KSK): 3d1h (262800 seconds)
# Iret(ZSK): RRSIG TTL (1d) + Dprp (1h) + Dsgn (1w) + retire-safety (2d)
# Iret(ZSK): 10d1h (867600 seconds)
Lksk=63072000
Lzsk=2592000
IretKSK=262800
IretZSK=867600

#
# Zone: step1.zsk-prepub.autosign.
#
set_zone "step1.zsk-prepub.autosign"
set_policy "zsk-prepub" "2" "3600"
set_server "ns3" "10.53.0.3"

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

# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "${Lksk}"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

key_clear "KEY2"
set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "${Lzsk}"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"
# Both KSK (KEY1) and ZSK (KEY2) start in OMNIPRESENT.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"
# Initially only two keys.
key_clear "KEY3"
key_clear "KEY4"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# These keys are immediately published and activated.
rollover_predecessor_keytimes 0
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the successor ZSK needs to be published.  That is
# the ZSK lifetime - prepublication time.  The prepublication time is DNSKEY
# TTL plus publish safety plus the zone propagation delay.  For the
# zsk-prepub policy that means: 30d - 3600s + 1d + 1h = 2498400 seconds.
check_next_key_event 2498400

#
# Zone: step2.zsk-prepub.autosign.
#
set_zone "step2.zsk-prepub.autosign"
set_policy "zsk-prepub" "3" "3600"
set_server "ns3" "10.53.0.3"
# New ZSK (KEY3) is prepublished, but not yet signing.
key_clear "KEY3"
set_keyrole "KEY3" "zsk"
set_keylifetime "KEY3" "${Lzsk}"
set_keyalgorithm "KEY3" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY3" "no"
set_zonesigning "KEY3" "no"
# Key states.
set_keystate "KEY2" "GOAL" "hidden"
set_keystate "KEY3" "GOAL" "omnipresent"
set_keystate "KEY3" "STATE_DNSKEY" "rumoured"
set_keystate "KEY3" "STATE_ZRRSIG" "hidden"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys were activated 694 hours ago (2498400 seconds).
rollover_predecessor_keytimes -2498400
# - The new ZSK is published now.
created=$(key_get KEY3 CREATED)
set_keytime "KEY3" "PUBLISHED" "${created}"
# - The new ZSK becomes active when the DNSKEY is OMNIPRESENT.
#   Ipub: TTLkey (1h) + Dprp (1h) + publish-safety (1d)
#   Ipub: 26 hour (93600 seconds).
IpubZSK=93600
set_addkeytime "KEY3" "ACTIVE" "${created}" "${IpubZSK}"
set_retired_removed "KEY3" "${Lzsk}" "${IretZSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the successor ZSK becomes OMNIPRESENT.  That is the
# DNSKEY TTL plus the zone propagation delay, plus the publish-safety. For
# the zsk-prepub policy, this means: 3600s + 1h + 1d = 93600 seconds.
check_next_key_event 93600

#
# Zone: step3.zsk-prepub.autosign.
#
set_zone "step3.zsk-prepub.autosign"
set_policy "zsk-prepub" "3" "3600"
set_server "ns3" "10.53.0.3"
# ZSK (KEY2) no longer is actively signing, RRSIG state in UNRETENTIVE.
# New ZSK (KEY3) is now actively signing, RRSIG state in RUMOURED.
set_zonesigning "KEY2" "no"
set_keystate "KEY2" "STATE_ZRRSIG" "unretentive"
set_zonesigning "KEY3" "yes"
set_keystate "KEY3" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY3" "STATE_ZRRSIG" "rumoured"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys are activated 30 days ago (2592000 seconds).
rollover_predecessor_keytimes -2592000
# - The new ZSK is published 26 hours ago (93600 seconds).
created=$(key_get KEY3 CREATED)
set_addkeytime "KEY3" "PUBLISHED" "${created}" -93600
set_keytime "KEY3" "ACTIVE" "${created}"
set_retired_removed "KEY3" "${Lzsk}" "${IretZSK}"

# Continue signing policy checks.
check_keytimes
check_apex
# Subdomain still has good signatures of ZSK (KEY2).
# Set expected zone signing on for KEY2 and off for KEY3,
# testing whether signatures which are still valid are being reused.
set_zonesigning "KEY2" "yes"
set_zonesigning "KEY3" "no"
check_subdomain
# Restore the expected zone signing properties.
set_zonesigning "KEY2" "no"
set_zonesigning "KEY3" "yes"
dnssec_verify

# Next key event is when all the RRSIG records have been replaced with
# signatures of the new ZSK, in other words when ZRRSIG becomes OMNIPRESENT.
# That is Dsgn plus the maximum zone TTL plus the zone propagation delay plus
# retire-safety. For the zsk-prepub policy that means: 1w (because 2w validity
# and refresh within a week) + 1d + 1h + 2d = 10d1h = 867600 seconds.
check_next_key_event 867600

#
# Zone: step4.zsk-prepub.autosign.
#
set_zone "step4.zsk-prepub.autosign"
set_policy "zsk-prepub" "3" "3600"
set_server "ns3" "10.53.0.3"
# ZSK (KEY2) DNSKEY is no longer needed.
# ZSK (KEY3) is now actively signing, RRSIG state in RUMOURED.
set_keystate "KEY2" "STATE_DNSKEY" "unretentive"
set_keystate "KEY2" "STATE_ZRRSIG" "hidden"
set_keystate "KEY3" "STATE_ZRRSIG" "omnipresent"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys are activated 961 hours ago (3459600 seconds).
rollover_predecessor_keytimes -3459600
# - The new ZSK is published 267 hours ago (961200 seconds).
created=$(key_get KEY3 CREATED)
set_addkeytime "KEY3" "PUBLISHED" "${created}" -961200
published=$(key_get KEY3 PUBLISHED)
set_addkeytime "KEY3" "ACTIVE" "${published}" "${IpubZSK}"
set_retired_removed "KEY3" "${Lzsk}" "${IretZSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the DNSKEY enters the HIDDEN state.  This is the
# DNSKEY TTL plus zone propagation delay. For the zsk-prepub policy this is:
# 3600s + 1h = 7200s
check_next_key_event 7200

#
# Zone: step5.zsk-prepub.autosign.
#
set_zone "step5.zsk-prepub.autosign"
set_policy "zsk-prepub" "3" "3600"
set_server "ns3" "10.53.0.3"
# ZSK (KEY2) DNSKEY is now completely HIDDEN and removed.
set_keystate "KEY2" "STATE_DNSKEY" "hidden"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys are activated 962 hours ago (3463200 seconds).
rollover_predecessor_keytimes -3463200
# - The new ZSK is published 268 hours ago (964800 seconds).
created=$(key_get KEY3 CREATED)
set_addkeytime "KEY3" "PUBLISHED" "${created}" -964800
published=$(key_get KEY3 PUBLISHED)
set_addkeytime "KEY3" "ACTIVE" "${published}" "${IpubZSK}"
set_retired_removed "KEY3" "${Lzsk}" "${IretZSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the new successor needs to be published.  This is the
# ZSK lifetime minus Iret minus Ipub minus DNSKEY TTL.  For the zsk-prepub
# policy this is: 30d - 867600s - 93600s - 3600s = 1627200 seconds.
check_next_key_event 1627200

#
# Zone: step6.zsk-prepub.autosign.
#
set_zone "step6.zsk-prepub.autosign"
set_policy "zsk-prepub" "2" "3600"
set_server "ns3" "10.53.0.3"
# ZSK (KEY2) DNSKEY is purged.
key_clear "KEY2"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

#
# Testing KSK Double-KSK rollover.
#

# Policy parameters.
# Lksk:      60 days (16070400 seconds)
# Lzsk:      1 year (31536000 seconds)
# Iret(KSK): DS TTL (1h) + DprpP (1h) + retire-safety (2d)
# Iret(KSK): 50h (180000 seconds)
# Iret(ZSK): RRSIG TTL (1d) + Dprp (1h) + Dsgn (1w) + retire-safety (2d)
# Iret(ZSK): 10d1h (867600 seconds)
Lksk=5184000
Lzsk=31536000
IretKSK=180000
IretZSK=867600

#
# Zone: step1.ksk-doubleksk.autosign.
#
set_zone "step1.ksk-doubleksk.autosign"
set_policy "ksk-doubleksk" "2" "7200"
CDNSKEY="no"
set_server "ns3" "10.53.0.3"
# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "${Lksk}"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "no"

key_clear "KEY2"
set_keyrole "KEY2" "zsk"
set_keylifetime "KEY2" "${Lzsk}"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "no"
set_zonesigning "KEY2" "yes"
# Both KSK (KEY1) and ZSK (KEY2) start in OMNIPRESENT.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"

set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"
# Initially only two keys.
key_clear "KEY3"
key_clear "KEY4"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# These keys are immediately published and activated.
rollover_predecessor_keytimes 0
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the successor KSK needs to be published.  That is
# the KSK lifetime - prepublication time.  The prepublication time is
# DNSKEY TTL plus publish safety plus the zone propagation delay.
# For the ksk-doubleksk policy that means: 60d - (1d3h) = 5086800 seconds.
check_next_key_event 5086800

#
# Zone: step2.ksk-doubleksk.autosign.
#
set_zone "step2.ksk-doubleksk.autosign"
set_policy "ksk-doubleksk" "3" "7200"
CDNSKEY="no"
set_server "ns3" "10.53.0.3"
# New KSK (KEY3) is prepublished (and signs DNSKEY RRset).
key_clear "KEY3"
set_keyrole "KEY3" "ksk"
set_keylifetime "KEY3" "${Lksk}"
set_keyalgorithm "KEY3" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY3" "yes"
set_zonesigning "KEY3" "no"
# Key states.
set_keystate "KEY1" "GOAL" "hidden"
set_keystate "KEY3" "GOAL" "omnipresent"
set_keystate "KEY3" "STATE_DNSKEY" "rumoured"
set_keystate "KEY3" "STATE_KRRSIG" "rumoured"
set_keystate "KEY3" "STATE_DS" "hidden"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys were activated 1413 hours ago (5086800 seconds).
rollover_predecessor_keytimes -5086800
# - The new KSK is published now.
created=$(key_get KEY3 CREATED)
set_keytime "KEY3" "PUBLISHED" "${created}"
# The new KSK should publish the CDS after the prepublication time.
# TTLkey:         2h
# DprpC:          1h
# publish-safety: 1d
# IpubC:          27h (97200 seconds)
IpubC=97200
set_addkeytime "KEY3" "SYNCPUBLISH" "${created}" "${IpubC}"
set_addkeytime "KEY3" "ACTIVE" "${created}" "${IpubC}"
set_retired_removed "KEY3" "${Lksk}" "${IretKSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the successor KSK becomes OMNIPRESENT.  That is the
# DNSKEY TTL plus the zone propagation delay, plus the publish-safety.  For
# the ksk-doubleksk policy, this means: 7200s + 1h + 1d = 97200 seconds.
check_next_key_event 97200

#
# Zone: step3.ksk-doubleksk.autosign.
#
set_zone "step3.ksk-doubleksk.autosign"
set_policy "ksk-doubleksk" "3" "7200"
CDNSKEY="no"
set_server "ns3" "10.53.0.3"

# The DNSKEY RRset has become omnipresent.
# Check keys before we tell named that we saw the DS has been replaced.
set_keystate "KEY3" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY3" "STATE_KRRSIG" "omnipresent"
# The old DS (KEY1) can be withdrawn and the new DS (KEY3) can be introduced.
set_keystate "KEY1" "STATE_DS" "unretentive"
set_keystate "KEY3" "STATE_DS" "rumoured"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# Check that CDS publication is logged.
check_cdslog "$DIR" "$ZONE" KEY3

# Set expected key times:
# - The old keys were activated 60 days ago (5184000 seconds).
rollover_predecessor_keytimes -5184000
# - The new KSK is published 27 hours ago (97200 seconds).
created=$(key_get KEY3 CREATED)
set_addkeytime "KEY3" "PUBLISHED" "${created}" -97200
# - The new KSK CDS is published now.
set_keytime "KEY3" "SYNCPUBLISH" "${created}"
syncpub=$(key_get KEY3 SYNCPUBLISH)
set_keytime "KEY3" "ACTIVE" "${syncpub}"
set_retired_removed "KEY3" "${Lksk}" "${IretKSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# We ignore any parent registration delay, so set the DS publish time to now.
rndc_checkds "$SERVER" "$DIR" KEY1 "now" "withdrawn" "$ZONE"
rndc_checkds "$SERVER" "$DIR" KEY3 "now" "published" "$ZONE"
# Next key event is when the predecessor DS has been replaced with the
# successor DS and enough time has passed such that the all validators that
# have this DS RRset cached only know about the successor DS.  This is the
# the retire interval, which is the parent propagation delay plus the DS TTL
# plus the retire-safety.  For the ksk-double-ksk policy this means:
# 1h + 3600s + 2d = 2d2h = 180000 seconds.
check_next_key_event 180000

#
# Zone: step4.ksk-doubleksk.autosign.
#
set_zone "step4.ksk-doubleksk.autosign"
set_policy "ksk-doubleksk" "3" "7200"
CDNSKEY="no"
set_server "ns3" "10.53.0.3"
# KSK (KEY1) DNSKEY can be removed.
set_keysigning "KEY1" "no"
set_keystate "KEY1" "STATE_DNSKEY" "unretentive"
set_keystate "KEY1" "STATE_KRRSIG" "unretentive"
set_keystate "KEY1" "STATE_DS" "hidden"
# New KSK (KEY3) DS is now OMNIPRESENT.
set_keystate "KEY3" "STATE_DS" "omnipresent"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old keys were activated 1490 hours ago (5364000 seconds).
rollover_predecessor_keytimes -5364000
# - The new KSK is published 77 hours ago (277200 seconds).
created=$(key_get KEY3 CREATED)
set_addkeytime "KEY3" "PUBLISHED" "${created}" -277200
published=$(key_get KEY3 PUBLISHED)
set_addkeytime "KEY3" "SYNCPUBLISH" "${published}" "${IpubC}"
syncpub=$(key_get KEY3 SYNCPUBLISH)
set_keytime "KEY3" "ACTIVE" "${syncpub}"
set_retired_removed "KEY3" "${Lksk}" "${IretKSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the DNSKEY enters the HIDDEN state.  This is the
# DNSKEY TTL plus zone propagation delay. For the ksk-doubleksk policy this is:
# 7200s + 1h = 10800s
check_next_key_event 10800

#
# Zone: step5.ksk-doubleksk.autosign.
#
set_zone "step5.ksk-doubleksk.autosign"
set_policy "ksk-doubleksk" "3" "7200"
CDNSKEY="no"
set_server "ns3" "10.53.0.3"
# KSK (KEY1) DNSKEY is now HIDDEN.
set_keystate "KEY1" "STATE_DNSKEY" "hidden"
set_keystate "KEY1" "STATE_KRRSIG" "hidden"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - The old KSK is activated 1492 hours ago (5371200 seconds).
rollover_predecessor_keytimes -5371200
# - The new KSK is published 79 hours ago (284400 seconds).
created=$(key_get KEY3 CREATED)
set_addkeytime "KEY3" "PUBLISHED" "${created}" -284400
published=$(key_get KEY3 PUBLISHED)
set_addkeytime "KEY3" "SYNCPUBLISH" "${published}" "${IpubC}"
syncpub=$(key_get KEY3 SYNCPUBLISH)
set_keytime "KEY3" "ACTIVE" "${syncpub}"
set_retired_removed "KEY3" "${Lksk}" "${IretKSK}"

# Various signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the new successor needs to be published.  This is the
# KSK lifetime minus Ipub minus Iret minus DNSKEY TTL.  For the
# ksk-doubleksk this is: 60d - 1d3h - 1d - 2d2h - 2h =
# 5184000 - 97200 - 180000 - 7200 = 4813200 seconds.
check_next_key_event 4899600

#
# Zone: step6.ksk-doubleksk.autosign.
#
set_zone "step6.ksk-doubleksk.autosign"
set_policy "ksk-doubleksk" "2" "7200"
CDNSKEY="no"
set_server "ns3" "10.53.0.3"
# KSK (KEY1) DNSKEY is purged.
key_clear "KEY1"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

#
# Testing CSK key rollover (1).
#

# Policy parameters.
# Lcsk:      186 days (5184000 seconds)
# Iret(KSK): DS TTL (1h) + DprpP (1h) + retire-safety (2h)
# Iret(KSK): 4h (14400 seconds)
# Iret(ZSK): RRSIG TTL (1d) + Dprp (1h) + Dsgn (25d) + retire-safety (2h)
# Iret(ZSK): 26d3h (2257200 seconds)
Lcsk=16070400
IretKSK=14400
IretZSK=2257200
IretCSK=$IretZSK

csk_rollover_predecessor_keytimes() {
  _addtime=$1

  _created=$(key_get KEY1 CREATED)
  set_addkeytime "KEY1" "PUBLISHED" "${_created}" "${_addtime}"
  set_addkeytime "KEY1" "SYNCPUBLISH" "${_created}" "${_addtime}"
  set_addkeytime "KEY1" "ACTIVE" "${_created}" "${_addtime}"
  [ "$Lcsk" = 0 ] || set_retired_removed "KEY1" "${Lcsk}" "${IretCSK}"
}

#
# Zone: step1.csk-roll.autosign.
#
set_zone "step1.csk-roll.autosign"
set_policy "csk-roll" "1" "3600"
CDS_SHA256="no"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "${Lcsk}"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
# The CSK (KEY1) starts in OMNIPRESENT.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_ZRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"
# Initially only one key.
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# This key is immediately published and activated.
csk_rollover_predecessor_keytimes 0
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the successor CSK needs to be published.
# This is Lcsk - Ipub - Dreg.
# Lcsk: 186d (16070400 seconds)
# Ipub: 3h   (10800 seconds)
check_next_key_event 16059600

#
# Zone: step2.csk-roll.autosign.
#
set_zone "step2.csk-roll.autosign"
set_policy "csk-roll" "2" "3600"
CDS_SHA256="no"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# New CSK (KEY2) is prepublished (signs DNSKEY RRset, but not yet other RRsets).
key_clear "KEY2"
set_keyrole "KEY2" "csk"
set_keylifetime "KEY2" "16070400"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "yes"
set_zonesigning "KEY2" "no"
# Key states.
set_keystate "KEY1" "GOAL" "hidden"
set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
set_keystate "KEY2" "STATE_KRRSIG" "rumoured"
set_keystate "KEY2" "STATE_ZRRSIG" "hidden"
set_keystate "KEY2" "STATE_DS" "hidden"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - This key was activated 4461 hours ago (16059600 seconds).
csk_rollover_predecessor_keytimes -16059600
# - The new CSK is published now.
created=$(key_get KEY2 CREATED)
set_keytime "KEY2" "PUBLISHED" "${created}"
# - The new CSK should publish the CDS after the prepublication time.
#   Ipub: 3 hour (10800 seconds)
Ipub="10800"
set_addkeytime "KEY2" "SYNCPUBLISH" "${created}" "${Ipub}"
set_addkeytime "KEY2" "ACTIVE" "${created}" "${Ipub}"
set_retired_removed "KEY2" "${Lcsk}" "${IretCSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the successor CSK becomes OMNIPRESENT.  That is the
# DNSKEY TTL plus the zone propagation delay, plus the publish-safety. For
# the csk-roll policy, this means 3 hours = 10800 seconds.
check_next_key_event 10800

#
# Zone: step3.csk-roll.autosign.
#
set_zone "step3.csk-roll.autosign"
set_policy "csk-roll" "2" "3600"
CDS_SHA256="no"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# Swap zone signing role.
set_zonesigning "KEY1" "no"
set_zonesigning "KEY2" "yes"
# CSK (KEY1) will be removed, so moving to UNRETENTIVE.
set_keystate "KEY1" "STATE_ZRRSIG" "unretentive"
# New CSK (KEY2) DNSKEY is OMNIPRESENT, so moving ZRRSIG to RUMOURED.
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY2" "STATE_ZRRSIG" "rumoured"
# The old DS (KEY1) can be withdrawn and the new DS (KEY2) can be introduced.
set_keystate "KEY1" "STATE_DS" "unretentive"
set_keystate "KEY2" "STATE_DS" "rumoured"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# Check that CDS publication is logged.
check_cdslog "$DIR" "$ZONE" KEY2

# Set expected key times:
# - This key was activated 186 days ago (16070400 seconds).
csk_rollover_predecessor_keytimes -16070400
# - The new CSK is published three hours ago, CDS must be published now.
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED" "${created}" "-${Ipub}"
set_keytime "KEY2" "SYNCPUBLISH" "${created}"
# - Also signatures are being introduced now.
set_keytime "KEY2" "ACTIVE" "${created}"
set_retired_removed "KEY2" "${Lcsk}" "${IretCSK}"

# Continue signing policy checks.
check_keytimes
check_apex
# Subdomain still has good signatures of old CSK (KEY1).
# Set expected zone signing on for KEY1 and off for KEY2,
# testing whether signatures which are still valid are being reused.
set_zonesigning "KEY1" "yes"
set_zonesigning "KEY2" "no"
check_subdomain
# Restore the expected zone signing properties.
set_zonesigning "KEY1" "no"
set_zonesigning "KEY2" "yes"
dnssec_verify

# We ignore any parent registration delay, so set the DS publish time to now.
rndc_checkds "$SERVER" "$DIR" KEY1 "now" "withdrawn" "$ZONE"
rndc_checkds "$SERVER" "$DIR" KEY2 "now" "published" "$ZONE"
# Next key event is when the predecessor DS has been replaced with the
# successor DS and enough time has passed such that the all validators that
# have this DS RRset cached only know about the successor DS.  This is the
# the retire interval, which is the parent propagation delay plus the DS TTL
# plus the retire-safety.  For the csk-roll policy this means:
# 1h + 1h + 2h = 4h = 14400 seconds.
check_next_key_event 14400

#
# Zone: step4.csk-roll.autosign.
#
set_zone "step4.csk-roll.autosign"
set_policy "csk-roll" "2" "3600"
CDS_SHA256="no"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# The old CSK (KEY1) is no longer signing the DNSKEY RRset.
set_keysigning "KEY1" "no"
# The old CSK (KEY1) DS is hidden.  We still need to keep the DNSKEY public
# but can remove the KRRSIG records.
set_keystate "KEY1" "STATE_KRRSIG" "unretentive"
set_keystate "KEY1" "STATE_DS" "hidden"
# The new CSK (KEY2) DS is now OMNIPRESENT.
set_keystate "KEY2" "STATE_DS" "omnipresent"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - This key was activated 4468 hours ago (16084800 seconds).
csk_rollover_predecessor_keytimes -16084800
# - The new CSK started signing 4h ago (14400 seconds).
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "ACTIVE" "${created}" -14400
set_addkeytime "KEY2" "SYNCPUBLISH" "${created}" -14400
syncpub=$(key_get KEY2 SYNCPUBLISH)
set_addkeytime "KEY2" "PUBLISHED" "${syncpub}" "-${Ipub}"
set_retired_removed "KEY2" "${Lcsk}" "${IretCSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the KRRSIG enters the HIDDEN state.  This is the
# DNSKEY TTL plus zone propagation delay. For the csk-roll policy this is:
# 1h + 1h = 7200 seconds.
check_next_key_event 7200

#
# Zone: step5.csk-roll.autosign.
#
set_zone "step5.csk-roll.autosign"
set_policy "csk-roll" "2" "3600"
CDS_SHA256="no"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# The old CSK (KEY1) KRRSIG records are now all hidden.
set_keystate "KEY1" "STATE_KRRSIG" "hidden"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - This key was activated 4470 hours ago (16092000 seconds).
csk_rollover_predecessor_keytimes -16092000
# - The new CSK started signing 6h ago (21600 seconds).
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "ACTIVE" "${created}" -21600
set_addkeytime "KEY2" "SYNCPUBLISH" "${created}" -21600
syncpub=$(key_get KEY2 SYNCPUBLISH)
set_addkeytime "KEY2" "PUBLISHED" "${syncpub}" "-${Ipub}"
set_retired_removed "KEY2" "${Lcsk}" "${IretCSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the DNSKEY can be removed.  This is when all ZRRSIG
# records have been replaced with signatures of the new CSK.  We have
# calculated the interval to be 26d3h of which 4h (Iret(KSK)) plus
# 2h (DNSKEY TTL + Dprp) have already passed.  So next key event is in
# 26d3h - 4h - 2h = 621h = 2235600 seconds.
check_next_key_event 2235600

#
# Zone: step6.csk-roll.autosign.
#
set_zone "step6.csk-roll.autosign"
set_policy "csk-roll" "2" "3600"
CDS_SHA256="no"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# The old CSK (KEY1) ZRRSIG records are now all hidden (so the DNSKEY can
# be removed).
set_keystate "KEY1" "STATE_DNSKEY" "unretentive"
set_keystate "KEY1" "STATE_ZRRSIG" "hidden"
# The new CSK (KEY2) is now fully OMNIPRESENT.
set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times
# - This key was activated 5091 hours ago (18327600 seconds).
csk_rollover_predecessor_keytimes -18327600
# - The new CSK is activated 627 hours ago (2257200 seconds).
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "ACTIVE" "${created}" -2257200
set_addkeytime "KEY2" "SYNCPUBLISH" "${created}" -2257200
syncpub=$(key_get KEY2 SYNCPUBLISH)
set_addkeytime "KEY2" "PUBLISHED" "${syncpub}" "-${Ipub}"
set_retired_removed "KEY2" "${Lcsk}" "${IretCSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the DNSKEY enters the HIDDEN state.  This is the
# DNSKEY TTL plus zone propagation delay. For the csk-roll policy this is:
# 1h + 1h = 7200 seconds.
check_next_key_event 7200

#
# Zone: step7.csk-roll.autosign.
#
set_zone "step7.csk-roll.autosign"
set_policy "csk-roll" "2" "3600"
CDS_SHA256="no"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# The old CSK (KEY1) is now completely HIDDEN.
set_keystate "KEY1" "STATE_DNSKEY" "hidden"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - This key was activated 5093 hours ago (18334800 seconds).
csk_rollover_predecessor_keytimes -18334800
# - The new CSK is activated 629 hours ago (2264400 seconds).
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "ACTIVE" "${created}" -2264400
set_addkeytime "KEY2" "SYNCPUBLISH" "${created}" -2264400
syncpub=$(key_get KEY2 SYNCPUBLISH)
set_addkeytime "KEY2" "PUBLISHED" "${syncpub}" "-${Ipub}"
set_retired_removed "KEY2" "${Lcsk}" "${IretCSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the new successor needs to be published.
# This is the Lcsk, minus time passed since the key started signing,
# minus the prepublication time.
# Lcsk:        186d (16070400 seconds)
# Time passed: 629h (2264400 seconds)
# Ipub:        3h   (10800 seconds)
check_next_key_event 13795200

#
# Zone: step8.csk-roll.autosign.
#
set_zone "step8.csk-roll.autosign"
set_policy "csk-roll" "1" "3600"
CDS_SHA256="no"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# The old CSK (KEY1) is purged.
key_clear "KEY1"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

#
# Testing CSK key rollover (2).
#

# Policy parameters.
# Lcsk:      186 days (16070400 seconds)
# Dreg:      N/A
# Iret(KSK): DS TTL (1h) + DprpP (1w) + retire-safety (1h)
# Iret(KSK): 170h (61200 seconds)
# Iret(ZSK): RRSIG TTL (1d) + Dprp (1h) + Dsgn (12h) + retire-safety (1h)
# Iret(ZSK): 38h (136800 seconds)
Lcsk=16070400
IretKSK=612000
IretZSK=136800
IretCSK=$IretKSK

#
# Zone: step1.csk-roll2.autosign.
#
set_zone "step1.csk-roll2.autosign"
set_policy "csk-roll2" "1" "3600"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "16070400"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
# The CSK (KEY1) starts in OMNIPRESENT.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_ZRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"
# Initially only one key.
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# This key is immediately published and activated.
csk_rollover_predecessor_keytimes 0
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the successor CSK needs to be published.
# This is Lcsk - Ipub.
# Lcsk:  186d   (16070400 seconds)
# Ipub:  3h     (10800 seconds)
# Total: 186d3h (16059600 seconds)
check_next_key_event 16059600

#
# Zone: step2.csk-roll2.autosign.
#
set_zone "step2.csk-roll2.autosign"
set_policy "csk-roll2" "2" "3600"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# New CSK (KEY2) is prepublished (signs DNSKEY RRset, but not yet other RRsets).
key_clear "KEY2"
set_keyrole "KEY2" "csk"
set_keylifetime "KEY2" "16070400"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "yes"
set_zonesigning "KEY2" "no"
# Key states.
set_keystate "KEY1" "GOAL" "hidden"
set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "rumoured"
set_keystate "KEY2" "STATE_KRRSIG" "rumoured"
set_keystate "KEY2" "STATE_ZRRSIG" "hidden"
set_keystate "KEY2" "STATE_DS" "hidden"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - This key was activated 4461 hours ago (16059600 seconds).
csk_rollover_predecessor_keytimes -16059600
# - The new CSK is published now.
created=$(key_get KEY2 CREATED)
set_keytime "KEY2" "PUBLISHED" "${created}"
# - The new CSK should publish the CDS after the prepublication time.
# - Ipub: 3 hour (10800 seconds)
Ipub="10800"
set_addkeytime "KEY2" "SYNCPUBLISH" "${created}" "${Ipub}"
set_addkeytime "KEY2" "ACTIVE" "${created}" "${Ipub}"
set_retired_removed "KEY2" "${Lcsk}" "${IretCSK}"

# Continue signing policy checks.
check_apex
check_subdomain
dnssec_verify

# Next key event is when the successor CSK becomes OMNIPRESENT.  That is the
# DNSKEY TTL plus the zone propagation delay, plus the publish-safety. For
# the csk-roll2 policy, this means 3h hours = 10800 seconds.
check_next_key_event 10800

#
# Zone: step3.csk-roll2.autosign.
#
set_zone "step3.csk-roll2.autosign"
set_policy "csk-roll2" "2" "3600"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# CSK (KEY1) can be removed, so move to UNRETENTIVE.
set_zonesigning "KEY1" "no"
set_keystate "KEY1" "STATE_ZRRSIG" "unretentive"
# New CSK (KEY2) DNSKEY is OMNIPRESENT, so move ZRRSIG to RUMOURED state.
set_zonesigning "KEY2" "yes"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY2" "STATE_ZRRSIG" "rumoured"
# The old DS (KEY1) can be withdrawn and the new DS (KEY2) can be introduced.
set_keystate "KEY1" "STATE_DS" "unretentive"
set_keystate "KEY2" "STATE_DS" "rumoured"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
# Check that CDS publication is logged.
check_cdslog "$DIR" "$ZONE" KEY2

# Set expected key times:
# - This key was activated 186 days ago (16070400 seconds).
csk_rollover_predecessor_keytimes -16070400
# - The new CSK is published three hours ago, CDS must be published now.
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED" "${created}" "-${Ipub}"
set_keytime "KEY2" "SYNCPUBLISH" "${created}"
# - Also signatures are being introduced now.
set_keytime "KEY2" "ACTIVE" "${created}"
set_retired_removed "KEY2" "${Lcsk}" "${IretCSK}"

# Continue signing policy checks.
check_keytimes
check_apex
# Subdomain still has good signatures of old CSK (KEY1).
# Set expected zone signing on for KEY1 and off for KEY2,
# testing whether signatures which are still valid are being reused.
set_zonesigning "KEY1" "yes"
set_zonesigning "KEY2" "no"
check_subdomain
# Restore the expected zone signing properties.
set_zonesigning "KEY1" "no"
set_zonesigning "KEY2" "yes"
dnssec_verify

# We ignore any parent registration delay, so set the DS publish time to now.
rndc_checkds "$SERVER" "$DIR" KEY1 "now" "withdrawn" "$ZONE"
rndc_checkds "$SERVER" "$DIR" KEY2 "now" "published" "$ZONE"
# Next key event is when the predecessor ZRRSIG records have been replaced
# with that of the successor and enough time has passed such that the all
# validators that have such signed RRsets in cache only know about the
# successor signatures.  This is the retire interval: Dsgn plus the
# maximum zone TTL plus the zone propagation delay plus retire-safety. For the
# csk-roll2 policy that means: 12h (because 1d validity and refresh within
# 12 hours) + 1d + 1h + 1h = 38h = 136800 seconds.  Prevent intermittent false
# positives on slow platforms by subtracting the number of seconds which
# passed between key creation and invoking 'rndc dnssec -checkds'.
now="$(TZ=UTC date +%s)"
time_passed=$((now - start_time))
next_time=$((136800 - time_passed))
check_next_key_event $next_time

#
# Zone: step4.csk-roll2.autosign.
#
set_zone "step4.csk-roll2.autosign"
set_policy "csk-roll2" "2" "3600"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# The old CSK (KEY1) ZRRSIG is now HIDDEN.
set_keystate "KEY1" "STATE_ZRRSIG" "hidden"
# The new CSK (KEY2) ZRRSIG is now OMNIPRESENT.
set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - This key was activated 4502 hours ago (16207200 seconds).
csk_rollover_predecessor_keytimes -16207200
# - The new CSK was published 41 hours (147600 seconds) ago.
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED" "${created}" -147600
published=$(key_get KEY2 PUBLISHED)
set_addkeytime "KEY2" "SYNCPUBLISH" "${published}" "${Ipub}"
set_addkeytime "KEY2" "ACTIVE" "${published}" "${Ipub}"
set_retired_removed "KEY2" "${Lcsk}" "${IretCSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the predecessor DS has been replaced with the
# successor DS and enough time has passed such that the all validators that
# have this DS RRset cached only know about the successor DS.  This is the
# registration delay plus the retire interval, which is the parent
# propagation delay plus the DS TTL plus the retire-safety.  For the
# csk-roll2 policy this means: 1w + 1h + 1h = 170h = 612000 seconds.
# However, 136800 seconds have passed already, so 478800 seconds left.
check_next_key_event 475200

#
# Zone: step5.csk-roll2.autosign.
#
set_zone "step5.csk-roll2.autosign"
set_policy "csk-roll2" "2" "3600"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# The old CSK (KEY1) DNSKEY can be removed.
set_keysigning "KEY1" "no"
set_keystate "KEY1" "STATE_DNSKEY" "unretentive"
set_keystate "KEY1" "STATE_KRRSIG" "unretentive"
set_keystate "KEY1" "STATE_DS" "hidden"
# The new CSK (KEY2) is now fully OMNIPRESENT.
set_keystate "KEY2" "STATE_DS" "omnipresent"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - This key was activated 4634 hours ago (16682400 seconds).
csk_rollover_predecessor_keytimes -16682400
# - The new CSK was published 173 hours (622800 seconds) ago.
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED" "${created}" -622800
published=$(key_get KEY2 PUBLISHED)
set_addkeytime "KEY2" "SYNCPUBLISH" "${published}" "${Ipub}"
set_addkeytime "KEY2" "ACTIVE" "${published}" "${Ipub}"
set_retired_removed "KEY2" "${Lcsk}" "${IretCSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the DNSKEY enters the HIDDEN state.  This is the
# DNSKEY TTL plus zone propagation delay. For the csk-roll policy this is:
# 1h + 1h = 7200 seconds.
check_next_key_event 7200

#
# Zone: step6.csk-roll2.autosign.
#
set_zone "step6.csk-roll2.autosign"
set_policy "csk-roll2" "2" "3600"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# The old CSK (KEY1) is now completely HIDDEN.
set_keystate "KEY1" "STATE_DNSKEY" "hidden"
set_keystate "KEY1" "STATE_KRRSIG" "hidden"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# Set expected key times:
# - This key was activated 4636 hours ago (16689600 seconds).
csk_rollover_predecessor_keytimes -16689600
# - The new CSK was published 175 hours (630000 seconds) ago.
created=$(key_get KEY2 CREATED)
set_addkeytime "KEY2" "PUBLISHED" "${created}" -630000
published=$(key_get KEY2 PUBLISHED)
set_addkeytime "KEY2" "SYNCPUBLISH" "${published}" "${Ipub}"
set_addkeytime "KEY2" "ACTIVE" "${published}" "${Ipub}"
set_retired_removed "KEY2" "${Lcsk}" "${IretCSK}"

# Continue signing policy checks.
check_keytimes
check_apex
check_subdomain
dnssec_verify

# Next key event is when the new successor needs to be published.
# This is the Lcsk, minus time passed since the key was published.
# Lcsk:        186d (16070400 seconds)
# Time passed: 175h (630000 seconds)
check_next_key_event 15440400

#
# Zone: step7.csk-roll2.autosign.
#
set_zone "step7.csk-roll2.autosign"
set_policy "csk-roll2" "2" "3600"
CDS_SHA384="yes"
set_server "ns3" "10.53.0.3"
# The old CSK (KEY1) could have been purged, but purge-keys is disabled.

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

#
# Test #2375: Scheduled rollovers are happening faster than they can finish
#
set_zone "three-is-a-crowd.kasp"
set_policy "ksk-doubleksk" "3" "7200"
set_server "ns3" "10.53.0.3"
CDNSKEY="no"
# These are the same time values as calculated for ksk-doubleksk.
Lksk=5184000
Lzsk=31536000
IretKSK=180000
IretZSK=867600
# KSK (KEY1) is outgoing.
key_clear "KEY1"
set_keyrole "KEY1" "ksk"
set_keylifetime "KEY1" "${Lksk}"
set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
set_keystate "KEY1" "GOAL" "hidden"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "unretentive"
# KSK (KEY2) is incoming.
key_clear "KEY2"
set_keyrole "KEY2" "ksk"
set_keylifetime "KEY2" "${Lksk}"
set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY2" "yes"
set_zonesigning "KEY2" "no"
set_keystate "KEY2" "GOAL" "omnipresent"
set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY2" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY2" "STATE_DS" "rumoured"
# We will introduce the third KSK shortly.
key_clear "KEY3"
# ZSK (KEY4).
key_clear "KEY4"
set_keyrole "KEY4" "zsk"
set_keylifetime "KEY4" "${Lzsk}"
set_keyalgorithm "KEY4" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY4" "no"
set_zonesigning "KEY4" "yes"
set_keystate "KEY4" "GOAL" "omnipresent"
set_keystate "KEY4" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY4" "STATE_ZRRSIG" "omnipresent"
# Run preliminary tests.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify
# Roll over KEY2.
created=$(key_get KEY2 CREATED)
rndc_rollover "$SERVER" "$DIR" $(key_get KEY2 ID) "${created}" "$ZONE"
# Update expected number of keys and key states.
set_keystate "KEY2" "GOAL" "hidden"
set_policy "ksk-doubleksk" "4" "7200"
CDNSKEY="no"
# New KSK (KEY3) is introduced.
set_keyrole "KEY3" "ksk"
set_keylifetime "KEY3" "${Lksk}"
set_keyalgorithm "KEY3" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
set_keysigning "KEY3" "yes"
set_zonesigning "KEY3" "no"
set_keystate "KEY3" "GOAL" "omnipresent"
set_keystate "KEY3" "STATE_DNSKEY" "rumoured"
set_keystate "KEY3" "STATE_KRRSIG" "rumoured"
set_keystate "KEY3" "STATE_DS" "hidden"
# Run tests again. We now expect four keys (3x KSK, 1x ZSK).
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

# Test dynamic zones that switch to inline-signing.
set_zone "dynamic2inline.kasp"
set_policy "default" "1" "3600"
set_server "ns6" "10.53.0.6"
# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

# The CSK is rumoured.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_ZRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"
# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

# Test key lifetime changes
set_keytimes_lifetime_update() {
  if [ $1 -eq 0 ]; then
    set_keytime "KEY1" "RETIRED" "none"
    set_keytime "KEY1" "REMOVED" "none"
  else
    active=$(key_get KEY1 ACTIVE)
    set_addkeytime "KEY1" "RETIRED" "${active}" $1
    # The key is removed after the retire time plus max-zone-ttl (1d),
    # sign delay (9d), zone propagation delay (5m), retire safety (1h) =
    # 777600 + 86400 + 300 + 3600 = 867900
    retired=$(key_get KEY1 RETIRED)
    set_addkeytime "KEY1" "REMOVED" "${retired}" 867900
  fi
}

check_key_lifetime() {
  zone=$1
  policy=$2
  lifetime=$3

  set_zone "$zone"
  set_policy "$policy" "1" "3600"
  set_server "ns6" "10.53.0.6"
  # Key properties.
  key_clear "KEY1"
  set_keyrole "KEY1" "csk"
  set_keylifetime "KEY1" "$lifetime"
  set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
  set_keysigning "KEY1" "yes"
  set_zonesigning "KEY1" "yes"
  key_clear "KEY2"
  key_clear "KEY3"
  key_clear "KEY4"

  # The CSK is rumoured.
  set_keystate "KEY1" "GOAL" "omnipresent"
  set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
  set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
  set_keystate "KEY1" "STATE_ZRRSIG" "rumoured"
  set_keystate "KEY1" "STATE_DS" "hidden"
  check_keys

  # Key timings.
  set_keytimes_csk_policy
  set_keytimes_lifetime_update $lifetime

  # Variuous checks.
  check_keytimes
  check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
  check_apex
  check_subdomain
  dnssec_verify
}
check_key_lifetime "shorter-lifetime" "long-lifetime" "31536000"
check_key_lifetime "longer-lifetime" "short-lifetime" "16070400"
check_key_lifetime "limit-lifetime" "unlimited-lifetime" "0"
check_key_lifetime "unlimit-lifetime" "short-lifetime" "16070400"

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

#
# Testing going insecure.
#

#
# Zone step1.going-insecure.kasp
#
set_zone "step1.going-insecure.kasp"
set_policy "unsigning" "2" "7200"
set_server "ns6" "10.53.0.6"

# Policy parameters.
# Lksk:      0
# Lzsk:      60 days (5184000 seconds)
# Iret(KSK): DS TTL (1d) + DprpP (1h) + retire-safety (1h)
# Iret(KSK): 1d2h (93600 seconds)
# Iret(ZSK): RRSIG TTL (1d) + Dprp (5m) + Dsgn (9d) + retire-safety (1h)
# Iret(ZSK): 10d1h5m (867900 seconds)
Lksk=0
Lzsk=5184000
IretKSK=93600
IretZSK=867900

init_migration_insecure() {
  key_clear "KEY1"
  set_keyrole "KEY1" "ksk"
  set_keylifetime "KEY1" "${Lksk}"
  set_keyalgorithm "KEY1" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
  set_keysigning "KEY1" "yes"
  set_zonesigning "KEY1" "no"

  set_keystate "KEY1" "GOAL" "omnipresent"
  set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
  set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
  set_keystate "KEY1" "STATE_DS" "omnipresent"

  key_clear "KEY2"
  set_keyrole "KEY2" "zsk"
  set_keylifetime "KEY2" "${Lzsk}"
  set_keyalgorithm "KEY2" "$DEFAULT_ALGORITHM_NUMBER" "$DEFAULT_ALGORITHM" "$DEFAULT_BITS"
  set_keysigning "KEY2" "no"
  set_zonesigning "KEY2" "yes"

  set_keystate "KEY2" "GOAL" "omnipresent"
  set_keystate "KEY2" "STATE_DNSKEY" "omnipresent"
  set_keystate "KEY2" "STATE_ZRRSIG" "omnipresent"

  key_clear "KEY3"
  key_clear "KEY4"
}
init_migration_insecure

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# We have set the timing metadata to now - 10 days (864000 seconds).
rollover_predecessor_keytimes -864000
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone step1.going-insecure-dynamic.kasp
#

set_zone "step1.going-insecure-dynamic.kasp"
set_dynamic
set_policy "unsigning" "2" "7200"
set_server "ns6" "10.53.0.6"
init_migration_insecure

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# We have set the timing metadata to now - 10 days (864000 seconds).
rollover_predecessor_keytimes -864000
check_keytimes
check_apex
check_subdomain
dnssec_verify

#
# Zone step1.going-straight-to-none.kasp
#
set_zone "step1.going-straight-to-none.kasp"
set_policy "default" "1" "3600"
set_server "ns6" "10.53.0.6"
# Key properties.
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
# DNSKEY, RRSIG (ksk), RRSIG (zsk) are published. DS needs to wait.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_ZRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"
# This policy only has one key.
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# The first key is immediately published and activated.
created=$(key_get KEY1 CREATED)
set_keytime "KEY1" "PUBLISHED" "${created}"
set_keytime "KEY1" "ACTIVE" "${created}"
set_keytime "KEY1" "SYNCPUBLISH" "${created}"
# Key lifetime is unlimited, so not setting RETIRED and REMOVED.
check_keytimes

check_apex
check_subdomain
dnssec_verify

#
# Zone step1.going-straight-to-none-dynamic.kasp
#
set_zone "step1.going-straight-to-none-dynamic.kasp"
set_policy "default" "1" "3600"
set_server "ns6" "10.53.0.6"
# Key properties.
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
# DNSKEY, RRSIG (ksk), RRSIG (zsk) are published. DS needs to wait.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_ZRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"
# This policy only has one key.
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"

# The first key is immediately published and activated.
created=$(key_get KEY1 CREATED)
set_keytime "KEY1" "PUBLISHED" "${created}"
set_keytime "KEY1" "ACTIVE" "${created}"
set_keytime "KEY1" "SYNCPUBLISH" "${created}"
# Key lifetime is unlimited, so not setting RETIRED and REMOVED.
check_keytimes

check_apex
check_subdomain
dnssec_verify

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

# Test dynamic zones that switch to inline-signing.
set_zone "dynamic2inline.kasp"
set_policy "default" "1" "3600"
set_server "ns6" "10.53.0.6"
# Key properties.
key_clear "KEY1"
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

# The CSK is rumoured.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "rumoured"
set_keystate "KEY1" "STATE_KRRSIG" "rumoured"
set_keystate "KEY1" "STATE_ZRRSIG" "rumoured"
set_keystate "KEY1" "STATE_DS" "hidden"
# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

# Test key lifetime updates.
check_key_lifetime "shorter-lifetime" "short-lifetime" "16070400"
check_key_lifetime "longer-lifetime" "long-lifetime" "31536000"
check_key_lifetime "limit-lifetime" "short-lifetime" "16070400"
check_key_lifetime "unlimit-lifetime" "unlimited-lifetime" "0"

#
# Testing going insecure.
#

#
# Zone: step1.going-insecure.kasp
#
set_zone "step1.going-insecure.kasp"
set_policy "insecure" "2" "3600"
set_server "ns6" "10.53.0.6"
# Expect a CDS/CDNSKEY Delete Record.
set_cdsdelete

# Key goal states should be HIDDEN.
init_migration_insecure
set_keystate "KEY1" "GOAL" "hidden"
set_keystate "KEY2" "GOAL" "hidden"
# The DS may be removed if we are going insecure.
set_keystate "KEY1" "STATE_DS" "unretentive"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

# Tell named that the DS has been removed.
rndc_checkds "$SERVER" "$DIR" "KEY1" "now" "withdrawn" "$ZONE"
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

# Next key event is when the DS becomes HIDDEN. This happens after the
# parent propagation delay, and DS TTL:
# 1h + 1d = 25h = 90000 seconds.
check_next_key_event 90000

#
# Zone: step2.going-insecure.kasp
#
set_zone "step2.going-insecure.kasp"
set_policy "insecure" "2" "3600"
set_server "ns6" "10.53.0.6"

# The DS is long enough removed from the zone to be considered HIDDEN.
# This means the DNSKEY and the KSK signatures can be removed.
set_keystate "KEY1" "STATE_DS" "hidden"
set_keystate "KEY1" "STATE_DNSKEY" "unretentive"
set_keystate "KEY1" "STATE_KRRSIG" "unretentive"
set_keysigning "KEY1" "no"

set_keystate "KEY2" "STATE_DNSKEY" "unretentive"
set_keystate "KEY2" "STATE_ZRRSIG" "unretentive"
set_zonesigning "KEY2" "no"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain

# Next key event is when the DNSKEY becomes HIDDEN. This happens after the
# propagation delay, plus DNSKEY TTL:
# 5m + 2h = 125m =  7500 seconds.
check_next_key_event 7500

#
# Zone: step1.going-insecure-dynamic.kasp
#
set_zone "step1.going-insecure-dynamic.kasp"
set_dynamic
set_policy "insecure" "2" "3600"
set_server "ns6" "10.53.0.6"
# Expect a CDS/CDNSKEY Delete Record.
set_cdsdelete

# Key goal states should be HIDDEN.
init_migration_insecure
set_keystate "KEY1" "GOAL" "hidden"
set_keystate "KEY2" "GOAL" "hidden"
# The DS may be removed if we are going insecure.
set_keystate "KEY1" "STATE_DS" "unretentive"

# Various signing policy checks.
check_keys
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

# Tell named that the DS has been removed.
rndc_checkds "$SERVER" "$DIR" "KEY1" "now" "withdrawn" "$ZONE"
wait_for_done_signing
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain
dnssec_verify

# Next key event is when the DS becomes HIDDEN. This happens after the
# parent propagation delay, retire safety delay, and DS TTL:
# 1h + 1d = 25h = 90000 seconds.
check_next_key_event 90000

#
# Zone: step2.going-insecure-dynamic.kasp
#
set_zone "step2.going-insecure-dynamic.kasp"
set_dynamic
set_policy "insecure" "2" "3600"
set_server "ns6" "10.53.0.6"

# The DS is long enough removed from the zone to be considered HIDDEN.
# This means the DNSKEY and the KSK signatures can be removed.
set_keystate "KEY1" "STATE_DS" "hidden"
set_keystate "KEY1" "STATE_DNSKEY" "unretentive"
set_keystate "KEY1" "STATE_KRRSIG" "unretentive"
set_keysigning "KEY1" "no"

set_keystate "KEY2" "STATE_DNSKEY" "unretentive"
set_keystate "KEY2" "STATE_ZRRSIG" "unretentive"
set_zonesigning "KEY2" "no"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
check_apex
check_subdomain

# Next key event is when the DNSKEY becomes HIDDEN. This happens after the
# propagation delay, plus DNSKEY TTL:
# 5m + 2h = 125m =  7500 seconds.
check_next_key_event 7500

#
# Zone: step1.going-straight-to-none.kasp
#
set_zone "step1.going-straight-to-none.kasp"
set_policy "none" "1" "3600"
set_server "ns6" "10.53.0.6"

# The zone will go bogus after signatures expire, but remains validly signed for now.

# Key properties.
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
# DNSKEY, RRSIG (ksk), RRSIG (zsk) are published. DS needs to wait.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_ZRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"
# This policy only has one key.
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
dnssec_verify

#
# Zone: step1.going-straight-to-none-dynamic.kasp
#
set_zone "step1.going-straight-to-none-dynamic.kasp"
set_policy "none" "1" "3600"
set_server "ns6" "10.53.0.6"

# The zone will go bogus after signatures expire, but remains validly signed for now.

# Key properties.
set_keyrole "KEY1" "csk"
set_keylifetime "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning "KEY1" "yes"
set_zonesigning "KEY1" "yes"
# DNSKEY, RRSIG (ksk), RRSIG (zsk) are published. DS needs to wait.
set_keystate "KEY1" "GOAL" "omnipresent"
set_keystate "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_ZRRSIG" "omnipresent"
set_keystate "KEY1" "STATE_DS" "omnipresent"
# This policy only has one key.
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

# Various signing policy checks.
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
dnssec_verify

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

_check_soa_ttl() {
  dig_with_opts @10.53.0.6 example SOA >dig.out.ns6.test$n.soa2 || return 1
  soa1=$(awk '$4 == "SOA" { print $7 }' dig.out.ns6.test$n.soa1)
  soa2=$(awk '$4 == "SOA" { print $7 }' dig.out.ns6.test$n.soa2)
  ttl1=$(awk '$4 == "SOA" { print $2 }' dig.out.ns6.test$n.soa1)
  ttl2=$(awk '$4 == "SOA" { print $2 }' dig.out.ns6.test$n.soa2)
  test ${soa1:-1000} -lt ${soa2:-0} || return 1
  test ${ttl1:-0} -eq $1 || return 1
  test ${ttl2:-0} -eq $2 || return 1
}

n=$((n + 1))
echo_i "Check that 'rndc reload' of just the serial updates the signed instance ($n)"
TSIG=
ret=0
dig_with_opts @10.53.0.6 example SOA >dig.out.ns6.test$n.soa1 || ret=1
cp ns6/example2.db.in ns6/example.db || ret=1
nextpart ns6/named.run >/dev/null
rndccmd 10.53.0.6 reload || ret=1
wait_for_log 3 "all zones loaded" ns6/named.run || ret=1
# Check that the SOA SERIAL increases and check the TTLs (should be 300 as
# defined in ns6/example2.db.in).
retry_quiet 10 _check_soa_ttl 300 300 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "Check that restart with zone changes and deleted journal works ($n)"
TSIG=
ret=0
dig_with_opts @10.53.0.6 example SOA >dig.out.ns6.test$n.soa1 || ret=1
stop_server --use-rndc --port ${CONTROLPORT} ns6
# TTL of all records change from 300 to 400
cp ns6/example3.db.in ns6/example.db || ret=1
rm ns6/example.db.jnl
nextpart ns6/named.run >/dev/null
start_server --noclean --restart --port ${PORT} ns6
wait_for_log 3 "all zones loaded" ns6/named.run || ret=1
# Check that the SOA SERIAL increases and check the TTLs (should be changed
# from 300 to 400 as defined in ns6/example3.db.in).
retry_quiet 10 _check_soa_ttl 300 400 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
