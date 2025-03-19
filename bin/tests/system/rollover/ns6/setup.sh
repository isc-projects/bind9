#!/bin/sh -e

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
. ../../conf.sh

echo_i "ns6/setup.sh"

setup() {
  zone="$1"
  echo_i "setting up zone: $zone"
  zonefile="${zone}.db"
  infile="${zone}.db.infile"
}

# Make lines shorter by storing key states in environment variables.
H="HIDDEN"
R="RUMOURED"
O="OMNIPRESENT"
U="UNRETENTIVE"

for zn in dynamic2inline.kasp shorter-lifetime longer-lifetime limit-lifetime \
  unlimit-lifetime; do
  setup $zn
  cp template.db.in $zonefile
done

# The child zones (step1, step2) beneath these zones represent the various
# steps of unsigning a zone.
for zn in going-insecure.kasp going-insecure-dynamic.kasp; do
  # Step 1:
  # Set up a zone with dnssec-policy that is going insecure.
  setup step1.$zn
  echo "$zone" >>zones
  T="now-10d"
  S="now-12955mi"
  keytimes="-P $T -A $T"
  cdstimes="-P sync $S"
  KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $keytimes $cdstimes $zone 2>keygen.out.$zone.1)
  ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 $keytimes $zone 2>keygen.out.$zone.2)
  cat template.db.in "${KSK}.key" "${ZSK}.key" >"$infile"
  private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK" >>"$infile"
  private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK" >>"$infile"
  cp $infile $zonefile
  $SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

  # Step 2:
  # Set up a zone with dnssec-policy that is going insecure. Don't add
  # this zone to the zones file, because this zone is no longer expected
  # to be fully signed.
  setup step2.$zn
  # The DS was withdrawn from the parent zone 26 hours ago.
  D="now-26h"
  keytimes="-P $T -A $T -I $D -D now"
  cdstimes="-P sync $S -D sync $D"
  KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $keytimes $cdstimes $zone 2>keygen.out.$zone.1)
  ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 $keytimes $zone 2>keygen.out.$zone.2)
  $SETTIME -s -g $H -k $O $T -r $O $T -d $U $D -D ds $D "$KSK" >settime.out.$zone.1 2>&1
  $SETTIME -s -g $H -k $O $T -z $O $T "$ZSK" >settime.out.$zone.2 2>&1
  # Fake lifetime of old algorithm keys.
  echo "Lifetime: 0" >>"${KSK}.state"
  echo "Lifetime: 5184000" >>"${ZSK}.state"
  cat template.db.in "${KSK}.key" "${ZSK}.key" >"$infile"
  private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK" >>"$infile"
  private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK" >>"$infile"
  cp $infile $zonefile
  $SIGNER -S -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1
done

# These zones are going straight to "none" policy. This is undefined behavior.
T="now-10d"
S="now-12955mi"
csktimes="-P $T -A $T -P sync $S"

setup step1.going-straight-to-none.kasp
echo "$zone" >>zones
CSK=$($KEYGEN -k default $csktimes $zone 2>keygen.out.$zone.1)
$SETTIME -s -g $O -k $O $TactN -z $O $TactN -r $O $TactN -d $O $TactN "$CSK" >settime.out.$zone.1 2>&1
cat template.db.in "${CSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

setup step1.going-straight-to-none-dynamic.kasp
echo "$zone" >>zones
CSK=$($KEYGEN -k default $csktimes $zone 2>keygen.out.$zone.1)
$SETTIME -s -g $O -k $O $TactN -z $O $TactN -r $O $TactN -d $O $TactN "$CSK" >settime.out.$zone.1 2>&1
cat template.db.in "${CSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -s now-1h -e now+2w -o $zone -O full -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1
