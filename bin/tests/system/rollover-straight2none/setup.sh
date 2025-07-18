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
. ../conf.sh

cd "ns6"

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

# These zones are going straight to "none" policy. This is undefined behavior.
T="now-10d"
S="now-12955mi"
csktimes="-P $T -A $T -P sync $S"

setup going-straight-to-none.kasp
echo "$zone" >>zones
CSK=$($KEYGEN -k default $csktimes $zone 2>keygen.out.$zone.1)
$SETTIME -s -g $O -k $O $TactN -z $O $TactN -r $O $TactN -d $O $TactN "$CSK" >settime.out.$zone.1 2>&1
cat template.db.in "${CSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1

setup going-straight-to-none-dynamic.kasp
echo "$zone" >>zones
CSK=$($KEYGEN -k default $csktimes $zone 2>keygen.out.$zone.1)
$SETTIME -s -g $O -k $O $TactN -z $O $TactN -r $O $TactN -d $O $TactN "$CSK" >settime.out.$zone.1 2>&1
cat template.db.in "${CSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$CSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -z -x -s now-1h -e now+2w -o $zone -O full -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1
