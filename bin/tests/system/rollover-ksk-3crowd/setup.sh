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

cd "ns3"

setup() {
  zone="$1"
  echo_i "setting up zone: $zone"
  zonefile="${zone}.db"
  infile="${zone}.db.infile"
  echo "$zone" >>zones
}

# Set in the key state files the Predecessor/Successor fields.
# Key $1 is the predecessor of key $2.
key_successor() {
  id1=$(keyfile_to_key_id "$1")
  id2=$(keyfile_to_key_id "$2")
  echo "Predecessor: ${id1}" >>"${2}.state"
  echo "Successor: ${id2}" >>"${1}.state"
}

# Make lines shorter by storing key states in environment variables.
H="HIDDEN"
R="RUMOURED"
O="OMNIPRESENT"
U="UNRETENTIVE"

# Test #2375, the "three is a crowd" bug, where a new key is introduced but the
# previous rollover has not finished yet. In other words, we have a key KEY2
# that is the successor of key KEY1, and we introduce a new key KEY3 that is
# the successor of key KEY2:
#
#     KEY1 < KEY2 < KEY3.
#
# The expected behavior is that all three keys remain in the zone, and not
# the bug behavior where KEY2 is removed and immediately replaced with KEY3.
#
# Set up a zone that has a KSK (KEY1) and have the successor key (KEY2)
# published as well.
setup three-is-a-crowd.kasp
# These times are the same as step3.ksk-doubleksk.autosign.
TpubN="now-60d"
TactN="now-1413h"
TretN="now"
TremN="now+50h"
TpubN1="now-27h"
TsbmN1="now"
TactN1="${TretN}"
TretN1="now+60d"
TremN1="now+1490h"
ksktimes="-P ${TpubN}  -A ${TpubN}  -P sync ${TactN}  -I ${TretN}  -D ${TremN} -D sync ${TactN1}"
newtimes="-P ${TpubN1} -A ${TactN1} -P sync ${TsbmN1} -I ${TretN1} -D ${TremN1}"
zsktimes="-P ${TpubN}  -A ${TpubN}"
KSK1=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $ksktimes $zone 2>keygen.out.$zone.1)
KSK2=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 -f KSK $newtimes $zone 2>keygen.out.$zone.2)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 7200 $zsktimes $zone 2>keygen.out.$zone.3)
$SETTIME -s -g $H -k $O $TactN -r $O $TactN -d $O $TactN "$KSK1" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $R $TpubN1 -r $R $TpubN1 -d $H $TpubN1 "$KSK2" >settime.out.$zone.2 2>&1
$SETTIME -s -g $O -k $O $TactN -z $O $TactN "$ZSK" >settime.out.$zone.3 2>&1
# Set key rollover relationship.
key_successor $KSK1 $KSK2
# Sign zone.
cat template.db.in "${KSK1}.key" "${KSK2}.key" "${ZSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK1" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK2" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK" >>"$infile"
cp $infile $zonefile
$SIGNER -S -x -G "cds:sha-256" -s now-1h -e now+2w -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1
