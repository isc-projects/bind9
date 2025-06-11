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

# Multi-signer zones.
setup "multisigner-model2.kasp"
cp template.db.in "$zonefile"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -f KSK -L 3600 -M 32768:65535 $zone 2>keygen.out.$zone.1)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -M 32768:65535 $zone 2>keygen.out.$zone.2)
cat "${KSK}.key" | grep -v ";.*" >>"${zone}.db"
cat "${ZSK}.key" | grep -v ";.*" >>"${zone}.db"
# Import a ZSK of another provider into the DNSKEY RRset.
ZSK1=$($KEYGEN -K ../ -a $DEFAULT_ALGORITHM -L 3600 -M 0:32767 $zone 2>keygen.out.$zone.3)
cat "../${ZSK1}.key" | grep -v ";.*" >>"${zone}.db"

# We are changing an existing single-signed zone to multi-signed
# zone where the key tags do not match the dnssec-policy key tag range
setup single-to-multisigner.kasp
T="now-7d"
S="now-8635mi" # T - 1d5m
keytimes="-P $T -A $T"
cdstimes="-P sync $S"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -M 0:32767 -L 3600 -f KSK $keytimes $cdstimes $zone 2>keygen.out.$zone.1)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -M 0:32767 -L 3600 $keytimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $O -d $O $T -k $O $T -r $O $T "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $T -z $O $T "$ZSK" >settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" >"$infile"
$SIGNER -PS -z -x -s now-2w -e now-1mi -o $zone -f "${zonefile}" $infile >signer.out.$zone.1 2>&1
echo "Lifetime: 0" >>"${KSK}".state
echo "Lifetime: 0" >>"${ZSK}".state
