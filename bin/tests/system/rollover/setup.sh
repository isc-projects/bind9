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

# Make lines shorter by storing key states in environment variables.
H="HIDDEN"
R="RUMOURED"
O="OMNIPRESENT"
U="UNRETENTIVE"

# Zone to test manual rollover.
setup manual-rollover.kasp
T="now-7d"
keytimes="-P $T -A $T"
KSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 -f KSK $keytimes $zone 2>keygen.out.$zone.1)
ZSK=$($KEYGEN -a $DEFAULT_ALGORITHM -L 3600 $keytimes $zone 2>keygen.out.$zone.2)
$SETTIME -s -g $O -d $O $T -k $O $T -r $O $T "$KSK" >settime.out.$zone.1 2>&1
$SETTIME -s -g $O -k $O $T -z $O $T "$ZSK" >settime.out.$zone.2 2>&1
cat template.db.in "${KSK}.key" "${ZSK}.key" >"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$KSK" >>"$infile"
private_type_record $zone $DEFAULT_ALGORITHM_NUMBER "$ZSK" >>"$infile"
cp $infile $zonefile
$SIGNER -PS -x -o $zone -O raw -f "${zonefile}.signed" $infile >signer.out.$zone.1 2>&1
