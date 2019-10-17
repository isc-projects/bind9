#!/bin/sh -e
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
. "$SYSTEMTESTTOP/conf.sh"

echo_i "ns3/setup.sh"

setup() {
	zone="$1"
	echo_i "setting up zone: $zone"
	zonefile="${zone}.db"
	infile="${zone}.db.infile"
	echo $zone >> zones
}

#
# Set up zones that will be initially signed.
#
for zn in default rsasha1 dnssec-keygen some-keys legacy-keys pregenerated \
	  rsasha1-nsec3 rsasha256 rsasha512 ecdsa256 ecdsa384
do
	setup "${zn}.kasp"
	cp template.db.in $zonefile
done

# Some of these zones already have keys.
zone="dnssec-keygen.kasp"
$KEYGEN -k rsasha1 -l policies/kasp.conf $zone > keygen.out.$zone.1 2>&1

zone="some-keys.kasp"
$KEYGEN -P none -A none -a RSASHA1 -b 2000 -L 1234 $zone > keygen.out.$zone.1 2>&1
$KEYGEN -P none -A none -a RSASHA1 -f KSK  -L 1234 $zone > keygen.out.$zone.2 2>&1

zone="legacy.kasp"
$KEYGEN -a RSASHA1 -b 2000 -L 1234 $zone > keygen.out.$zone.1 2>&1
$KEYGEN -a RSASHA1 -f KSK  -L 1234 $zone > keygen.out.$zone.2 2>&1

zone="pregenerated.kasp"
$KEYGEN -k rsasha1 -l policies/kasp.conf $zone > keygen.out.$zone.1 2>&1
$KEYGEN -k rsasha1 -l policies/kasp.conf $zone > keygen.out.$zone.2 2>&1

