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

set -e

zone=.
infile=root.db.in
zonefile=root.db

echo_i "ns1/setup.sh"

for tld in multisigner update-any bad-dsync secondary; do
  cp "../ns2/dsset-${tld}." .
done

KSK=$($KEYGEN -q -fk -a $DEFAULT_ALGORITHM -b $DEFAULT_BITS $zone)
ZSK=$($KEYGEN -q -a $DEFAULT_ALGORITHM -b $DEFAULT_BITS $zone)

cat $infile $KSK.key $ZSK.key >$zonefile

$SIGNER -g -o $zone $zonefile >/dev/null 2>&1

# Configure the resolving server with a static key.
keyfile_to_static_ds "$KSK" >trusted.conf
cp trusted.conf ../ns2/trusted.conf
cp trusted.conf ../ns3/trusted.conf
cp trusted.conf ../ns4/trusted.conf
cp trusted.conf ../ns5/trusted.conf
