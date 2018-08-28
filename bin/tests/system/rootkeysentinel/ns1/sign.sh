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

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

zone=.
infile=root.db.in
zonefile=root.db

keyalgn=$(printf "%03u" "$ALGON")
keyname=`$KEYGEN -q -a $ALGO -b $BITS -n zone $zone`
keyid=`expr ${keyname} : 'K.+'${keyalgn}'+\(.*\)'`

(cd ../ns2 && $SHELL sign.sh ${keyid:-00000} )

cp ../ns2/dsset-example$TP .

cat $infile $keyname.key > $zonefile

$SIGNER -P -g -o $zone $zonefile > /dev/null

# Configure the resolving server with a trusted key.
keyfile_to_trusted_keys $keyname > trusted.conf
cp trusted.conf ../ns2/trusted.conf
cp trusted.conf ../ns3/trusted.conf
cp trusted.conf ../ns4/trusted.conf
