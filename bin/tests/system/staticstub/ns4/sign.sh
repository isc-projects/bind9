#!/bin/sh -e
#
# Copyright (C) 2010, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: sign.sh,v 1.3 2010/12/17 00:57:39 marka Exp $

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

zone=sub.example
infile=${zone}.db.in
zonefile=${zone}.db

keyname1=`$KEYGEN -q -r $RANDFILE -a NSEC3RSASHA1 -b 768 -n zone $zone`
keyname2=`$KEYGEN -q -r $RANDFILE -a NSEC3RSASHA1 -b 1024 -f KSK -n zone $zone`

cat $infile $keyname1.key $keyname2.key > $zonefile

$SIGNER -r $RANDFILE -o $zone $zonefile > /dev/null 2>&1
