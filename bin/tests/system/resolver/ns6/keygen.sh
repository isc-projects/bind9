#!/bin/sh -e
#
# Copyright (C) 2010, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: keygen.sh,v 1.2 2010/11/16 06:46:44 marka Exp $

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

zone=example.net
zonefile="${zone}.db"
infile="${zonefile}.in"
cp $infile $zonefile
ksk=`$KEYGEN -q -3 -r $RANDFILE -fk $zone`
zsk=`$KEYGEN -q -3 -r $RANDFILE $zone`
cat $ksk.key $zsk.key >> $zonefile
$SIGNER -P -r $RANDFILE -o $zone $zonefile > /dev/null 2>&1
