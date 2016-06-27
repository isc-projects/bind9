#!/bin/sh -e
#
# Copyright (C) 2013, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: sign.sh,v 1.43 2011/11/04 05:36:28 each Exp $

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

zone=optout-tld
infile=optout-tld.db.in
zonefile=optout-tld.db

keyname=`$KEYGEN -q -r $RANDFILE -a RSASHA256 -b 768 -n zone $zone`

cat $infile $keyname.key >$zonefile

$SIGNER -P -3 - -A -r $RANDFILE -o $zone $zonefile > /dev/null 2>&1
