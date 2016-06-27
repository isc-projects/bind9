#!/bin/sh
#
# Copyright (C) 2011, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

(cd ../ns3 && $SHELL -e ./sign.sh || exit 1)

echo "I:dlv/ns2/sign.sh"

zone=druz.
infile=druz.db.in
zonefile=druz.db
outfile=druz.pre
dlvzone=utld.

keyname1=`$KEYGEN -r $RANDFILE -a DSA -b 768 -n zone $zone 2> /dev/null` 
keyname2=`$KEYGEN -f KSK -r $RANDFILE -a DSA -b 768 -n zone $zone 2> /dev/null`

cat $infile $keyname1.key $keyname2.key >$zonefile

$SIGNER -r $RANDFILE -l $dlvzone -g -o $zone -f $outfile $zonefile > /dev/null 2> signer.err || cat signer.err

$CHECKZONE -q -D -i none druz druz.pre |
sed '/IN DNSKEY/s/\([a-z0-9A-Z/]\{10\}\)[a-z0-9A-Z/]\{16\}/\1XXXXXXXXXXXXXXXX/'> druz.signed

echo "I: signed $zone"
