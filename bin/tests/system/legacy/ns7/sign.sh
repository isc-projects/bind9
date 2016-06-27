#!/bin/sh
#
# Copyright (C) 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

echo "I:sign edns512-notcp"

zone=edns512-notcp
infile=edns512-notcp.db.in
zonefile=edns512-notcp.db
outfile=edns512-notcp.db.signed

keyname1=`$KEYGEN -r $RANDFILE -a RSASHA512 -b 4096 -n zone $zone 2> /dev/null` 
keyname2=`$KEYGEN -f KSK -r $RANDFILE -a RSASHA512 -b 4096 -n zone $zone 2> /dev/null`

cat $infile $keyname1.key $keyname2.key >$zonefile

$SIGNER -r $RANDFILE -g -o $zone -f $outfile -e +30y $zonefile > /dev/null 2> signer.err || cat signer.err

grep -v '^;' $keyname2.key | $PERL -n -e '
local ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
local $key = join("", @rest);
print <<EOF
trusted-keys {
    "$dn" $flags $proto $alg "$key";
};
EOF
' > trusted.conf
cp trusted.conf ../ns1
