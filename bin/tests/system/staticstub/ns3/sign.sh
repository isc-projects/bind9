#!/bin/sh 
#
# Copyright (C) 2010, 2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

zone=example.
infile=example.db.in
zonefile=example.db

(cd ../ns4 && $SHELL -e sign.sh )

cp ../ns4/dsset-sub.example$TP .

keyname1=`$KEYGEN -q -r $RANDFILE -a RSASHA256 -b 1024 -n zone $zone`
keyname2=`$KEYGEN -q -r $RANDFILE -a RSASHA256 -b 2048 -f KSK -n zone $zone`
cat $infile $keyname1.key $keyname2.key > $zonefile

$SIGNER -g -r $RANDFILE -o $zone $zonefile > /dev/null 2>&1

# Configure the resolving server with a trusted key.

cat $keyname2.key | grep -v '^; ' | $PERL -n -e '
local ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
local $key = join("", @rest);
print <<EOF
trusted-keys {
    "$dn" $flags $proto $alg "$key";
};
EOF
' > trusted.conf

zone=undelegated
infile=undelegated.db.in
zonefile=undelegated.db
keyname1=`$KEYGEN -q -r $RANDFILE -a RSASHA256 -b 1024 -n zone $zone`
keyname2=`$KEYGEN -q -r $RANDFILE -a RSASHA256 -b 2048 -f KSK -n zone $zone`
cat $infile $keyname1.key $keyname2.key > $zonefile

$SIGNER -g -r $RANDFILE -o $zone $zonefile > /dev/null 2>&1

cat $keyname2.key | grep -v '^; ' | $PERL -n -e '
local ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
local $key = join("", @rest);
print <<EOF
trusted-keys {
    "$dn" $flags $proto $alg "$key";
};
EOF
' >> trusted.conf

cp trusted.conf ../ns2/trusted.conf
