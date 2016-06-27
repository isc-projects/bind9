#!/bin/sh -e
#
# Copyright (C) 2011, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

zone=dlv.isc.org
infile=dlv.isc.org.db.in
zonefile=dlv.isc.org.db

dlvkey=`$KEYGEN -q -r $RANDFILE -a RSAMD5 -b 768 -n zone $zone`
cat $infile $dlvkey.key > $zonefile
$SIGNER -P -g -r $RANDFILE -o $zone $zonefile > /dev/null

zone=.
infile=root.db.in
zonefile=root.db

rootkey=`$KEYGEN -q -r $RANDFILE -a RSAMD5 -b 768 -n zone $zone`
cat $infile $rootkey.key > $zonefile
$SIGNER -P -g -r $RANDFILE -o $zone $zonefile > /dev/null

# Create bind.keys file for the use of the resolving server
echo "managed-keys {" > bind.keys
cat $dlvkey.key | grep -v '^; ' | $PERL -n -e '
local ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
local $key = join("", @rest);
print <<EOF
    "$dn" initial-key $flags $proto $alg "$key";
EOF
' >>  bind.keys
cat $rootkey.key | grep -v '^; ' | $PERL -n -e '
local ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
local $key = join("", @rest);
print <<EOF
    "$dn" initial-key $flags $proto $alg "$key";
EOF
' >>  bind.keys
echo "};" >> bind.keys
