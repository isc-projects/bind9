#!/bin/sh -e
#
# Copyright (C) 2000-2004, 2006-2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

zone=.
infile=root.db.in
zonefile=root.db

(cd ../ns2 && $SHELL sign.sh )
(cd ../ns6 && $SHELL sign.sh )
(cd ../ns7 && $SHELL sign.sh )

cp ../ns2/dsset-example$TP .
cp ../ns2/dsset-dlv$TP .
cp ../ns2/dsset-in-addr.arpa$TP .

grep "8 [12] " ../ns2/dsset-algroll$TP > dsset-algroll$TP
cp ../ns6/dsset-optout-tld$TP .

keyname=`$KEYGEN -q -r $RANDFILE -a RSAMD5 -b 768 -n zone $zone`

cat $infile $keyname.key > $zonefile

$SIGNER -P -g -r $RANDFILE -o $zone $zonefile > /dev/null

# Configure the resolving server with a trusted key.
cat $keyname.key | grep -v '^; ' | $PERL -n -e '
local ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
local $key = join("", @rest);
print <<EOF
trusted-keys {
    "$dn" $flags $proto $alg "$key";
};
EOF
' > trusted.conf

# ...or with a managed key.
cat $keyname.key | grep -v '^; ' | $PERL -n -e '
local ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
local $key = join("", @rest);
print <<EOF
managed-keys {
    "$dn" initial-key $flags $proto $alg "$key";
};
EOF
' > managed.conf
cp trusted.conf ../ns2/trusted.conf
cp trusted.conf ../ns3/trusted.conf
cp trusted.conf ../ns4/trusted.conf
cp trusted.conf ../ns6/trusted.conf
cp trusted.conf ../ns7/trusted.conf
cp managed.conf ../ns4/managed.conf
#
#  Save keyid for managed key id test.
#
keyid=`expr $keyname : 'K.+001+\(.*\)'`
keyid=`expr $keyid + 0`
echo "$keyid" > managed.key.id
