#!/bin/sh -e
#
# Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

zone=.
zonefile=root.db

keyname=`$KEYGEN -qfk -r $RANDFILE $zone`
zskkeyname=`$KEYGEN -q -r $RANDFILE $zone`

$SIGNER -Sg -r $RANDFILE -o $zone $zonefile > /dev/null 2>&-

# Configure the resolving server with a managed trusted key.
cat $keyname.key | grep -v '^; ' | $PERL -n -e '
local ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
local $key = join("", @rest);
print <<EOF
managed-keys {
    "$dn" initial-key $flags $proto $alg "$key";
};
EOF
' > managed.conf
cp managed.conf ../ns2/managed.conf

# Configure a trusted key statement (used by delve)
cat $keyname.key | grep -v '^; ' | $PERL -n -e '
local ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
local $key = join("", @rest);
print <<EOF
trusted-keys {
    "$dn" $flags $proto $alg "$key";
};
EOF
' > trusted.conf

#
#  Save keyname and keyid for managed key id test.
#
echo "$keyname" > managed.key
keyid=`expr $keyname : 'K\.+00.+\([0-9]*\)'`
keyid=`expr $keyid + 0`
echo "$keyid" > managed.key.id
