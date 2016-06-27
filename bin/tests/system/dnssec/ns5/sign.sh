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
infile=../ns1/root.db.in
zonefile=root.db.signed

keyname=`$KEYGEN -r $RANDFILE -qfk $zone`

# copy the KSK out first, then revoke it
cat $keyname.key | grep -v '^; ' | $PERL -n -e '
local ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
local $key = join("", @rest);
print <<EOF
managed-keys {
    "$dn" initial-key $flags $proto $alg "$key";
};
EOF
' > revoked.conf

$SETTIME -R now ${keyname}.key > /dev/null

# create a current set of keys, and sign the root zone
$KEYGEN -r $RANDFILE -q $zone > /dev/null
$KEYGEN -r $RANDFILE -qfk $zone > /dev/null
$SIGNER -S -r $RANDFILE -o $zone -f $zonefile $infile > /dev/null 2>&1
