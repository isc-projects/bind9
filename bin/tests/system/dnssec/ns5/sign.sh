#!/bin/sh -e
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

zone=.
infile=../ns1/root.db.in
zonefile=root.db.signed

keyname=`$KEYGEN -a RSASHA1 -qfk $zone`

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
$KEYGEN -a RSASHA1 -q $zone > /dev/null
$KEYGEN -a RSASHA1 -qfk $zone > /dev/null
$SIGNER -S -o $zone -f $zonefile $infile > /dev/null 2>&1
