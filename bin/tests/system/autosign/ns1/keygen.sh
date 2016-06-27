#!/bin/sh -e
#
# Copyright (C) 2009-2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

zone=.
zonefile=root.db
infile=root.db.in

(cd ../ns2 && $SHELL keygen.sh )

cat $infile ../ns2/dsset-example. > $zonefile

zskact=`$KEYGEN -3 -q -r $RANDFILE $zone`
zskvanish=`$KEYGEN -3 -q -r $RANDFILE $zone`
zskdel=`$KEYGEN -3 -q -r $RANDFILE -D now $zone`
zskinact=`$KEYGEN -3 -q -r $RANDFILE -I now $zone`
zskunpub=`$KEYGEN -3 -q -r $RANDFILE -G $zone`
zsksby=`$KEYGEN -3 -q -r $RANDFILE -A none $zone`
zskactnowpub1d=`$KEYGEN -3 -q -r $RANDFILE -A now -P +1d $zone`
zsknopriv=`$KEYGEN -3 -q -r $RANDFILE $zone`
rm $zsknopriv.private

ksksby=`$KEYGEN -3 -q -r $RANDFILE -P now -A now+15s -fk $zone`
kskrev=`$KEYGEN -3 -q -r $RANDFILE -R now+15s -fk $zone`

cat $ksksby.key | grep -v '^; ' | $PERL -n -e '
local ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
local $key = join("", @rest);
print <<EOF
trusted-keys {
    "$dn" $flags $proto $alg "$key";
};
EOF
' > trusted.conf
cp trusted.conf ../ns2/trusted.conf
cp trusted.conf ../ns3/trusted.conf
cp trusted.conf ../ns4/trusted.conf

cat $kskrev.key | grep -v '^; ' | $PERL -n -e '
local ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
local $key = join("", @rest);
print <<EOF
trusted-keys {
    "$dn" $flags $proto $alg "$key";
};
EOF
' > trusted.conf
cp trusted.conf ../ns5/trusted.conf

echo $zskact > ../active.key
echo $zskvanish > ../vanishing.key
echo $zskdel > ../del.key
echo $zskinact > ../inact.key
echo $zskunpub > ../unpub.key
echo $zsknopriv > ../nopriv.key
echo $zsksby > ../standby.key
echo $zskactnowpub1d > ../activate-now-publish-1day.key
$REVOKE -R $kskrev > ../rev.key
