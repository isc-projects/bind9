#!/bin/sh -e
#
# Copyright (C) 2009-2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

# Have the child generate subdomain keys and pass DS sets to us.
( cd ../ns3 && $SHELL keygen.sh )

for subdomain in secure nsec3 autonsec3 optout rsasha256 rsasha512 nsec3-to-nsec oldsigs sync
do
	cp ../ns3/dsset-$subdomain.example. .
done

# Create keys and pass the DS to the parent.
zone=example
zonefile="${zone}.db"
infile="${zonefile}.in"
cat $infile dsset-*.example. > $zonefile

kskname=`$KEYGEN -3 -q -r $RANDFILE -fk $zone`
$KEYGEN -3 -q -r $RANDFILE $zone > /dev/null
$DSFROMKEY $kskname.key > dsset-${zone}.

# Create keys for a private secure zone.
zone=private.secure.example
zonefile="${zone}.db"
infile="${zonefile}.in"
cp $infile $zonefile
$KEYGEN -3 -q -r $RANDFILE -fk $zone > /dev/null
$KEYGEN -3 -q -r $RANDFILE $zone > /dev/null

# Extract saved keys for the revoke-to-duplicate-key test
zone=bar
zonefile="${zone}.db"
infile="${zonefile}.in"
cat $infile > $zonefile
for i in Xbar.+005+30676.key Xbar.+005+30804.key Xbar.+005+30676.private \
	 Xbar.+005+30804.private
do
	cp $i `echo $i | sed s/X/K/`
done
$KEYGEN -q -r $RANDFILE $zone > /dev/null
$DSFROMKEY Kbar.+005+30804.key > dsset-bar.
