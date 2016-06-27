#!/bin/sh
#
# Copyright (C) 2010, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL clean.sh

test -r $RANDFILE || $GENRANDOM 400 $RANDFILE

cp ns1/named1.conf ns1/named.conf
cp ns2/named1.conf ns2/named.conf
cp ns3/named1.conf ns3/named.conf
cp ns4/named1.conf ns4/named.conf

if $SHELL ../testcrypto.sh -q
then
	(cd ns1 && $SHELL -e sign.sh)
	(cd ns4 && $SHELL -e sign.sh)
else
	echo "I:using pre-signed zones"
	cp -f ns1/signed.db.presigned ns1/signed.db.signed
	cp -f ns4/signed.db.presigned ns4/signed.db.signed
fi
