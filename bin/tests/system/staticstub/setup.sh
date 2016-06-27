#!/bin/sh
#
# Copyright (C) 2010, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

sed 's/SERVER_CONFIG_PLACEHOLDER/server-names { "ns.example.net"; };/' ns2/named.conf.in > ns2/named.conf

sed 's/EXAMPLE_ZONE_PLACEHOLDER/zone "example" { type master; file "example.db.signed"; };/' ns3/named.conf.in > ns3/named.conf

test -r $RANDFILE || $GENRANDOM 400 $RANDFILE

cd ns3 && $SHELL -e sign.sh
