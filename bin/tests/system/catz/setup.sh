#!/bin/sh
#
# Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL clean.sh

cat ns1/catalog.example.db.in > ns1/catalog1.example.db
cat ns1/catalog.example.db.in > ns3/catalog2.example.db
cat ns1/catalog.example.db.in > ns1/catalog3.example.db
cat ns1/catalog.example.db.in > ns1/catalog4.example.db
cat ns2/named.conf.in > ns2/named.conf
mkdir ns2/zonedir
