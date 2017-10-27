#!/bin/sh -e
#
# Copyright (C) 2015-2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL clean.sh

test -r $RANDFILE || $GENRANDOM 800 $RANDFILE

cp ns1/named1.conf ns1/named.conf
cp ns5/named1.args ns5/named.args

( cd ns1 && $SHELL sign.sh )

cp ns2/managed.conf ns2/managed1.conf

cd ns4
mkdir nope
touch nope/managed-keys.bind
touch nope/managed.keys.bind.jnl
chmod 444 nope/*
