#!/bin/sh
#
# Copyright (C) 2010-2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

test -r $RANDFILE || $GENRANDOM 400 $RANDFILE

rm -f ns1/*.jnl ns1/K*.key ns1/K*.private ns1/_default.tsigkeys

key=`$KEYGEN -Cq -K ns1 -a DSA -b 512 -r $RANDFILE -n HOST -T KEY key.example.nil.`
cat ns1/example.nil.db.in ns1/${key}.key > ns1/example.nil.db
