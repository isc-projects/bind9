#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL clean.sh

for i in 1 2 3 4 5 6 7 8 9 10; do
    copy_setports ns1/named$i.conf.in ns1/named$i.conf
done

cp ns1/named1.conf ns1/named.conf

for cc in ecsoff 1 2 3 4 5 6 7 8; do
        cp example.db.in ns1/example-$cc.db
        echo "@ IN TXT \"$cc\"" >> ns1/example-$cc.db
done
