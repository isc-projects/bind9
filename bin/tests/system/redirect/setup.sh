#!/bin/sh -e
#
# Copyright (C) 2011-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL clean.sh

test -r $RANDFILE || $GENRANDOM 400 $RANDFILE

cp ns2/redirect.db.in ns2/redirect.db
cp ns2/example.db.in ns2/example.db
( cd ns1 && $SHELL sign.sh )

cp ns4/example.db.in ns4/example.db
( cd ns3 && $SHELL sign.sh )
