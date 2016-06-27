#!/bin/sh -e
#
# Copyright (C) 2010-2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

test -r $RANDFILE || $GENRANDOM 400 $RANDFILE

cp ns4/tld1.db ns4/tld.db
cp ns6/to-be-removed.tld.db.in ns6/to-be-removed.tld.db
cp ns7/server.db.in ns7/server.db
cp ns7/named1.conf ns7/named.conf
(cd ns6 && $SHELL keygen.sh)
