#!/bin/sh -e
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the NOTICE file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

test -r $RANDFILE || $GENRANDOM 800 $RANDFILE

cp ns4/tld1.db ns4/tld.db
cp ns6/to-be-removed.tld.db.in ns6/to-be-removed.tld.db
cp ns7/server.db.in ns7/server.db
cp ns7/named1.conf ns7/named.conf
(cd ns6 && $SHELL keygen.sh)
