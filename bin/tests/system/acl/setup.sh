#!/bin/sh
#
# Copyright (C) 2008, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL ../genzone.sh 2 3 >ns2/example.db
$SHELL ../genzone.sh 2 3 >ns2/tsigzone.db
cp -f ns2/named1.conf ns2/named.conf
