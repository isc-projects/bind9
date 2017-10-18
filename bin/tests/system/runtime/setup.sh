#!/bin/sh -e
#
# Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL clean.sh

cp ns2/named1.conf ns2/named.conf

mkdir ns2/nope
chmod 555 ns2/nope
echo "directory \"`pwd`/ns2\";" > ns2/dir
echo "directory \"`pwd`/ns2/nope\";" > ns2/nopedir
echo "managed-keys-directory \"`pwd`/ns2\";" > ns2/mkd
echo "managed-keys-directory \"`pwd`/ns2/nope\";" > ns2/nopemkd
