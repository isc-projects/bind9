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

cp ns2/named1.conf ns2/named.conf

mkdir ns2/nope

if [ 1 = "${CYGWIN:-0}" ]
then
    setfacl -s user::r-x,group::r-x,other::r-x ns2/nope
else
    chmod 555 ns2/nope
fi
