#!/bin/sh
#
# Copyright (C) 2011, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL clean.sh

copy_setports ns1/named.plain ns1/named.conf
copy_setports ns1/rndc.conf.in ns1/rndc.conf
copy_setports ns1/controls.conf.in ns1/controls.conf
