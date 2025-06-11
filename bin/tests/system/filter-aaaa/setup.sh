#!/bin/sh

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

. ../conf.sh

copy_setports ns1/named1.conf.in ns1/named.conf
copy_setports ns2/named1.conf.in ns2/named.conf
copy_setports ns3/named1.conf.in ns3/named.conf
copy_setports ns4/named1.conf.in ns4/named.conf
copy_setports ns5/named.conf.in ns5/named.conf

copy_setports conf/good1.conf.in conf/good1.conf
copy_setports conf/good2.conf.in conf/good2.conf
copy_setports conf/good3.conf.in conf/good3.conf
copy_setports conf/good4.conf.in conf/good4.conf
copy_setports conf/good5.conf.in conf/good5.conf

copy_setports conf/bad1.conf.in conf/bad1.conf
copy_setports conf/bad2.conf.in conf/bad2.conf
copy_setports conf/bad3.conf.in conf/bad3.conf
copy_setports conf/bad4.conf.in conf/bad4.conf
copy_setports conf/bad5.conf.in conf/bad5.conf

(cd ns1 && $SHELL -e sign.sh)
(cd ns4 && $SHELL -e sign.sh)
