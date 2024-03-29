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

copy_setports ns1/named.conf.in ns1/named.conf
copy_setports ns2/named.conf.in tmp
sed 's/SERVER_CONFIG_PLACEHOLDER/server-names { "ns.example.net"; };/' tmp >ns2/named.conf

copy_setports ns3/named.conf.in tmp
sed 's/EXAMPLE_ZONE_PLACEHOLDER/zone "example" { type primary; file "example.db.signed"; };/' tmp >ns3/named.conf

copy_setports ns4/named.conf.in ns4/named.conf

cd ns3 && $SHELL -e sign.sh
