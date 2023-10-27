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

set -e

rm -f ./anchor.* ./*/anchor.*
rm -f ./*/named.conf
rm -f ./*/named.memstats
rm -f ./*/named.run
rm -f ./ans*/ans.run
rm -f ./ans*/query.log
rm -f ./delv.out.test*
rm -f ./dig.out.*test*
rm -f ./dig.out.mm.*
rm -f ./dig.out.mn.*
rm -f ./dig.out.nm.*
rm -f ./dig.out.nn.*
rm -f ./host.out.test*
rm -f ./ns*/managed-keys.bind*
rm -f ./ns*/K* ./ns*/keyid ./ns*/keydata
rm -f ./ns1/root.db
rm -f ./ns*/dsset-*
rm -f ./ns2/example.db
rm -f ./ns2/example.tld.db
rm -f ./nslookup.out.test*
rm -f ./nsupdate.out.test*
rm -f ./yamlget.out.*
