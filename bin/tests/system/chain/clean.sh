#!/bin/sh
#
# Copyright (C) 2011, 2012, 2014-2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f dig.out.* named*.pid
rm -f ns*/named.conf
rm -f */named.memstats */named.recursing */named.lock */named.run */ans.run
rm -f ns2/K* ns2/dsset-* ns2/example.db.signed
