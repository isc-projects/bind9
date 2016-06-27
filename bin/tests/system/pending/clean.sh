#!/bin/sh
#
# Copyright (C) 2009, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -rf */*.signed
rm -rf */*.jnl
rm -rf */K*
rm -rf */dsset-*
rm -rf */named.memstats
rm -rf */named.run
rm -rf */trusted.conf
rm -rf ns1/root.db
rm -rf ns2/example.db
rm -rf ns2/example.com.db
rm -rf nsupdate.out.test
rm -f ns*/named.lock
