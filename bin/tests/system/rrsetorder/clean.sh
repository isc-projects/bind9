#!/bin/sh
#
# Copyright (C) 2006-2008, 2011, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f dig.out.test*
rm -f dig.out.cyclic dig.out.fixed dig.out.random dig.out.nomatch
rm -f dig.out.0 dig.out.1 dig.out.2 dig.out.3
rm -f dig.out.cyclic2
rm -f ns2/root.bk
rm -f ns?/named.run ns?/named.core
rm -f */named.memstats
rm -f ns*/named.lock
