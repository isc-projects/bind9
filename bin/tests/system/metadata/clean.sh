#!/bin/sh
#
# Copyright (C) 2009, 2011, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f K* dsset-* *.signed *.new
rm -f zsk.key ksk.key parent.ksk.key parent.zsk.key 
rm -f pending.key rolling.key standby.key inact.key
rm -f prerev.key postrev.key oldstyle.key
rm -f keys sigs
rm -f tmp.out
rm -f ns*/named.lock
