#!/bin/sh
#
# Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f traffic traffic.out.*
rm -f dig.out*
rm -f */named.memstats
rm -f */named.run
rm -f ns*/named.lock
rm -f ns*/named.stats
rm -f xml.*stats json.*stats
rm -f compressed.headers regular.headers compressed.out regular.out
