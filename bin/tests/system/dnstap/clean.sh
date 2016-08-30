#!/bin/sh
#
# Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f */named.memstats
rm -f */named.run
rm -f */named.stats
rm -f dig.out*
rm -f dnstap.out
rm -f dnstap.out.save
rm -f fstrm_capture.out
rm -f ns*/dnstap.out
rm -f ns*/dnstap.out.save
rm -f ns*/dnstap.out.save.?
rm -f ns*/named.lock
