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

rm -f */named.conf
rm -f */named.memstats
rm -f */named.run
rm -f */named.run.prev
rm -f */named.stats
rm -f dig.out*
rm -f dnstap.*
rm -f fstrm_capture.out.*
rm -f ns*/dnstap.out
rm -f ns*/dnstap.out.save
rm -f ns*/dnstap.out.save.?
rm -f ns*/managed-keys.bind*
rm -f ns2/dnstap.out.*
rm -f ns2/example.db ns2/example.db.jnl
rm -f ns3/dnstap.out.*
rm -f ydump.out
