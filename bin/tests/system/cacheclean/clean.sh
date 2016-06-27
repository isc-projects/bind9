#!/bin/sh
#
# Copyright (C) 2001, 2004, 2007, 2011, 2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: clean.sh,v 1.8 2011/08/03 23:47:48 tbox Exp $

#
# Clean up after cache cleaner tests.
#

rm -f dig.out.ns2
rm -f dig.out.expire
rm -f */named.memstats
rm -f */named.run
rm -f ns2/named_dump.db
rm -f ns*/named.lock
