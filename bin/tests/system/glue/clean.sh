#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the NOTICE file distributed with this work for additional
# information regarding copyright ownership.

# $Id: clean.sh,v 1.9 2007/09/26 03:22:43 marka Exp $

#
# Clean up after glue tests.
#

rm -f dig.out ns1/cache
rm -f */named.memstats
rm -f */named.run
rm -f ns*/named.lock
