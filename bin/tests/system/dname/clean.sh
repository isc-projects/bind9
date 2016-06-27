#!/bin/sh
#
# Copyright (C) 2011, 2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: clean.sh,v 1.2 2011/03/18 21:14:19 fdupont Exp $

#
# Clean up after resolver tests.
#
rm -f */named.memstats
rm -f */named.run
rm -f dig.out.*
rm -f ns*/named.lock
