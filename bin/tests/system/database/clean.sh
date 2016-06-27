#!/bin/sh
#
# Copyright (C) 2011, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: clean.sh,v 1.3 2011/03/01 23:48:05 tbox Exp $

rm -f ns1/named.conf ns1/named.run ns1/named.memstats
rm -f dig.out.*
rm -f ns*/named.lock
