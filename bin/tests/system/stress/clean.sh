#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: clean.sh,v 1.6 2007/09/26 03:22:44 marka Exp $

rm -f reload.pid

rm -f ns?/zones.conf
rm -f ns?/zone*.bk

rm -f ns1/delegations.db

rm -f ns2/zone0*.db
rm -f ns2/zone0*.jnl
rm -f */named.memstats
rm -f ns*/named.lock
