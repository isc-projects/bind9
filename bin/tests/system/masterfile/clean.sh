#!/bin/sh
#
# Copyright (C) 2001, 2004, 2007, 2010, 2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: clean.sh,v 1.7 2010/09/15 12:38:35 tbox Exp $

rm -f dig.out.*
rm -f */named.memstats
rm -f */named.run
rm -f ns*/named.lock
rm -f checkzone.out*
