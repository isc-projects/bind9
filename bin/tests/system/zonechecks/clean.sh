#!/bin/sh
#
# Copyright (C) 2004, 2007, 2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f *.out
rm -f */named.memstats
rm -f */named.run
rm -f */*.db */*.db.signed */K*.key */K*.private */*.jnl */dsset-*
rm -f rndc.out.*
rm -f ns*/named.lock
