#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2005, 2007, 2012-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: clean.sh,v 1.14 2007/09/26 03:22:44 marka Exp $

#
# Clean up after zone transfer tests.
#

rm -f ns3/example.bk dig.out.ns?.?
rm -f ns2/named.conf ns2/example.db ns3/named.conf ns3/internal.bk
rm -f */*.jnl
rm -f */named.memstats
rm -f */named.run
rm -f ns2/external/K*
rm -f ns2/external/inline.db.jbk
rm -f ns2/external/inline.db.signed
rm -f ns2/external/inline.db.signed.jnl
rm -f ns2/internal/K*
rm -f ns2/internal/inline.db.jbk
rm -f ns2/internal/inline.db.signed
rm -f ns2/internal/inline.db.signed.jnl
rm -f dig.out.external dig.out.internal
rm -f ns*/named.lock
