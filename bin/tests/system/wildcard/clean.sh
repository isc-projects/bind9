#!/bin/sh
#
# Copyright (C) 2012-2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f ns*/named.run
rm -f ns1/K*
rm -f ns1/*.db
rm -f ns1/*.signed
rm -f ns1/dsset-*
rm -f ns1/keyset-*
rm -f ns1/trusted.conf
rm -f ns1/private.nsec.conf
rm -f ns1/private.nsec3.conf
rm -f ns1/signer.err
rm -f */named.memstats
rm -f dig.out.ns*.test*
rm -f ns*/named.lock
