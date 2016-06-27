#!/bin/sh
#
# Copyright (C) 2010, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f ns1/K*
rm -f ns1/*.signed
rm -f ns1/signer.err
rm -f ns1/dsset-*
rm -f ns1/named.run ns1/named.conf
rm -f ns1/named.memstats

rm -f ns2/named.run ns2/named.conf
rm -f ns2/named.memstats

rm -f ns3/named.run ns3/named.conf
rm -f ns3/named.memstats

rm -f ns4/K*
rm -f ns4/*.signed
rm -f ns4/signer.err
rm -f ns4/dsset-*
rm -f ns4/named.run ns4/named.conf
rm -f ns4/named.memstats

rm -f dig.out.*
rm -f ns*/named.lock
