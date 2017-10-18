#!/bin/sh
# Copyright (C) 2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

. ../getopts.sh

sed -e "s/@PORT@/${port}/g;s/@CONTROLPORT@/${controlport}/g" < ns1/named1.conf.in > ns1/named.conf
echo "${port}" > ns1/named.port

sed -e "s/@PORT@/${port}/g;s/@CONTROLPORT@/${controlport}/g" < ans2/ans.pl.in > ans2/ans.pl
echo "${port}" > ans2/named.port

sed -e "s/@PORT@/${port}/g;s/@CONTROLPORT@/${controlport}/g" < ns3/named.conf.in > ns3/named.conf
echo "${port}" > ns3/named.port
