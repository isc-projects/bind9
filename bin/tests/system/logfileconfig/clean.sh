#!/bin/sh
#
# Copyright (C) 2011, 2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: clean.sh,v 1.4 2011/03/22 16:51:50 smann Exp $

#
# Clean up after log file tests
#
rm -f ns1/named.pid ns1/named.run
rm -f ns1/named.memstats ns1/dig.out
rm -f ns1/named_log ns1/named_pipe ns1/named_sym
rm -f ns1/named.conf
rm -rf ns1/named_dir
rm -f ns1/named_deflog
rm -f ns*/named.lock
rm -f ns1/query_log
rm -f ns1/rndc.out.test*
rm -f ns1/dig.out.test*
rm -f ns1/named_vers
rm -f ns1/named_vers.*
rm -f ns1/named_unlimited
rm -f ns1/named_unlimited.*
