#!/bin/sh
#
# Copyright (C) 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f K* */K* */dsset-*. */*.signed */trusted.conf */tmp*
rm -f ns*/dsset-example
rm -f ns*/named.run
rm -f ns*/named.memstats
rm -f ns1/root.db
rm -f ns2/signer.err
rm -f dig.out.*
rm -f ns*/named.lock
