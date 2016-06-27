#!/bin/sh
#
# Copyright (C) 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f */K* */dsset-* */*.signed */trusted.conf
rm -f ns1/root.db
rm -f ns1/signer.err
rm -f dig.out*
rm -f */named.run
rm -f */named.memstats
rm -f ns*/named.lock
