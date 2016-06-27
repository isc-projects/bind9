#!/bin/sh -e
#
# Copyright (C) 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

../../../tools/genrandom 400 random.data

cd ns1 && sh sign.sh

cd ../ns5 && cp -f trusted.conf.bad trusted.conf

