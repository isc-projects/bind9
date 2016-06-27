#!/bin/sh
#
# Copyright (C) 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

../../../tools/genrandom 400 random.data

if $KEYGEN -q -a RSAMD5 -b 512 -n zone -r random.data foo > /dev/null 2>&1
then
    rm -f Kfoo*
else
    echo "I:This test requires that --with-openssl was used." >&2
    exit 255
fi
