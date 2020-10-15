#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

test -r $RANDFILE || $GENRANDOM $RANDOMSIZE $RANDFILE

if $KEYGEN -q -a RSAMD5 -b 512 -n zone -r $RANDFILE foo > /dev/null 2>&1
then
    rm -f Kfoo*
else
    echo_i "This test requires that --with-openssl was used." >&2
    exit 255
fi
