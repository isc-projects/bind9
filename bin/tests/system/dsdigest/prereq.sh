#!/bin/sh -e
#
# Copyright (C) 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

gostfail=0 ecdsafail=0
$SHELL ../testcrypto.sh -q gost || gostfail=1
$SHELL ../testcrypto.sh -q ecdsa || ecdsafail=1

if [ $gostfail = 0 -a $ecdsafail = 0 ]; then
	echo both > supported
elif [ $gostfail = 1 -a $ecdsafail = 1 ]; then
	echo "I:This test requires support for ECDSA or GOST cryptography." >&2
	exit 255
elif [ $gostfail = 0 ]; then
	echo gost > supported
else
        echo ecdsa > supported
fi
