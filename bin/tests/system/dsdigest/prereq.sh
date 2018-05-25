#!/bin/sh -e
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

ecdsafail=0
$SHELL ../testcrypto.sh -q ecdsa || ecdsafail=1

if [ $ecdsafail = 1 ]; then
	echo_i "This test requires support for ECDSA cryptography." >&2
	exit 255
else
        echo ecdsa > supported
fi
