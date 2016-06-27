#!/bin/sh
#
# Copyright (C) 2010, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

echo "I:(Native PKCS#11)" >&2
rsafail=0 eccfail=0

$SHELL ../testcrypto.sh -q rsa || rsafail=1
$SHELL ../testcrypto.sh -q ecdsa || eccfail=1

if [ $rsafail = 0 -a $eccfail = 0 ]; then
	echo both > supported
elif [ $rsafail = 1 -a $eccfail = 1 ]; then
	echo "I:This test requires PKCS#11 support for either RSA or ECDSA cryptography." >&2
	exit 255
elif [ $rsafail = 0 ]; then
	echo rsaonly > supported
else
        echo ecconly > supported
fi
