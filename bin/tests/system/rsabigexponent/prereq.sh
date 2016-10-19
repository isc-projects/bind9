#!/bin/sh
#
# Copyright (C) 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

test -r $RANDFILE || $GENRANDOM 400 $RANDFILE

if $BIGKEY > /dev/null 2>&1
then
    rm -f Kexample.*
else
    echo "I:This test requires cryptography" >&2
    echo "I:configure with --with-openssl, or --with-pkcs11 and --enable-native-pkcs11" >&2
    exit 255
fi
