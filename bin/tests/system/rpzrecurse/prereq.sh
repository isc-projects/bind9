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

ret=0
$FEATURETEST --rpz-nsdname || ret=1
$FEATURETEST --rpz-nsip || ret=1

if [ $ret != 0 ]; then
    echo_i "This test requires NSIP AND NSDNAME support in RPZ." >&2
    exit 1
fi

$SHELL ../testcrypto.sh || exit 255

if $PERL -e 'use Net::DNS;' 2>/dev/null
then
    :
else
    echo_i "This test requires the Net::DNS library." >&2
    exit 1
fi
