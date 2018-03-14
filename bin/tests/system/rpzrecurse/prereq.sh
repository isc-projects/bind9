#!/bin/sh
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

ret=0
$FEATURETEST --rpz-nsdname || ret=1
$FEATURETEST --rpz-nsip || ret=1

if [ $ret != 0 ]; then
    echo "I:This test requires NSIP AND NSDNAME support in RPZ." >&2
    exit 1
fi

exec $SHELL ../testcrypto.sh
