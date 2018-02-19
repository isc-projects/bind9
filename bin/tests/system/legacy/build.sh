#!/bin/sh
#
# Copyright (C) 2014, 2016-2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

test -r $RANDFILE || $GENRANDOM 800 $RANDFILE

$SHELL clean.sh

(cd ns6 && $SHELL -e sign.sh)
(cd ns7 && $SHELL -e sign.sh)

$SHELL clean.sh
