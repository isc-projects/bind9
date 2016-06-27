#!/bin/sh
#
# Copyright (C) 2001, 2004, 2007, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if $PERL -e 'use Net::DNS;' 2>/dev/null
then
    :
else
    echo "I:This test requires the Net::DNS library." >&2
    exit 1
fi
