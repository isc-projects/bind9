#!/bin/sh
#
# Copyright (C) 2000-2002, 2004, 2006, 2007, 2009, 2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

if $PERL -e 'use Net::DNS;' 2>/dev/null
then
    if $PERL -e 'use Net::DNS; die if ($Net::DNS::VERSION >= 0.69 && $Net::DNS::VERSION <= 0.70);' 2>/dev/null
    then
        :
    else
        echo "I:Net::DNS versions 0.69 to 0.70 have bugs that cause this test to fail: please update." >&2
        exit 1
    fi
fi

exec $SHELL ../testcrypto.sh
