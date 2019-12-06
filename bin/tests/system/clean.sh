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

#
# Clean up after a specified system test.
#

SYSTEMTESTTOP="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"
. $SYSTEMTESTTOP/conf.sh

export SYSTEMTESTTOP

if [ $# -eq 0 ]; then
    echo "usage: $0 test-directory" >&2
    exit 1
fi

systest=$1
shift

if [ -f $systest/clean.sh ]; then
    ( cd $systest && $SHELL clean.sh "$@" )
else
    echo "Test directory $systest does not exist" >&2
    exit 1
fi
