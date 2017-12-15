#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2010-2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Run all the system tests.
#
# Usage:
#    runall.sh [numprocesses]
#
# ...where numprocess is the number of processes to use. The default is 1,
# which runs the tests sequentially.

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

usage="Usage: ./runall.sh [numprocesses]"

if [ $# -eq 0 ]; then
    numproc=1
elif [ $# -eq 1 ]; then
    test "$1" -eq "$1" > /dev/null 2>& 1
    if [ $? -ne 0 ]; then
        # Value passed is not numeric
        echo "$usage"
        exit 1
    fi
    numproc=$1
else
    echo "$usage"
    exit 1
fi

make -j $numproc check

exit $?
