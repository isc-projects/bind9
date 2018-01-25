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
#    runall.sh [-n] [numprocesses]
#
#   -n          Noclean.  Keep all output files produced by all tests.  These
#               can later be removed by running "cleanall.sh".
#
#   numprocess  Number of simultaneous processes to use when running the tests.
#               The default is one, which causes the tests to run sequentially.

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

usage="Usage: ./runall.sh [-n] [numprocesses]"

while getopts "n" flag; do
    case "$flag" in
	n) CLEANFLAG="NOCLEAN=-n" ;;
    esac
done
shift `expr $OPTIND - 1`

if [ $# -eq 0 ]; then
    numproc=1
elif [ $# -eq 1 ]; then
    test "$1" -eq "$1" > /dev/null 2>& 1
    if [ $? -ne 0 ]; then
        # Value passed is not numeric
        echo "$usage" >&2
        exit 1
    fi
    numproc=$1
else
    echo "$usage" >&2
    exit 1
fi

$CLEANFLAG make -j $numproc check

exit $?
