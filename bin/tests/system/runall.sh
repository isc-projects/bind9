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
#   numprocess  Number of concurrent processes to use when running the tests.
#               The default is one, which causes the tests to run sequentially.
#               (This is ignored when running on Windows as the tests are always
#               run sequentially on that platform.)

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

usage="Usage: ./runall.sh [-n] [numprocesses]"

SYSTEMTEST_NO_CLEAN=0

# Handle "-n" switch if present.

while getopts "n" flag; do
    case "$flag" in
        n) SYSTEMTEST_NO_CLEAN=1 ;;
    esac
done
export NOCLEAN
shift `expr $OPTIND - 1`

# Obtain number of processes to use.

if [ $# -eq 0 ]; then
    numproc=1
elif [ $# -eq 1 ]; then
    test "$1" -eq "$1" > /dev/null 2>&1
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

# Run the tests.

export SYSTEMTEST_NO_CLEAN

status=0
if [ "$CYGWIN" = "" ]; then
    # Running on Unix, use "make" to run tests in parallel.
    make -j $numproc check
    status=$?
else
    # Running on Windows: no "make" available, so run the tests sequentially.
    # (This is simpler than working out where "nmake" is likely to be found.
    # Besides, "nmake" does not support parallel execution so if "nmake" is
    # used, the tests would be run sequentially anyway.)
    {
        for testdir in $SUBDIRS; do
            $SHELL run.sh $testdir || status=1
        done
    } 2>&1 | tee "systests.output"
fi
exit $status
