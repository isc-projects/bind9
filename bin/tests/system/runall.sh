#!/bin/sh
#
# Copyright (C) 2004, 2007, 2010-2012, 2014, 2015, 2018  Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) 2000, 2001  Internet Software Consortium.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

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

# Handle "-n" switch if present.

NOCLEAN=""
while getopts "n" flag; do
    case "$flag" in
        n) NOCLEAN="-n" ;;
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
            $SHELL run.sh $NOCLEAN $testdir || status=1
        done
    } 2>&1 | tee "systests.output"
fi
exit $status
