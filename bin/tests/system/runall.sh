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

# Make sure interfaces are up.
$PERL testsock.pl || {
    cat <<EOF
I:NOTE: System tests were skipped because they require that the
I:      IP addresses 10.53.0.1 through 10.53.0.8 be configured
I:      as alias addresses on the loopback interface.  Please run
I:      "bin/tests/system/ifconfig.sh up" as root to configure them.
EOF
    exit 1
}

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
