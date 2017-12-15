#!/bin/sh
#
# Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#
# Clean up after a specified system test.
#

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

# See if the "-r" flag is present.  This will usually be set when all the tests
# are run (e.g. from "runall.sh") and tells the script not to delete the
# test.output file created by run.sh.  This is because the script running all
# the tests will call "testsummary.sh", which will concatenate all test output
# files into a single systests.output.

while getopts "r" flag; do
    case $flag in
	r) runall=1 ;;
	*) exit 1;;
    esac
done
shift `expr $OPTIND - 1`

test $# -gt 0 || { echo "usage: $0 [-r] test-directory" >&2; exit 1; }

test=$1
shift

if [ "$runall" = "" ]; then
    rm -f $test/test.output
fi

if test -f $test/clean.sh; then
    ( cd $test && $SHELL clean.sh "$@" )
fi
