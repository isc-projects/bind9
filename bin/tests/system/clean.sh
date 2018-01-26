#!/bin/sh
#
# Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
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

runall=0

while getopts "r" flag; do
    case $flag in
	r) runall=1 ;;
    esac
done
shift `expr $OPTIND - 1`

if [ $# -eq 0 ]; then
    echo "usage: $0 [-r] test-directory" >&2
    exit 1
fi

systest=$1
shift

if [ $runall -eq 0 ]; then
    rm -f $systest/test.output
fi

if [ -f $systest/clean.sh ]; then
    ( cd $systest && $SHELL clean.sh "$@" )
else
    echo "Test directory $systest does not exist" >&2
    exit 1
fi
