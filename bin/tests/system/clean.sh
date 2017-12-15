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
