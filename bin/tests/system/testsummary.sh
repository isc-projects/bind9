#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
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

# Creates the system tests output file from the various test.output files.  It
# then searches that file and prints the number of tests passed, failed, not
# run.  It also checks whether the IP addresses 10.53.0.[1-8] were set up and,
# if not, prints a warning.
#
# Usage:
#    testsummary.sh [-n]
#
# -n	Do NOT delete the individual test.output files after concatenating
#	them into systests.output.
#
# Status return:
# 0 - no tests failed
# 1 - one or more tests failed

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

keepfile=0

while getopts "n" flag; do
    case $flag in
	n) keepfile=1 ;;
    esac
done

if [ `ls */test.output 2> /dev/null | wc -l` -eq 0 ]; then
    echowarn "I:No 'test.output' files were found."
    echowarn "I:Printing summary from pre-existing 'systests.output'."
else
    cat */test.output > systests.output
    if [ $keepfile -eq 0 ]; then
        rm -f */test.output
    fi
fi

status=0
echoinfo "I:System test result summary:"
echoinfo "`grep 'R:[a-z0-9_-][a-z0-9_-]*:[A-Z][A-Z]*' systests.output | cut -d':' -f3 | sort | uniq -c | sed -e 's/^/I:/'`"

FAILED_TESTS=`grep 'R:[a-z0-9_-][a-z0-9_-]*:FAIL' systests.output | cut -d':' -f2 | sort | sed -e 's/^/I:      /'`
if [ -n "${FAILED_TESTS}" ]; then
	echoinfo "I:The following system tests failed:"
	echoinfo "${FAILED_TESTS}"
	status=1
fi

exit $status
