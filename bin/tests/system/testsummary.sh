#!/bin/sh
#
# Copyright (C) 2018  Internet Systems Consortium, Inc. ("ISC")
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

cat */test.output > systests.output 2> /dev/null
if [ $keepfile -eq 0 ]; then
    rm -f */test.output
fi

$PERL testsock.pl || {
    cat <<EOF
I:NOTE: System tests were skipped because they require that the
I:      IP addresses 10.53.0.1 through 10.53.0.8 be configured
I:      as alias addresses on the loopback interface.  Please run
I:      "bin/tests/system/ifconfig.sh up" as root to configure them.
EOF
}

status=0
echo "I:System test result summary:"
grep '^R:' systests.output | cut -d':' -f3 | sort | uniq -c | sed -e 's/^/I:/'
grep '^R:[^:]*:FAIL' systests.output > /dev/null && status=1

exit $status
