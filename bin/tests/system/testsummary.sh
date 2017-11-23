#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2010-2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Searches the system test output file (systests.output) and prints a summary
# of tests passed, failed, not run.  It also checks whether the IP addresses
# 10.53.0.[1-8] were set up and, if not, prints a warning.
#
# Usage:
#    testsummary.sh
#
# Status return:
# 0 - no tests failed
# 1 - one or more tests failed

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

$PERL testsock.pl || {
    cat <<EOF >&2
I:
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
