#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2010-2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#
# Run all the system tests.
#

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

status=0

{
    for d in $SUBDIRS
    do
            $SHELL run.sh "${@}" $d || status=1
    done
} 2>&1 | tee "systests.output"

$PERL testsock.pl || {
    cat <<EOF >&2
I:
I:NOTE: System tests were skipped because they require that the
I:      IP addresses 10.53.0.1 through 10.53.0.8 be configured
I:      as alias addresses on the loopback interface.  Please run
I:      "bin/tests/system/ifconfig.sh up" as root to configure them.
EOF
}

echo "I:System test result summary:"
grep '^R:' systests.output | sort | uniq -c | sed -e 's/^/I: /' -e 's/R://'
grep '^R:FAIL' systests.output > /dev/null && status=1

exit $status
