#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

#
# Check the installed bind9 header files to make sure that no header
# depends on another header having been included first, and that
# they all compile as C++.
#

case $# in
  1) ;;
  *) echo "usage: sh util/check-instincludes.sh <prefix>" >&2;
     exit 1;
     ;;
esac

prefix=$1

test -f ./configure.in || {
    echo "$0: run from top of bind9 source tree" >&2;
    exit 1;
}

tmp=/tmp/thdr$$.tmp

status=0

echo "Checking header independence and C++ compatibility..."

# Make a list of header files.
(cd $prefix/include; find . -name '*.h' -print | sed 's!^./!!') > $tmp

# Check each header.
while read h
do
    echo " - <$h>"

    # Build a test program.
    cat <<EOF >test.cc
#include <$h>
EOF

    # Compile the test program.
    if
       gcc  -W -Wall -Wmissing-prototypes -Wcast-qual -Wwrite-strings \
           -I/usr/pkg/pthreads/include -I$prefix/include -c test.cc 2>&1
    then
       :
    else
       status=1
    fi
done <$tmp

rm -f test.cc test.o $tmp

exit $status
