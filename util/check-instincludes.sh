#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) Internet Software Consortium.
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

# $Id$

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
