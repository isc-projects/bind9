#!/bin/sh
#
# Copyright (C) 2000  Internet Software Consortium.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
# DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
# FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# $Id: altbuild.sh,v 1.2 2000/08/30 17:04:55 gson Exp $

#
# "Alternative build" test.
#
# Build BIND9 with build options that are seldom tested otherwise.
# It is built directly from CVS; specify the CVS tag as a command
# line argument.
#

case $# in 
    1) tag=$1 ;;
    *) echo "usage: $0 cvs-tag" >&2; exit 1 ;;
esac

srcdir=/tmp/src
builddir=/tmp/build
instdir=/tmp/inst

test ! -d $srcdir || rm -rf $srcdir
mkdir $srcdir

test ! -d $builddir || rm -rf $builddir
mkdir $builddir

test ! -d $instdir || rm -rf $instdir
mkdir $instdir

cd $srcdir || exit 1

cvs export -r $tag bind9

cd $builddir || exit 1

# Test a libtool / separate object dir build.

CFLAGS="-g -DISC_CHECK_NONE -DISC_MEM_FILL=0" \
    sh $srcdir/bind9/configure --with-libtool --prefix=$instdir
gmake clean
gmake
gmake install

# Rebuild in the source tree so that the test suite
# works, then run it.

cd $srcdir/bind9 || exit 1
CFLAGS="-g -DISC_CHECK_NONE -DISC_MEM_FILL=0" \
    sh configure --with-libtool --prefix=$instdir
make
make install

( cd bin/tests && make test )

# Check the installed header files

sh util/check-instincludes.sh $instdir
