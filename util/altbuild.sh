#!/bin/sh
#
# Copyright (C) 2004  Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) 2000-2003  Internet Software Consortium.
#
# Permission to use, copy, modify, and distribute this software for any
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

# $Id: altbuild.sh,v 1.11.12.4 2007/01/17 00:32:45 marka Exp $

#
# "Alternative build" test.
#
# Build BIND9 with build options that are seldom tested otherwise.
# Specify the CVS tag or the name of a kit .tar.gz file as a
# command line argument.
#

tmpdir=/tmp
case $# in 
    2) arg=$1 tmpdir="$2" ;;
    1) arg=$1 ;;
    *) echo "usage: $0 cvs-tag | absolute-path-to-gzipped-tar-file [tmpdir]" >&2; exit 1 ;;
esac

here=`pwd`

test -f util/check-instincludes.sh || {
    echo "$0: must be run from top of CVS tree";
    exit 1;
}

kitdir=${tmpdir}/kit
srcdir=${tmpdir}/src
builddir=${tmpdir}/build
instdir=${tmpdir}/inst

test -d $tmpdir || mkdir $tmpdir
test ! -d $kitdir || rm -rf $kitdir
mkdir $kitdir

test ! -d $srcdir || rm -rf $srcdir
mkdir $srcdir

test ! -d $builddir || rm -rf $builddir
mkdir $builddir

test ! -d $instdir || rm -rf $instdir
mkdir $instdir

case $arg in
    *.tar.gz)
	kit="$arg"
	;;
    *)
	tag="$arg"
        sh util/kit.sh $tag $kitdir || exit 1
        kit=$kitdir/*.tar.gz
	;;
esac

cd $srcdir || exit 1
gzcat $kit | tar xf -

cd $builddir || exit 1

# Test a libtool / separate object dir / threadless build.

CFLAGS="-g -DISC_CHECK_NONE -DISC_MEM_FILL=0 -DISC_LIST_CHECKINIT" \
    sh $srcdir/bind-*/configure --with-libtool \
	--disable-threads --with-openssl --enable-libbind --prefix=$instdir
gmake clean
gmake
gmake install

# Rebuild in the source tree so that the test suite
# works, then run it.

cd $srcdir/bind-* || exit 1
CFLAGS="-g -DISC_CHECK_NONE -DISC_MEM_FILL=0 -DISC_LIST_CHECKINIT" \
    sh configure --with-libtool --disable-threads --prefix=$instdir
make
make install

( cd bin/tests && make test )

# Check the installed header files

cd $here
sh util/check-instincludes.sh $instdir
