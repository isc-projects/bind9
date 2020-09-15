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
	--disable-threads --with-openssl --prefix=$instdir
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
