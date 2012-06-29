#! /bin/sh -ex
#
# Copyright (C) 2004, 2007, 2012  Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) 2000, 2001  Internet Software Consortium.
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

# XXXDCL This is currently much too specific to the environment in which
# it was written (NetBSD 1.5_alpha2 with libiconv in /usr/local/lib).  It
# is essentially just a copy of the commands I used to test building of
# the mdnkit contributed source, and needs to be better generalized. 

# Directory was prepared with:
# cvs export -r {tag} bind9
# cd bind9

sh -ex util/sanitize_all.sh

mdn=`pwd`/contrib/idn/mdnkit

set +e
patch -p0 < $mdn/patch/bind9/patch.most > patch.out 2>&1
set -e

cmd="egrep '^Hunk' patch.out | egrep -v '^Hunk #[0-9]+ succeeded at [0-9]+\.$'"
if eval $cmd | egrep -q .; then
  echo Patch was not entirely clean: >&2
  $cmd >&2
  echo Patch output is in patch.out. >&2
  exit 1
fi

cd $mdn

CFLAGS=-I/usr/local/include ./configure --with-iconv='-L/usr/local/lib -liconv'
make

cd ../../..

cp configure configure.orig
autoconf
set +e
diff -u2 ./configure.orig ./configure > $mdn/patch/bind9/patch.configure
set -e

make

make distclean > /dev/null 2>&1

mdntmp=tmp/mdn

rm -rf $mdntmp
mkdir -p $mdntmp/lib $mdntmp/include
cp $mdn/lib/.libs/libmdn.so $mdntmp/lib
cp -r $mdn/include/mdn $mdntmp/include

./configure --with-mdn=$mdntmp --with-iconv="-L/usr/local/lib -liconv" 

LD_LIBRARY_PATH=/usr/local/lib:$mdntmp/lib:/usr/lib make

exit 0
