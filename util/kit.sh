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

# $Id: kit.sh,v 1.4 2000/08/11 19:58:19 gson Exp $

# Make a release kit
#
# Usage: sh kit.sh tag tmpdir
#
# (e.g., sh kit.sh v9_0_0b5 /tmp/bindkit
#

case $# in
    2) tag=$1; tmpdir=$2 ;;
    *) echo "usage: sh kit.sh cvstag tmpdir" >&2
       exit 1
       ;;
esac

test -d $tmpdir ||
mkdir $tmpdir || {
    echo "$0: could not create directory $tmpdir" >&2
    exit 1
}

cd $tmpdir || exit 1

cvs checkout -p -r $tag bind9/version >version.tmp
. ./version.tmp

VERSION=${MAJORVER}.${MINORVER}.${PATCHVER}${RELEASETYPE}${RELEASEVER}

echo "building release kit for BIND version $VERSION, hold on..."

topdir=bind-$VERSION

test ! -d $topdir || {
    echo "$0: directory `pwd`/$topdir already exists" >&2
    exit 1
}

cvs -Q export -r $tag -d $topdir bind9

cd $topdir || exit 1

sh util/sanitize_all.sh

# Omit some files and directories from the kit.
rm -rf TODO conftools util doc/design doc/dev doc/expired doc/html bin/lwresd
find . -name .cvsignore -print | xargs rm

cd .. || exit 1

kit=$topdir.tar.gz

gtar -c -z -f $kit $topdir

echo "done, kit is in `pwd`/$kit"
