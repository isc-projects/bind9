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

# $Id: kit.sh,v 1.11 2000/12/04 18:40:24 gson Exp $

# Make a release kit
#
# Usage: sh kit.sh tag tmpdir
#
#    (e.g., sh kit.sh v9_0_0b5 /tmp/bindkit
#
# To build a snapshot release, use the pseudo-tag "snapshot".
#
#   (e.g., sh kit.sh snapshot /tmp/bindkit
#

case $# in
    2) tag=$1; tmpdir=$2 ;;
    *) echo "usage: sh kit.sh cvstag tmpdir" >&2
       exit 1
       ;;
esac

case $tag in
    snapshot) tag="HEAD"; snapshot=true ;;
    *) snapshot=false ;;
esac


test -d $tmpdir ||
mkdir $tmpdir || {
    echo "$0: could not create directory $tmpdir" >&2
    exit 1
}

cd $tmpdir || exit 1

cvs checkout -p -r $tag bind9/version >version.tmp
. ./version.tmp


if $snapshot
then
    dstamp=`date +'%Y%m%d'`

    RELEASETYPE=s
    RELEASEVER=$dstamp
fi

version=${MAJORVER}.${MINORVER}.${PATCHVER}${RELEASETYPE}${RELEASEVER}

echo "building release kit for BIND version $version, hold on..."

topdir=bind-$version

test ! -d $topdir || {
    echo "$0: directory `pwd`/$topdir already exists" >&2
    exit 1
}

cvs -Q export -r $tag -d $topdir bind9

cd $topdir || exit 1

if $snapshot
then
    cat <<EOF >version
MAJORVER=$MAJORVER
MINORVER=$MINORVER
PATCHVER=$PATCHVER
RELEASETYPE=$RELEASETYPE
RELEASEVER=$RELEASEVER
EOF
fi

sh util/sanitize_all.sh

# Omit some files and directories from the kit.

rm -rf TODO conftools util doc/design doc/dev doc/expired \
    doc/html doc/todo doc/private bin/lwresd doc/man/ctoman \
    doc/man/isc doc/man/bin/resolver.5 \
    bin/tests/system/relay

find . -name .cvsignore -print | xargs rm

cd .. || exit 1

kit=$topdir.tar.gz

gtar -c -z -f $kit $topdir

echo "done, kit is in `pwd`/$kit"
