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

# $Id: kit.sh,v 1.20.2.1.10.4 2004/06/03 02:52:00 marka Exp $

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

arg=-r
case $# in
    3)
	case "$1" in
	snapshot) ;;
	*) echo "usage: sh kit.sh [snapshot] cvstag tmpdir" >&2
	   exit 1
	   ;;
	esac
	snapshot=true;
	releasetag=$2
	tag=$2
	tmpdir=$3
	;;
    2)
	tag=$1
	tmpdir=$2
	case $tag in
	    snapshot) tag=HEAD; snapshot=true ; releasetag="" ;;
	    *) snapshot=false ;;
	esac
	;;
    *) echo "usage: sh kit.sh [snapshot] cvstag tmpdir" >&2
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


if $snapshot
then
    set `date -u +'%Y%m%d%H%M%S %Y/%m/%d %H:%M:%S UTC'`
    dstamp=$1
    RELEASETYPE=s
    RELEASEVER=${dstamp}${releasetag}
    shift
    tag="$@"
    arg=-D
fi

version=${MAJORVER}.${MINORVER}.${PATCHVER}${RELEASETYPE}${RELEASEVER}

echo "building release kit for BIND version $version, hold on..."

topdir=bind-$version

test ! -d $topdir || {
    echo "$0: directory `pwd`/$topdir already exists" >&2
    exit 1
}

cvs -Q export $arg "$tag" -d $topdir bind9

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

# Omit some files and directories from the kit.
#
# Some of these directories (doc/html, doc/man...) no longer
# contain any files and should therefore be absent in the
# checked-out tree, but they did exist at some point and
# we still delete them from releases just in case something 
# gets accidentally resurrected.

rm -rf EXCLUDED TODO conftools util doc/design doc/dev doc/expired \
    doc/html doc/todo doc/private bin/lwresd doc/man \
    lib/lwres/man/resolver.5 \
    bin/tests/system/relay lib/cfg

find . -name .cvsignore -print | xargs rm

# The following files should be executable.
chmod +x configure install-sh mkinstalldirs \
	 lib/bind/configure lib/bind/mkinstalldirs \
	 bin/tests/system/ifconfig.sh

cd .. || exit 1

kit=$topdir.tar.gz

tar -c -f - $topdir | gzip > $kit

echo "done, kit is in `pwd`/$kit"
