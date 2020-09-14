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

remote=--remote=git@gitlab.isc.org:isc-projects/bind9.git

case "${1:-}" in
--remote=*)
	remote="${1}"
	shift
	;;
esac

repo=`expr "X${remote}X" : '^X--remote=\(.*\)X$'`

case $# in
    3)
	case "$1" in
	snapshot) ;;
	*) echo "usage: sh kit.sh [snapshot] gittag tmpdir" >&2
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
	    snapshot) tag=master; snapshot=true ; releasetag="" ;;
	    *) snapshot=false ;;
	esac
	;;
    *) echo "usage: sh kit.sh [snapshot] gittag tmpdir" >&2
       exit 1
       ;;
esac

# create tmpdir
test -d $tmpdir ||
mkdir $tmpdir || {
    echo "$0: could not create directory $tmpdir" >&2
    exit 1
}

cd $tmpdir || {
	echo "$0: cd $tmpdir failed"
	exit 1
}

hash=`git ls-remote $repo refs/heads/$tag | awk '{print $1}'`
if [ -z "$hash" ]; then
        hash=`git ls-remote $repo refs/tags/$tag | awk '{print $1}'`
fi
if [ -z "$hash" ]; then
        echo "Unable to determine hash for $tag, aborting."
        exit 1
fi
shorthash=`echo $hash | cut -c1-7`

verdir=bind9-kit.$$
mkdir $verdir || {
    echo "$0: could not create directory $tmpdir/$verdir" >&2
    exit 1
}
git archive --format=tar $remote $tag version | ( cd $verdir ;tar xf - )
test -f $verdir/version || {
    echo "$0: could not get 'version' file" >&2
    exit 1
}
. $verdir/version

rm $verdir/version
rmdir $verdir

if $snapshot
then
    RELEASETYPE=s
    RELEASEVER=${shorthash}
fi

version=${MAJORVER}.${MINORVER}${PATCHVER:+.}${PATCHVER}${RELEASETYPE}${RELEASEVER}${EXTENSIONS}

echo "building release kit for BIND version $version, hold on..."

topdir=bind-$version

test ! -d $topdir || {
    echo "$0: directory $tmpdir/$topdir already exists" >&2
    exit 1
}

mkdir $topdir || exit 1

git archive --format=tar $remote $tag | ( cd $topdir; tar xf -)

cd $topdir || exit 1

if $snapshot
then
    cat <<EOF >version
MAJORVER=$MAJORVER
MINORVER=$MINORVER
PATCHVER=$PATCHVER
RELEASETYPE=$RELEASETYPE
RELEASEVER=$RELEASEVER
EXTENSIONS=$EXTENSIONS
EOF
fi

# Omit some files and directories from the kit.
#
# Some of these directories (doc/html, doc/man...) no longer
# contain any files and should therefore be absent in the
# checked-out tree, but they did exist at some point and
# we still delete them from releases just in case something 
# gets accidentally resurrected.

rm -rf TODO EXCLUDED conftools doc/design doc/dev doc/draft doc/expired \
    doc/html doc/rfc doc/todo doc/private doc/man doc/markdown \
    contrib/zkt/doc/rfc5011.txt \
    bin/tests/system/relay lib/cfg

# Remove everything but mksymtbl.pl and bindkeys.pl from util
find util -name bindkeys.pl -o -name mksymtbl.pl -prune -o -type f -print | xargs rm -f
find util -depth -type d -print | xargs rmdir 2>/dev/null

# Remove all .gitignore files
find . -name .gitignore -print | xargs rm

# Remove branchsync.dat, if present
rm -f branchsync.dat

# populate srcid file
echo "SRCID=$shorthash" > srcid

# The following files should be executable.
chmod +x configure install-sh mkinstalldirs bin/tests/system/ifconfig.sh
# Fix up releases with libbind.
if test -f lib/bind/configure
then
	 chmod +x lib/bind/configure lib/bind/mkinstalldirs
fi

# Fix files which should be using DOS style newlines
windirs=`find lib bin -type d -name win32`
windirs="$windirs win32utils"
winnames="-name *.mak -or -name *.dsp -or -name *.dsw -or -name *.txt -or -name *.bat"
for f in `find $windirs -type f \( $winnames \) -print`
do
	awk '{sub("\r$", "", $0); printf("%s\r\n", $0);}' < $f > tmp
	touch -r $f tmp
	mv tmp $f
done

# check that documentation has been updated properly; issue a warning
# if it hasn't
ok=
for f in doc/arm/*.html
do
	if test "$f" -nt doc/arm/Bv9ARM-book.xml
	then
		ok=ok
	fi
done

if test "$ok" != ok
then
	echo "WARNING: ARM source is newer than the html version."
fi

if test doc/arm/Bv9ARM-book.xml -nt doc/arm/Bv9ARM.pdf
then
	echo "WARNING: ARM source is newer than the PDF version."
fi

for f in `find . -name "*.docbook" -print`
do
	docbookfile=$f
	htmlfile=${f%.docbook}.html
	if test $docbookfile -nt $htmlfile
	then
		echo "WARNING: $docbookfile is newer than the html version."
	fi
done

# build the tarball
cd .. || exit 1

kit=$topdir.tar.gz
tar -c -f - $topdir | gzip > $kit
echo "done, kit is in `pwd`/$kit"
