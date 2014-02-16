#!/bin/sh
#
# Copyright (C) 2004, 2007-2010, 2012, 2013  Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) 2000-2003  Internet Software Consortium.
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

remote=--remote=cvs.isc.org:/proj/git/prod/bind9.git

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

shorthash=`git ls-remote $repo refs/heads/$tag | cut -c1-8`
if [ -z "$shorthash" ]; then
        shorthash=`git ls-remote $repo refs/tags/$tag | cut -c1-8`
fi
if [ -z "$shorthash" ]; then
        echo "Unable to determine hash for $tag, aborting."
        exit 1
fi

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
    doc/html doc/rfc doc/todo doc/private bin/lwresd doc/man \
    lib/lwres/man/resolver.5 contrib/zkt/doc/rfc5011.txt \
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
