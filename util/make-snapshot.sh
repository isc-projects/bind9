#!/bin/sh

# $Id: make-snapshot.sh,v 1.1 2000/04/28 00:09:22 explorer Exp $

CVS_RSH=ssh ; export CVS_RSH

prefix='/udir/ftp/isc/bind9/snapshots/bind9-snap-'
tagprefix='bind9-snap-'
cvsroot=':ext:rc.isc.org:/proj/cvs/isc'
pkg='bind9'

d=`date +'%Y%m%d'`

makefname() {
    if test ! -r $prefix$d.tar.gz ; then
	filename=$prefix$d.tar.gz
	tstamp=$tagprefix$d
	dstamp=$d
	return 0
    fi

    for i in a b c d e f g h i j k l m n o p q r s t u v w x y z ; do
	if test ! -r $prefix$d$i.tar.gz ; then
	    filename=$prefix$d$i.tar.gz
	    tstamp=$tagprefix$d$i
	    dstamp=$d$i
	    return 0
	fi
    done

    echo "Cannot make a unique filename"
    exit 1
}

makefname

echo "using $filename, tstamp $tstamp, dstamp $dstamp"

cvs -d $cvsroot co -d $tstamp $pkg

. $tstamp/version

chmod 644 $tstamp/version

echo "MAJORVER=$MAJORVER" > $tstamp/version
echo "MINORVER=$MINORVER" >> $tstamp/version
echo "PATCHVER=$PATCHVER" >> $tstamp/version
echo "RELEASETYPE=s" >> $tstamp/version
echo "RELEASEVER=$dstamp" >> $tstamp/version

cat $tstamp/version

tar cf - $tstamp | gzip > $filename.tmp
mv $filename.tmp $filename
chmod 444 $filename

rm -rf $tstamp
