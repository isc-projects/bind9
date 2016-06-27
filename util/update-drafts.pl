#!/usr/local/bin/perl -w
#
# Copyright (C) 2000, 2001, 2004, 2007, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id$

#
# Replace internet drafts with updated versions, if any.
#
# Usage:
#
#   cd doc/draft
#   perl ../../util/update-drafts.pl *.txt
#   (ignore "404 Not Found" errors from FTP)
#   cvs commit -m"updated drafts"
#

foreach (@ARGV) {
    $ofile = $_;
    if (/^(.*-)([0-9][0-9])(\.txt)/) {
	    $nfile = "$1" . sprintf("%02d", $2 + 1) . "$3";
	    print $nfile, "\n";
	    system "ftp http://www.ietf.org/internet-drafts/$nfile";
	    if ($? == 0) {
		unlink($ofile);
		system "cvs remove $ofile";
		system "cvs add $nfile";
	    }
    }
}
