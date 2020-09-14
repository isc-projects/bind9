#!/usr/local/bin/perl -w
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
