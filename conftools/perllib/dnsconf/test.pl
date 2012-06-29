#!/usr/bin/perl
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

# $Id: test.pl,v 1.9 2007/06/19 23:47:07 tbox Exp $

push(@ARGV, "/etc/named.conf") if ! @ARGV;

use DNSConf;

##
## First get the current named.conf file and print it.
##
$named = new DNSConf;

$named->parse($ARGV[0]);

$dir = $named->getdirectory();

print "the directory value in $ARGV[0] is: ";
if (!defined($dir)) {
    print "undefined\n";
} else {
    print $dir, "\n";
}

print "\n\nAnd the full file is:\n\n";
$named->print(STDOUT);



##
## Now create out own and fill it up.
##

$anothernamed = new DNSConf;

$thedir = "/var/tmp";

print "Created a virgin config structure and added \"$thedir\"\n";
print "as the directory\n";

$anothernamed->setdirectory($thedir);

$anothernamed->settransfersin(300);

$str = $anothernamed->getdirectory();
print "Pulling that value out again yields: \"", $str, "\"\n";

print "And the full file contents is: \n\n";
$anothernamed->print(STDOUT);

undef($named);
undef($anothernamed);
