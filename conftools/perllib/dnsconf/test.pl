#!/usr/bin/perl
#
# Copyright (C) 2000, 2001, 2004, 2007, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

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
