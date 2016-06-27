#!/usr/bin/perl
#
# Copyright (C) 2000, 2001, 2004, 2007, 2011, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: setup.pl,v 1.16 2011/10/26 23:46:15 tbox Exp $

#
# Set up test data for zone transfer quota tests.
#
use FileHandle;

my $masterconf = new FileHandle("ns1/zones.conf", "w") or die;
my $slaveconf  = new FileHandle("ns2/zones.conf", "w") or die;

for ($z = 0; $z < 300; $z++) {
    my $zn = sprintf("zone%06d.example", $z);
    print $masterconf "zone \"$zn\" { type master; file \"$zn.db\"; };\n";
    print $slaveconf  "zone \"$zn\" { type slave; file \"$zn.bk\"; masterfile-format text; masters { 10.53.0.1; }; };\n";
    my $fn = "ns1/$zn.db";
    my $f = new FileHandle($fn, "w") or die "open: $fn: $!";
    print $f "\$TTL 300
\@	IN SOA 	ns1 . 1 300 120 3600 86400
	NS	ns1
	NS	ns2
ns1	A	10.53.0.1
ns2	A	10.53.0.2
	MX	10 mail1.isp.example.
	MX	20 mail2.isp.example.
www	A	10.0.0.1
xyzzy   A       10.0.0.2
";
    $f->close;
}
