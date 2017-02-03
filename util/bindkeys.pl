#!/usr/bin/env perl
#
# Copyright (C) 2009-2012, 2014, 2016, 2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

use strict;
use warnings;

my $lines;
while (<>) {
    chomp;
    if (/\/\* .Id:.* \*\//) {
	next;
    }
    s/\"/\\\"/g;
    s/$/\\n\\/;
    $lines .= $_ . "\n";
}

my $mkey = '#define MANAGED_KEYS "\\' . "\n" . $lines . "\"\n";

$lines =~ s/managed-keys/trusted-keys/;
$lines =~ s/\s+initial-key//g;
my $tkey = '#define TRUSTED_KEYS "\\' . "\n" . $lines . "\"\n";

print $tkey;
print "\n";
print $mkey;
