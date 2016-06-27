#!/bin/perl
#
# Copyright (C) 2007, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: sort-options.pl,v 1.3 2007/09/24 23:46:48 tbox Exp $

sub sortlevel() {
	my @options = ();
	my $fin = "";
	my $i = 0;
	while (<>) {
		if (/^\s*};$/) {
			$fin = $_;
			# print 2, $_;
			last;
		}
		next if (/^$/);
		if (/{$/) {
			# print 3, $_;
			my $sec = $_;
			push(@options, $sec . sortlevel());
		} else {
			push(@options, $_);
			# print 1, $_;
		}
		$i++;
	}
	my $result = "";
	foreach my $i (sort @options) {
		$result = ${result}.${i};
		$result = $result."\n" if ($i =~ /^[a-z]/i);
		# print 5, ${i};
	}
	$result = ${result}.${fin};
	return ($result);
}

print sortlevel();
