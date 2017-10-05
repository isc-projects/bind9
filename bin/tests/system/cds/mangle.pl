#!/usr/bin/perl
#
# Copyright (C) 2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

my $re = $ARGV[0];
shift;
while (<>) {
	s{($re)........}{${1}00000000};
	print;
}
