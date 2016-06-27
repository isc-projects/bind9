#!/usr/bin/perl
#
# Copyright (C) 2010, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: testsock6.pl,v 1.5 2010/06/22 23:46:52 tbox Exp $

require 5.001;

use IO::Socket::INET6;

foreach $addr (@ARGV) {
	my $sock;
	$sock = IO::Socket::INET6->new(LocalAddr => $addr,
                                       LocalPort => 0,
                                       Proto     => tcp)
                             or die "Can't bind : $@\n";
	close($sock);
}
