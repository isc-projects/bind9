#!/usr/bin/perl

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

require 5.001;

use IO::Socket::IP;

foreach $addr (@ARGV) {
	my $sock;
	$sock = IO::Socket::IP->new(LocalAddr => $addr,
				    Domain => PF_INET6,
                                    LocalPort => 0,
                                    Proto     => tcp)
                             or die "Can't bind : $@\n";
	close($sock);
}
