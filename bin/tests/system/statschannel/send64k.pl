#!/usr/bin/perl
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

#
# Send a file to a given address and port using TCP.  Used for
# configuring the test server in ans.pl.
#

use IO::File;
use IO::Socket;

@ARGV == 2 or die "usage: send.pl host port\n";

my $host = shift @ARGV;
my $port = shift @ARGV;

my $sock = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port,
				 Proto => "tcp",) or die "$!";
#send the file
while ($n = read(STDIN, $buf, 64000)) {
	$sock->syswrite($buf, $n);
}

#get the response with with a 15 second timeout
my $rin;
my $rout;
my $n;
do {
        $rin = '';
        vec($rin, fileno($sock), 1) = 1;
	$n = select($rout = $rin, undef, undef, 15);
	$n = $sock->sysread($buf, 64000) if ($n > 0);
	print STDOUT $buf if ($n > 0);
} while ($n > 0);

$sock->close;
