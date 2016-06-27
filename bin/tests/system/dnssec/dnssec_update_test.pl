#!/usr/bin/perl
#
# Copyright (C) 2002, 2004, 2007, 2010, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#
# DNSSEC Dynamic update test suite.
#
# Usage:
#
#   perl update_test.pl [-s server] [-p port] zone
#
# The server defaults to 127.0.0.1.
# The port defaults to 53.
#
# Installation notes:
#
# This program uses the Net::DNS::Resolver module.
# You can install it by saying
#
#    perl -MCPAN -e "install Net::DNS"
#
# $Id: dnssec_update_test.pl,v 1.7 2010/08/13 23:47:03 tbox Exp $
#

use Getopt::Std;
use Net::DNS;
use Net::DNS::Update;
use Net::DNS::Resolver;

$opt_s = "127.0.0.1";
$opt_p = 53;

getopt('s:p:');

$res = new Net::DNS::Resolver;
$res->nameservers($opt_s);
$res->port($opt_p);
$res->defnames(0); # Do not append default domain.

@ARGV == 1 or die
    "usage: perl update_test.pl [-s server] [-p port] zone\n";

$zone = shift @ARGV;

my $failures = 0;

sub assert {
    my ($cond, $explanation) = @_;
    if (!$cond) {
	print "I:Test Failed: $explanation ***\n";
	$failures++
    }
}

sub test {
    my ($expected, @records) = @_;

    my $update = new Net::DNS::Update("$zone");

    foreach $rec (@records) {
	$update->push(@$rec);
    }

    $reply = $res->send($update);

    # Did it work?
    if (defined $reply) {
	my $rcode = $reply->header->rcode;
        assert($rcode eq $expected, "expected $expected, got $rcode");
    } else {
	print "I:Update failed: ", $res->errorstring, "\n";
    }
}

sub section {
    my ($msg) = @_;
    print "I:$msg\n";
}

section("Add a name");
test("NOERROR", ["update", rr_add("a.$zone 300 A 73.80.65.49")]);

section("Delete the name");
test("NOERROR", ["update", rr_del("a.$zone")]);

if ($failures) {
    print "I:$failures update tests failed.\n";
} else {
    print "I:All update tests successful.\n";
}

exit $failures;
