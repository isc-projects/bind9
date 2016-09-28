#!/usr/bin/env perl
#
# Copyright (C) 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

use strict;
use warnings;

use IO::File;
use Getopt::Long;
use Net::DNS::Nameserver;
use Time::HiRes qw(usleep nanosleep);

my $pidf = new IO::File "ans.pid", "w" or die "cannot open pid file: $!";
print $pidf "$$\n" or die "cannot write pid file: $!";
$pidf->close or die "cannot close pid file: $!";
sub rmpid { unlink "ans.pid"; exit 1; };

$SIG{INT} = \&rmpid;
$SIG{TERM} = \&rmpid;

my $count = 0;
my $send_response = 0;

sub getlimit {
    if ( -e "ans.limit") {
	open(FH, "<", "ans.limit");
	my $line = <FH>;
	chomp $line;
	close FH;
	if ($line =~ /^\d+$/) {
	    return $line;
	}
    }

    return 0;
}

my $localaddr = "10.53.0.2";
my $localport = 5300;
my $verbose = 0;
my $limit = getlimit();

sub reply_handler {
    my ($qname, $qclass, $qtype, $peerhost, $query, $conn) = @_;
    my ($rcode, @ans, @auth, @add);

    print ("request: $qname/$qtype\n");
    STDOUT->flush();

    $count += 1;
    # Sleep 100ms to make sure that named sends both A and AAAA queries.
    usleep(100000);

    if ($qname eq "count" ) {
	if ($qtype eq "TXT") {
	    my ($ttl, $rdata) = (0, "$count");
	    my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
	    push @ans, $rr;
	    print ("\tcount: $count\n");
	}
	$rcode = "NOERROR";
    } elsif ($qname eq "reset" ) {
	$count = 0;
	$send_response = 0;
	$limit = getlimit();
	$rcode = "NOERROR";
	print ("\tlimit: $limit\n");
    } elsif ($qname eq "direct.example.org" ) {
	if ($qtype eq "A") {
	    my ($ttl, $rdata) = (3600, $localaddr);
	    my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
	    push @ans, $rr;
	}
	$rcode = "NOERROR";
    } elsif ($qname eq "indirect1.example.org" ||
	     $qname eq "indirect2.example.org" ||
	     $qname eq "indirect3.example.org" ||
	     $qname eq "indirect4.example.org" ||
	     $qname eq "indirect5.example.org" ||
	     $qname eq "indirect6.example.org" ||
	     $qname eq "indirect7.example.org" ||
	     $qname eq "indirect8.example.org") {
	if (! $send_response) {
	    my $rr = new Net::DNS::RR("$qname 86400 $qclass NS ns1.1.example.org");
	    push @auth, $rr;
	} elsif ($qtype eq "A") {
	    my ($ttl, $rdata) = (3600, $localaddr);
	    my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
	    push @ans, $rr;
	} 
	$rcode = "NOERROR";
    } elsif ($qname =~ /^ns1\.(\d+)\.example\.org$/) {
	my $next = $1 + 1;
	if ($limit == 0 || (! $send_response && $next <= $limit)) {
	    my $rr = new Net::DNS::RR("$1.example.org 86400 $qclass NS ns1.$next.example.org");
	    push @auth, $rr;
	} else {
	    $send_response = 1;
	    if ($qtype eq "A") {
		my ($ttl, $rdata) = (3600, $localaddr);
		my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
		print("\tresponse: $qname $ttl $qclass $qtype $rdata\n");
		push @ans, $rr;
	    }
	}
	$rcode = "NOERROR";
    } else {
	$rcode = "NXDOMAIN";
    }

    # mark the answer as authoritive (by setting the 'aa' flag
    return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
}

GetOptions(
    'port=i' => \$localport,
    'verbose!' => \$verbose,
);

my $ns = Net::DNS::Nameserver->new(
    LocalAddr => $localaddr,
    LocalPort => $localport,
    ReplyHandler => \&reply_handler,
    Verbose => $verbose,
);

$ns->main_loop;
