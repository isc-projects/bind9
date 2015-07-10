#!/usr/bin/perl
#
# Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# traffic-xml.pl:
# Parses the XML version of the RSSAC002 traffic stats into a
# normalized format.

use XML::Simple;

my $file = $ARGV[0];

my $ref = XMLin($file);

my $udp = $ref->{traffic}->{udp}->{counters};
foreach $group (@$udp) {
    my $type = "udp " . $group->{type} . " ";
    if (exists $group->{counter}->{name}) {
        print $type . $group->{counter}->{name} . ": " . $group->{counter}->{content} . "\n";
    } else {
        foreach $key (keys $group->{counter}) {
            print $type . $key . ": ". $group->{counter}->{$key}->{content} ."\n";
        }
    }
}

my $tcp = $ref->{traffic}->{tcp}->{counters};
foreach $group (@$tcp) {
    my $type = "tcp " . $group->{type} . " ";
    if (exists $group->{counter}->{name}) {
        print $type . $group->{counter}->{name} . ": " . $group->{counter}->{content} . "\n";
    } else {
        foreach $key (keys $group->{counter}) {
            print $type . $key . ": ". $group->{counter}->{$key}->{content} ."\n";
        }
    }
}
