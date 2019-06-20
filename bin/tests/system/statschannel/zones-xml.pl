#!/usr/bin/perl
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# zones-xml.pl:
# Parses the XML version of the dnssec sign stats for the
# "dnssec" zone in the default view into a normalized format.

use XML::Simple;

my $file = $ARGV[0];

my $ref = XMLin($file);

my $counters = $ref->{views}->{view}->{_default}->{zones}->{zone}->{dnssec}->{counters};

foreach $group (@$counters) {

    my $type = $group->{type};

    if ($type eq "dnssec") {
        my $prefix = "dnskey sign operations ";
        if (exists $group->{counter}->{name}) {
            print $prefix . $group->{counter}->{name} . ": " . $group->{counter}->{content} . "\n";
	} else {
            foreach $key (keys %{$group->{counter}}) {
                print $prefix . $key . ": ". $group->{counter}->{$key}->{content} ."\n";
            }
        }
    }
}
