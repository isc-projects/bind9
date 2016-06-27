#!/usr/bin/perl
#
# Copyright (C) 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id$

my $arg;
my $ext;
my $file;

foreach $arg (@ARGV) {
    if ($arg =~ /^\+/) {
        next;
    }
    if ($arg =~ /^-t/) {
        next;
    }
    if ($arg =~ /^ds$/i) {
        $ext = "ds";
        next;
    }
    if ($arg =~ /^dlv$/i) {
        $ext = "dlv";
        next;
    }
    if ($arg =~ /^dnskey$/i) {
        $ext = "dnskey";
        next;
    }
    $file = $arg;
    next;
}

open F, $file . "." . $ext . ".db" || die $!;
while (<F>) {
    print;
}
close F;
