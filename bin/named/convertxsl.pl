#!/usr/bin/env perl

use strict;
use warnings;

print 'char msg[] = "';

my $lines = '';

while (<>) {
    chomp;
    $lines .= $_;
}

$lines =~ s/[\ \t]+/ /g;
$lines =~ s/\>\ \</\>\</g;
$lines =~ s/\"/\\\"/g;
print $lines;

print '\\n";', "\n";
