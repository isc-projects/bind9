#!/usr/bin/perl -w

use strict;
use Time::Piece;
use Time::Seconds;

exit 1 if (scalar(@ARGV) != 2);

my $actual = Time::Piece->strptime($ARGV[0], '%d-%b-%Y %H:%M:%S.000 %z');
my $expected = Time::Piece->strptime($ARGV[1], '%s') + ONE_WEEK;
my $diff = abs($actual - $expected);

print($diff . "\n");
