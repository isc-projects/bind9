#!/usr/bin/perl
my $target = shift;
my $file = shift;
my $mtime = time - (stat $file)[9];
die "bad mtime $mtime"
	unless abs($mtime - $target) < 3;
