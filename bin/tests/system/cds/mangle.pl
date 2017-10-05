#!/usr/bin/perl
my $re = $ARGV[0];
shift;
while (<>) {
	s{($re)........}{${1}00000000};
	print;
}
