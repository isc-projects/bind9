#!/usr/bin/perl
#
# Given two CHANGES files, list [bug] entries present in the
# first one but not in the second one.
#

use FileHandle;

$/ = "";

# Read the CHANGES file $fn and return a hash of change
# texts and categories indexed by change number.

sub readfile {
	my ($fn) = @_;
	my $fh = new FileHandle($fn, "r")
	    or die "open: $fn: $!";
	
	my $changes = { };

	my ($changeid, $category);

	while (<$fh>) {
		if (m/---.* released ---/) {
			next;
		} elsif (m/^# /) {
			next;
		} elsif (m/^\s*(\d+)\.\s+\[(\w+)\]/) {
			$changeid = $1;
			$category = $2;
			# print "*** $1 $2\n";
		}
		$changes->{$changeid}->{text} .= $_;
		$changes->{$changeid}->{category} = $category;
	}

	return $changes;
}

@ARGV == 2 or die "usage: $0 changes-file-1 changes-file-2\n";

my $c1 = readfile($ARGV[0]);
my $c2 = readfile($ARGV[1]);

foreach my $c (sort {$a <=> $b} keys %$c1) {
	if ($c1->{$c}->{category} eq "bug" && !exists($c2->{$c})) {
		print $c1->{$c}->{text};
	}
	if ($c1->{$c}->{category} eq "port" && !exists($c2->{$c})) {
		print $c1->{$c}->{text};
	}
}
