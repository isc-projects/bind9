#!/bin/perl

sub sortlevel() {
	my @options = ();
	my $fin = "";
	my $i = 0;
	while (<>) {
		if (/^\s*};$/) {
			$fin = $_;
			# print 2, $_;
			last;
		}
		next if (/^$/);
		if (/{$/) {
			# print 3, $_;
			my $sec = $_;
			push(@options, $sec . sortlevel());
		} else {
			push(@options, $_);
			# print 1, $_;
		}
		$i++;
	}
	my $result = "";
	foreach my $i (sort @options) {
		$result = ${result}.${i};
		$result = $result."\n" if ($i =~ /^[a-z]/i);
		# print 5, ${i};
	}
	$result = ${result}.${fin};
	return ($result);
}

print sortlevel();
