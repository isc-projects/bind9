#!/usr/bin/perl
#
# Copyright (C) 2013  Internet Systems Consortium, Inc. ("ISC")
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

# todos.pl
# This script performs the equivalent of unix2dos on all the files in
# the BIND 9 source tree that require DOS-style newlines when building
# for win32.
#
# Path and directory
use strict;
use File::Find;

sub todos {
	local @ARGV = @_;
	unshift (@ARGV, '-') unless @ARGV;
	while ($ARGV = shift) {
		open(FH, $ARGV);
		binmode(FH);
		my @lines = <FH>;
		close(FH);

		open(FH, ">$ARGV");
		binmode(FH);
		for my $line (@lines) {
			$line =~ s/[\r\n]+$/\r\n/;
			print FH $line;
		}
		close(FH);
	}
}

sub wanted {
	return unless -f && $_ =~ qr/\.(mak|dsp|dsw|txt|bat)$/;
	todos $_;
}

finddepth(\&wanted, "..");
