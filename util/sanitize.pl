#!/usr/bin/perl
#
# Copyright (C) 2000  Internet Software Consortium.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
# DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
# FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# $Id: sanitize.pl,v 1.14 2000/12/02 04:13:34 gson Exp $

# Don't try and sanitize this file: NOMINUM_IGNORE

# Go through the directory tree and make sure that all of the files are
# sanitized.
#
# In normal mode, check file, removing code between
#      #ifndef key
# and the accompanying #else or #endif.  Similarly, code in an #else
# clause after an #ifndef test will be removed.  The #else or #endif's
# must appear as:
#      #else /* key */
#      #endif /* key */
# Balance is tested.
# Non-.c/.h files are tested for the existance of NOMINUM_anything anywhere
# in the file, and a warning is generated, unless the string
# NOMINUM_IGNORE appears before NOMINUM_.

# If the string key_DELETE is present, delete the file when the key
# is present.

# If the string key_KEEP is present, delete the file when the key
# is absent.

# Usage:
#  ./sanitize.pl -c     - Check syntax only, don't change anything
#  ./sanitize.pl -kkey  - Sanitize against key
#  ./sanitize.pl -ikey  - Reverse sense of sanitize.
#  ./sanitize.pl -      - Work as a pipe, sanitizing stdin to stdout.
#  ./sanitize.pl file   - Sanitize the specified file.

$makechange = 1;
$debug = 0;
$curkeys = 0;

# States:
#    0 - Outside of test, include code
#    1 - Inside NOMINUM_PUBLIC
#    2 - Inside !NOMINUM_PUBLIC

foreach $arg (@ARGV) {
	$_ = $arg;
	if (/^-c$/i) {
		$makechange = 0;
	}
	elsif (/^-k(.*)$/i) {
		$showon[$curkeys] = 1;
		$state[$curkeys] = 0;
		$key[$curkeys++] = $1;
	}
	elsif (/^-i(.*)$/i) {
		$showon[$curkeys] = 2;
		$state[$curkeys] = 0;
		$key[$curkeys++] = $1;
	}
	elsif (/^-$/i) {
		&runfile("-","-");
	}
#	elsif (/^-a$/i) {
#		&rundir();
#	}
	elsif (/^-d$/i) {
		$debug = 1;
	}
	else {
		&runfile($arg, $arg.".sanitize");
	}
}
exit(0);


sub runfile($) {
	for ($i = 0 ; $i < $curkeys; $i++) {
		$state[$i] = 0;
	}
	$deletefile = 0;

	open(INFILE, $_[0]) || die ("$_[0]");
	open(OUTFILE, ">$_[1]") || die ("$_[1]")
		if ($makechange);
	while (<INFILE>) {
		if (/NOMINUM_IGNORE/) {
			close(INFILE);
			close(OUTFILE);
			unlink($_[1]);
			last;
		}
		$masterstate = 0;
		$intest = 0;
		for ($i = 0 ; $i < $curkeys; $i++) {
			if ((/$key[$i]_DELETE/) &&
			    ($showon[$i] == 1)) {
				close(INFILE);
				close(OUTFILE);
				unlink($_[1]);
				$deletefile = 1;
				goto bailout;
			}
			elsif ((/$key[$i]_KEEP/) &&
			    ($showon[$i] == 2)) {
				close(INFILE);
				close(OUTFILE);
				unlink($_[1]);
				$deletefile = 1;
				goto bailout;
			}
			elsif (/\#.*ifdef.+$key[$i]/) {
				if ($state[$i] != 0) {
					print(STDERR "*** ERROR in file ".
					      "$_[0] line $.: ".
					      "#ifdef within unterminated ".
					      "if[n]def ($key[$i])\n");
					close(INFILE);
					close(OUTFILE) if ($makechange);
					unlink($_[1]);
					goto bailout;
				}
				$masterstate++;
				$state[$i] = 1;
				goto doneline;
			}
			elsif (/\#.*ifndef.+$key[$i]/) {
				if ($state[$i] != 0) {
					print(STDERR "*** ERROR in file ".
					      "$_[0] line $.: ".
					      "#ifndef within unterminated ".
					      "if[n]def ($key[$i])\n");
					close(INFILE);
					close(OUTFILE) if ($makechange);
					unlink($_[1]);
					last;
				}
				$masterstate++;
				$state[$i] = 2;
				goto doneline;

			}
			elsif (/\#.*else.+$key[$i]/) {
				if ($state[$i] == 0) {
					print(STDERR "*** ERROR in file ".
					      "$_[0] line $.: ".
					      "#else without matching ".
					      "#if[n]def. ($key[$i])\n");
					close(INFILE);
					close(OUTFILE) if ($makechange);
					unlink($_[1]);
					last;
				}
				$masterstate++;
				if ($state[$i] == 1) {
					$state[$i] = 2;
				} else {
					$state[$i] = 1;
				}
				goto doneline;
			}
			elsif (/\#.*endif.+$key[$i]/) {
				if ($state[$i] == 0) {
					print(STDERR "*** ERROR in file ".
					      "$_[0] line $.: ".
					      "#endif without matching ".
					      "#if[n]def. ($key[$i])\n");
					close(INFILE);
					close(OUTFILE) if ($makechange);
					unlink($_[1]);
					last;
				}
				$masterstate++;
				$state[$i] = 0;
				goto doneline;
			}
		}
	      doneline:
		for ($i = 0 ; $i < $curkeys; $i++) {
			if ($state[$i] != 0) {
				$intest++;
			}
			if (($state[$i] != 0) &&
			    ($state[$i] != $showon[$i])) {
				$masterstate++;
				last;
			}
		}
		if (($masterstate == 0) && $makechange) {
			if ($intest != 0) {
				if (/^#\+(.*)/) {
				    print(OUTFILE "$1\n");
			    } else {
				    print(OUTFILE);
			    }
			} else {
				print(OUTFILE);
			}
		}
	}
      bailout:
	$masterstate = 0;
	for ($i = 0 ; $i < $curkeys; $i++) {
		if ($state[$i] != 0) {
			print(STDERR "*** ERROR in file $_[0]: ".
			      "file ended with unterminated test.  ".
			      "$key[$i]\n");
			$masterstate++;
		}
	}
	if ($masterstate == 0) {
		close(INFILE);
		close(OUTFILE) if ($makechange);
		if (($_[0] ne "-") && ($makechange)) {
			unlink($_[0]) || die "unlink $_[0]:";
			if (!$deletefile) {
				rename($_[1], $_[0]) ||
					die "rename $_[1] to $_[0]:";
			}
		}
	}
}
