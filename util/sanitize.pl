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

# $Id: sanitize.pl,v 1.6 2000/09/26 23:17:32 bwelling Exp $

# Don't try and sanitize this file: NOMINUM_IGNORE

# Go through the directory tree and make sure that all of the files are
# sanitized.
#
# In normal mode, check file, removing code between
#      #ifndef NOMINUM_PUBLIC
# and the accompanying #else or #endif.  Similarly, code in an #else
# clause after an #ifndef test will be removed.  The #else or #endif's
# must appear as:
#      #else /* NOMINUM_PUBLIC */
#      #endif /* NOMINUM_PUBLIC */
# Balance is tested.
# Non-.c/.h files are tested for the existance of NOMINUM_PUBLIC anywhere
# in the file, and a warning is generated, unless the string
# NOMINUM_IGNORE appears before NOMINUM_PUBLIC.

# If the string NOMINUM_PUBLIC_DELETE is present, delete the file.

# Usage:
#  ./sanitize.pl -c   - Check syntax only, don't change anything
#  ./sanitize.pl -i   - Reverse sense of sanitize.
#  ./sanitize.pl -    - Work as a pipe, sanitizing stdin to stdout.
#  ./sanitize.pl file - Sanitize the specified file.

$makechange = 1;
$state = 0;
$showon = 1;
$debug = 0;
$deletefile = 0;

# States:
#    0 - Outside of test, include code
#    1 - Inside NOMINUM_PUBLIC
#    2 - Inside !NOMINUM_PUBLIC

foreach $arg (@ARGV) {
	$_ = $arg;
	if (/^-c$/i) {
		$makechange = 0;
	}
	elsif (/^-i$/i) {
		$showon = 2;
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
	$state = 0;
	open(INFILE, $_[0]) || die ("$_[0]");
	open(OUTFILE, ">$_[1]") || die ("$_[1]")
		if ($makechange);
	while (<INFILE>) {
		if (/NOMINUM_IGNORE/) {
			close(INFILE);
			close(OUTFILE);
			unlink($_[1]);
			break;
		}
		elsif (/NOMINUM_PUBLIC_DELETE/) {
			close(INFILE);
			close(OUTFILE);
			unlink($_[1]);
			$deletefile = 1;
			break;
		}
		elsif (/\#ifdef.+NOMINUM_PUBLIC/) {
			if ($state != 0) {
				print(STDERR "*** ERROR in file $_[0]".
				      "line $.: ".
				      "#ifdef within unterminated if[n]def\n");
				close(INFILE);
				close(OUTFILE) if ($makechange);
				unlink($_[1]);
				break;
			}
			$state = 1;
		}
		elsif (/\#ifndef.+NOMINUM_PUBLIC/) {
			if ($state != 0) {
				print(STDERR "*** ERROR in file $_[0] ".
				      "line $.: ".
				      "#ifndef within unterminated if[n]def\n");
				close(INFILE);
				close(OUTFILE) if ($makechange);
				unlink($_[1]);
				break;
			}
			$state = 2;
		}
		elsif (/\#else.+NOMINUM_PUBLIC/) {
			if ($state == 0) {
				print(STDERR "*** ERROR in file $_[0] ".
				      "line $.: ".
				      "#else without matching ".
				      "#if[n]def.\n");
				close(INFILE);
				close(OUTFILE) if ($makechange);
				unlink($_[1]);
				break;
			}
			if ($state == 1) {
				$state = 2;
			} else {
				$state = 1;
			}
		}
		elsif (/\#endif.+NOMINUM_PUBLIC/) {
			if ($state == 0) {
				print(STDERR "*** ERROR in file $_[0] line $.: ".
				      "#endif without matching ".
				      "#if[n]def.\n");
				close(INFILE);
				close(OUTFILE) if ($makechange);
				unlink($_[1]);
				break;
			}
			$state = 0;
		}
		elsif (/NOMINUM_PUBLIC/) {
			print(STDERR "*** WARNING in file $_[0] line $.: ".
			      "NOMINUM_PUBLIC outside of ".
			      "#ifdef/#else/#endif.\n");
		}
		else {
			if (($state == 0) || ($state == $showon)) {
				print(OUTFILE) if ($makechange);
			}
		}
	}
	if ($state != 0) {
		print(STDERR "*** ERROR in file $_[0]: ".
		      "file ended with unterminated test.\n");
	} else {
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
