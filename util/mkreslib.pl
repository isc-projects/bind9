#!/usr/bin/perl
#
# Copyright (C) 2000  Internet Software Consortium.
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
# ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
# CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
# PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
# SOFTWARE.

# Run this script from the top of the bind directory to make a res-lib
# distribution

# Don't bother keeping contrib or doc around in the new tarball
system ("rm -rf Makefile contrib doc");
system ("mv src/* src/.??* .");
system ("rmdir src");

# We don't want bin/, conf/, tests/, or OLD/
system ("rm -rf bin conf tests OLD");

# Move the old README away
system ("mv README README.bind8");

# Make a new README
open (README, ">README") || warn "README: $!";
print README <<EOF;
This is the resolver library from BIND 8, provided for legacy software
needing access to these functions.  Programmers of new software are encouraged
to use the new lightweight resolver library instead.

See the README.bind8 file for the original README shipped with BIND 8.
EOF
close (README);

system ("mv CHANGES CHANGES.bind8");
system ("mv INSTALL INSTALL.bind8");

# The following files aren't useful here
system ("rm -rf DNSSEC SUPPORT TODO");

# Massage the Makefile
system ("mv Makefile Makefile.bind8");

open (MAKEIN, "Makefile.bind8") || warn "Makefile.bind8: $!";
open (MAKEOUT, ">Makefile") || warn "Makefile: $!";

while (<MAKEIN>) {
  if (/^SUBDIRS= (.*)$/) {
    $line = $1;
    $line =~ s/bin//;
    print MAKEOUT "SUBDIRS= $line";
    next;
  }
  if (/^links:/) {
    goto DONE;
  }
  print MAKEOUT;
}
DONE:
print MAKEOUT "FRC:\n";
close (MAKEIN);
close (MAKEOUT);

