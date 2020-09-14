#! /usr/bin/perl -ws
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# Rudimentary, primarily for use by the developers.
# This just evolved with no serious attempt at making it
# bulletproof or foolproof.  Or pretty even.  Probably would
# have done it differently if it were actually designed as opposed
# to just growing as a multi-tentacled thing as various messages
# were either added or selectively silenced.

use strict;
use vars qw($help $debug);

sub
sortdir() {
  if (-d $::a) {
    if (-d $::b) {
      return ($::a cmp $::b);
    } else {
      return (-1);
    }
  } elsif (-d $::b) {
    return (1);
  } else {
    return ($::a cmp $::b);
  }
}

sub
do_dir($$) {
  my($predir, $dir) = @_;

  my $newdir = $predir ne "" ? "$predir/$dir" : $dir;

  print "================> $newdir\n";

  unless (chdir("$dir")) {
    print "cd $newdir: $1\n";
    return;
  }

  unless (opendir(DIR, ".")) {
    print "opendir $predir/$dir: $!\n";
    return;
  }

  foreach my $entry (sort sortdir readdir(DIR)) {
    next if $entry =~ /^\.\.?$/;

    if (-d $entry) {
      do_dir($newdir, $entry);
      next;
    }

    next if $entry !~ /\.o$/;

    do_file($entry);
  }

  closedir(DIR);

  chdir("..") or
    die "major malfunction: can't chdir to parent dir: $!\n";

  print "================> $predir\n";
}

sub
do_file($) {
  my $objfile = $_[0];
  my ($file, $savesource, $saveobj);
  my ($config_h, $cpp_if, $prefix, $elided, $comment, $prefix_extend, $body);

  unless ($objfile =~ /\.o$/) {
    print "$0: skipping non-object file $objfile\n";
    return;
  }

  ($file = $objfile) =~ s%\.o$%.c%;
  ($savesource = $file) =~ s%$%.save%;
  ($saveobj = $objfile) =~ s%$%.save%;

  if (-f $savesource) {
    print "$savesource exists, skipping\n";
    return;
  }

  unless (-f $file) {
    print "$file does not exist, skipping\n";
    return;
  }

  rename($file, $savesource);
  rename($objfile, $saveobj);

  open(SOURCE, "< $savesource");
  $_ = join('', <SOURCE>);
  close(SOURCE);

  $prefix = '';

  print "$file begin\n" if $debug;

  while (1) {
    eval {
      # Note that only '#include <...>' is checked, not '#include "..."'.
      #     1             23         4            5      6      78
      if (m%(\A\Q$prefix\E((.*\n)*?))(\#include\s+(<.*?>)(.*)\n)((.*\n)*)%) {
        $elided = $5;
        $prefix_extend = $2 . $4;
        $comment = $6;
        $body = $1 . $7;
      } else {
        print "$file end\n" if $debug;
        $elided = "";           # stop processing this file.
      }
    };

    if ($@ ne "") {
      print "$file processing failed: $@\n";
      last;
    }

    last if $elided eq "";

    print STDERR "$file checking $elided\n" if $debug;

    if (! $config_h) {
      $config_h = 1;
      if ($elided ne "<config.h>") {
        print "$file should include <config.h> before any other\n";
      }
    }

    # Always required.
    next if $elided eq "<config.h>";

    # Can mark in the header file when a #include should stay even
    # though it might not appear that way otherwise.
    next if $comment =~ /require|provide|extend|define|contract|explicit/i;

    if ($elided eq "<isc/print.h>") {
      next if m%snprintf%m;
    }

    open(SOURCE, "> $file");
    print SOURCE "$body";
    close(SOURCE);

    print "$file elided $elided, compiling\n" if $debug;

    if (compile($objfile) == 0) {
      if (! defined($cpp_if)) {
        $cpp_if = /^#if/m;
        print "$file has CPP #if(def), doublecheck elision recommendations.\n"
          if $cpp_if;
      }
      print "$file does not need $elided\n";
    } elsif ($elided eq "<string.h>") {
      print "$file prefer <isc/string.h> to <string.h>\n";
    }

  } continue {
    $prefix .= $prefix_extend;
  }

  rename($savesource, $file);
  rename($saveobj, $objfile);
}

sub
compile($) {
  my $obj = $_[0];

  unless ($obj =~ /\.o$/) {
    warn "$obj: not a .o object file\n";
    return;
  }

  my $output = $debug ? "/dev/tty" : "/dev/null";

  open(COMPILE, "make -e $obj 2>&1 >$output |");
  my $stderr_lines = join('', <COMPILE>);
  print $stderr_lines if $debug;
  close(COMPILE);

  unlink($obj);

  return ($stderr_lines ne "");
}

sub
main() {
  $| = 1;

  $0 =~ s%.*/%%;

  die "Usage: $0 [-debug]\n" if $help;

  unless (-f 'configure' && -f 'Makefile') {
    die "$0: run from top of bind9 source tree, after configure has run\n";
  }

  print "========================\n";
  print "building initial objects\n";
  print "========================\n";

  # XXX bleah
  unless (system("make") == 0) {
    die "make all failed, couldn't be sure all objects were generated.\n";
  }

  unless (system("cd bin/tests && make -k all_tests") == 0) {
    warn "make all_tests failed, but pressing on anyway\n";
  }

  print <<EOF;
================================================================
                    starting header elision

WARNING: Since this script only removes one header at a time,
programs might compile fine without the header because another
header provides the required information.  If that header is
also recommend for removal, then removing both of them could
lead to a program that does *not* compile fine.  So the only
way to be sure is to take them all out and then recompile to
see if there are any residual warnings/errors.

Similar, this program is quite ignorant when it comes to CPP
#if/#ifdef.  It might well be that a header file does not
appear to be necessary because the code that depends on it
is not being compiled.  To prevent this program from complaining
about such includes in later runs, put a "Required for ..."
comment on the same line as the #include.
================================================================
EOF

  # XXX gcc-specific
  # Disable builtin memcmp/memcpy/strcmp/strcpy/etc.  When they are
  # available, gcc won't warn about the lack of a prototype in a header
  # file.
  $ENV{'CFLAGS'} = "-fno-builtin";

  do_dir("", ".");
}

main();
