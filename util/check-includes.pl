#! /usr/bin/perl -ws
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

# $Id: check-includes.pl,v 1.3 2000/06/22 22:00:32 tale Exp $

# Rudimentary, primarily for use by the developers.
# This just evolved with no serious attempt at making it
# bulletproof or foolproof.  Or pretty even.  Probably would
# have done it differently if it were actually designed as opposed
# to just growing as a multi-tentacled thing as various messages
# were either added or selectively silenced.

# XXX many warnings should not be made unless the header will be a public file

use strict;
use vars qw($debug);

$0 =~ s%.*/%%;

die "Usage: $0 [-debug] headerfile ...\n" unless @ARGV > 0;

unless (-f 'configure.in') {
  die "$0: run from top of bind9 source tree\n";
}

undef $/;

my @files = @ARGV;

# Outer loop runs once for each file.
for (<>) {
  my ($file, $tmpfile, $objfile);

  $file = shift @files;

  unless ($file =~ /\.h$/) {
    print "$0: skipping non-header file $file\n";
    next;
  }

  die "$0: $file: no such file\n" unless -f $file;

  # header file fragments; ignore
  # XXX rdatastruct itself is moderately tricky.
  next if $file =~ m%/rdatastruct(pre|suf)\.h$%;

  # From external sources; ignore.
  next if $file =~ m%lib/dns/sec/(dnssafe|openssl)%m;

  # Totally wrong platform; ignore.
  next if $file =~ m%lib/isc/win32%;

  ($tmpfile = $file) =~ s%(.*/)?%/tmp/%;
  $tmpfile =~ s/\.h$/.c/;
  ($objfile = $tmpfile) =~ s/\.c$/\.o/;;

  $file =~ m%(.*/)?(.*)/(.*)\.h%;
  my $symbol = uc "\Q$2_$3_H\E";
  $symbol =~ s/\\-/_/g;

  if (! m%^\#ifndef\ $symbol\n
           \#define\ $symbol\ 1\n
           (.*\n)+
           \#endif\ /\*\ $symbol\ \*/\n
           \n*\Z%mx) {
      print "$file has non-conforming wrapper for symbol $symbol\n"
        unless $file =~ m%confparser_p\.h%;
  }

  my $nocomment = '^(?!\s+/?\*)';

  # check use of macros without having included proper header for them.

  if (/^(ISC_LANG_(BEGIN|END)DECLS)$/m && ! m%^#include <isc/lang\.h>$%m) {
    print "$file has $1 without <isc/lang.h>\n";
  }

  if (/$nocomment.*ISC_EVENTCLASS_/m && ! m%^#include <isc/eventclass\.h>%m) {
    print "$file has ISC_EVENTCLASS_ without <isc/eventclass.h>\n"
      unless $file =~ m%isc/eventclass.h%;
  }

  if (/$nocomment.*ISC_RESULTCLASS_/m &&
      ! m%^#include <isc/resultclass\.h>%m) {
    print "$file has ISC_RESULTCLASS_ without <isc/resultclass.h>\n"
      unless $file =~ m%isc/resultclass.h%;
  }

  if (/$nocomment.*ISC_(TRUE|FALSE|TF)\W/m &&
      ! m%^#include <isc/(types|boolean).h>%m) {
    print "$file has ISC_TRUE/FALSE/TF without <isc/(boolean|types).h>\n"
      unless $file =~ m%isc/boolean.h%;
  }

  if (/$nocomment.*ISC_PLATFORM_/m &&
      ! m%^#include <isc/platform.h>%m) {
    print "$file has ISC_PLATFORM_ without <isc/platform.h>\n"
      unless $file =~ m%isc/platform.h%;
  }

  if ($file !~ m%isc/magic\.h$%) {
    print "$file has ISC_MAGIC_VALID without <isc/magic.h>\n"
      if /$nocomment.*ISC_MAGIC_VALID/m && ! m%^#include <isc/magic.h>%m;

    print "$file could use ISC_MAGIC_VALID\n" if /^$nocomment.*->magic ==/m;
  }

  if (/$nocomment.*(ISC|DNS|DST)_R_/m &&
      ! m%^#include <\L$1\E/result.h>%m) {
    print "$file has $1_R_ without <\L$1\E/result.h>\n"
      unless $file =~ m%\L$1\E/result.h%m;
  }

  if (/^$nocomment(?!#define)[a-z].*([a-zA-Z0-9]\([^;]*\);)/m &&
      ! m%^#include <isc/lang.h>%m) {
    print "$file has declarations without <isc/lang.h>\n";
  }

  #
  # First see whether it can be compiled without any additional includes.
  # Only bother doing this for files that will be installed as public
  # headers (thus weeding out, for example, all of the dns/rdata/*/*.h)
  #
  if ($file =~ m%/include/% && system("cp $file $tmpfile") == 0) {
    if (compile($tmpfile, $objfile) != 0) {
      print "$file does not compile stand-alone\n";
    }
  }

  my $prefix = '';
  my ($elided, $comment, $prefix_extend, $body);
  while (1) {
    eval {
      #     1             23         4            5      6      78
      if (m%(\A\Q$prefix\E((.*\n)*?))(\#include .*(<.*?>)(.*)\n)((.*\n)*)%) {
        $elided = $5;
        $prefix_extend = $2 . $4;
        $comment = $6;
        $body = $1 . $7;
      } else {
        $elided = "";           # stop processing this file.
      }
    };

    if ($@ ne "") {
      print "$file processing failed: $@\n";
      last;
    }

    last if $elided eq "";

    print STDERR "$file checking $elided\n" if $debug;

    # Can mark in the header file when a #include should stay even
    # though it might not appear that way otherwise.
    next if $comment =~ /require|provide|extend|define|contract/i;

    #
    # Special exceptions.
    # XXXDCL some of these should be perhaps generalized (ie, look for
    # ISC_(LINK|LIST)_ when using <isc/list.h>.
    # 
    if (($file =~ m%isc/log\.h$% && $elided eq "<syslog.h>") ||
        ($file =~ m%isc/print\.h$% && $elided =~ /^<std(arg|def)\.h>$/) ||
        ($file =~ m%isc/string\.h$% && $elided eq "<string.h>") ||
        ($file =~ m%isc/types\.h$% &&
         $elided =~ m%^<isc/(boolean|int|offset)\.h>$%) ||
        ($file =~ m%isc/netdb\.h$% &&
         $elided =~ m%^<(netdb|isc/net)\.h>$%)) {
      next;
    }

    if ($elided =~ m%^<(isc|dns|dst)/result.h>$%) {
      my $dir = $1;

      if (! /$nocomment.*\U$dir\E_R_/m) {
        unless ($dir eq "isc" && /$nocomment.*isc_result_t/m) {
          # No {foo}_R_, but it is acceptable to include isc/result.h for
          # isc_result_t ... but not both isc/result.h and isc/types.h.
          # The later check will determine isc/result.h to be redundant,
          # so only the ISC_R_ aspect has to be pointed out.
          print "$file has <$dir/result.h> without \U$dir\E_R_\n";
          next;
        }
      } else {
        # There is an {foo}_R_; this is a necessary include.
        next;
      }
    }

    if ($elided eq "<isc/lang.h>") {
      if (! /^ISC_LANG_BEGINDECLS$/m) {
        print "$file includes <isc/lang.h> but has no ISC_LANG_BEGINDECLS\n";
      } elsif (! /^ISC_LANG_ENDDECLS$/m) {
        print "$file has ISC_LANG_BEGINDECLS but no ISC_LANG_ENDDECLS\n";
      } elsif (! /^$nocomment(?!#define)[a-z].*([a-zA-Z0-9]\()/m) {
        print "$file has <isc/lang.h> apparently not function declarations\n";
      }
      next;
    }

    if ($elided eq "<isc/eventclass.h>") {
      if (! /$nocomment.*ISC_EVENTCLASS_/m) {
        print "$file has <isc/eventclass.h> without ISC_EVENTCLASS_\n";
      }
      next;
    }

    if ($elided eq "<isc/resultclass.h>") {
      if (! /$nocomment.*ISC_RESULTCLASS_/m) {
        print "$file has <isc/resultclass.h> without ISC_RESULTCLASS_\n";
      }
      next;
    }

    if ($elided =~ "<(isc|dns)/types.h>") {
      my $dir = $1;
      if (! /^$nocomment.*$dir\_\S+\_t\s/m) {
        print "$file has <$dir/types.h> but apparently no $dir\_*_t uses\n";
      } elsif ($dir ne "isc" && m%^#include <isc/types.h>%m) {
        print "$file has <$dir/types.h> and redundant <isc/types.h>\n";
      }
      # ... otherwise the types.h file is needed for the relevant _t types
      # it defines, even if this header file accidentally picks it up by
      # including another header that itself included types.h.
      # So skip the elision test in any event.
      # XXX would be good to test for files that need types.h but don't
      # include it.
      next;
    }

    if ($elided eq "<isc/boolean.h>") {
      next if /^$nocomment.*ISC_(TRUE|FALSE|TF)\W/m;
    }

    if ($elided eq "<isc/platform.h>") {
      if (! /^$nocomment.*ISC_PLATFORM_/m) {
        print "$file has <isc/platform.h> but no ISC_PLATFORM_\n";
      }
      next;
    }

    if ($elided eq "<isc/magic.h>") {
      if (! /^$nocomment.*ISC_MAGIC_VALID/m) {
        print "$file has <isc/magic.h> but no ISC_MAGIC_VALID\n";
      }
      next;
    }

    open(TMP, "> $tmpfile");
    print TMP "$body";
    close(TMP);

    print "$file elided $elided, compiling\n" if $debug;

    if (compile($tmpfile, $objfile) == 0) {
      print "$file does not need $elided\n";
    }

  } continue {
    $prefix .= $prefix_extend;
  }
}

sub
compile() {
  my ($source, $objfile) = @_;

  my $stderr = $debug ? "" : "2>/dev/null";

  #XXX -Iflags are a pain.  this needs mending.
  system("cc " .
         "-Ilib/isc/include -Ilib/isc/unix/include " .
         "-Ilib/isc/pthreads/include " .
         "-Ilib/dns/include " .
         "-Ilib/dns/sec/dst/include " .
         "-Ilib/omapi/include " .
         "-c $source -o $objfile $stderr");

  unlink($source, $objfile);

  return ($?);
}
