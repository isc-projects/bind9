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

# Rudimentary, primarily for use by the developers.
# This just evolved with no serious attempt at making it
# bulletproof or foolproof.  Or pretty even.  Probably would
# have done it differently if it were actually designed as opposed
# to just growing as a multi-tentacled thing as various messages
# were either added or selectively silenced.

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
  my ($file, $tmpfile, $elided);

  $file = shift @files;

  unless ($file =~ /\.h$/) {
    print "$0: skipping non-header file $file\n";
    next;
  }

  die "$0: $file: no such file\n" unless -f $file;

  ($tmpfile = $file) =~ s%(.*/)?%/tmp/%;
  $tmpfile =~ s/\.h$/.c/;

  $file =~ m%(.*/)?(.*)/(.*)\.h%;
  my $symbol = uc "\Q$2_$3_H\E";
  $symbol =~ s/\\-/_/g;

  if (! m%^\#ifndef\ $symbol\n
           \#define\ $symbol\ 1\n
           (.*\n)+
           \#endif\ /\*\ $symbol\ \*/\n
           \n*\Z%mx) {
      warn "$file has non-conforming wrapper for symbol $symbol\n";
  }

  my $nocomment = '^(?!.\*)';

  # check use of macros without having included proper header for them.

  if (/^(ISC_LANG_(BEGIN|END)DECLS)$/m && ! m%^#include <isc/lang\.h>$%m) {
    warn "$file has $1 without <isc/lang.h>\n";
  }

  if (/$nocomment.*ISC_EVENTCLASS_/m && ! m%^#include <isc/eventclass\.h>%m) {
    warn "$file has ISC_EVENTCLASS_ without <isc/eventclass.h>\n"
      unless $file =~ m%isc/eventclass.h%;
  }

  if (/$nocomment.*ISC_RESULTCLASS_/m &&
      ! m%^#include <isc/resultclass\.h>%m) {
    warn "$file has ISC_RESULTCLASS_ without <isc/resultclass.h>\n"
      unless $file =~ m%isc/resultclass.h%;
  }

  if (/$nocomment.*ISC_(TRUE|FALSE|TF)\W/m &&
      ! m%^#include <isc/(types|boolean).h>%m) {
    warn "$file has ISC_TRUE/FALSE/TF without <isc/(boolean|types).h>\n"
      unless $file =~ m%isc/boolean.h%;
  }

  if (/$nocomment.*ISC_PLATFORM_/m &&
      ! m%^#include <isc/platform.h>%m) {
    warn "$file has ISC_PLATFORM_ without <isc/platform.h>\n"
      unless $file =~ m%isc/platform.h%;
  }

  if (/$nocomment.*(ISC|DNS|DST)_R_/m &&
      ! m%^#include <\L$1\E/result.h>%m) {
    warn "$file has $1_R_ without <\L$1\E/result.h>\n"
      unless $file =~ m%\L$1\E/result.h%m;
  }

  if (/^$nocomment(?!#define)[a-z].*([a-zA-Z0-9]\([^;]*\);)/m &&
      ! m%^#include <isc/lang.h>%m) {
    warn "$file has declarations without <isc/lang.h>\n";
  }

  my $prefix = '';
  my ($prefix_extend, $body);
  while (1) {
    eval {
      #     1             23         4            5           67
      if (m%(\A\Q$prefix\E((.*\n)*?))(\#include .*(<.*?>).*\n)((.*\n)*)%) {
        $elided = $5;
        $prefix_extend = $2 . $4;
        $body = $1 . $6;
      } else {
        $elided = "";           # stop processing this file.
      }
    };

    if ($@ ne "") {
      warn "$file processing failed: $@\n";
      last;
    }

    last if $elided eq "";

    print STDERR "$file checking $elided\n" if $debug;

    #
    # Special exceptions.
    # XXXDCL some of these should be perhaps generalized (ie, look for
    # ISC_(LINK|LIST)_ when using <isc/list.h>.
    # 
    if (($file =~ m%isc/log\.h$% && $elided eq "<syslog.h>") ||
        ($file =~ m%isc/print\.h$% && $elided =~ /^<std(arg|def)\.h>$/) ||
        ($file =~ m%isc/string\.h$% && $elided eq "<string.h>") ||
        ($file =~ m%isc/net\.h$% &&
         $elided =~ m%<(sys/socket|netinet6?/in6?|arpa/inet|isc/ipv6)\.h>%) ||
        ($file =~ m%isc/types\.h$% &&
         $elided =~ m%^<isc/(boolean|int|offset)\.h>$%) ||
        ($file =~ m%isc/netdb\.h$% &&
         $elided =~ m%^<(netdb|isc/net)\.h>$%) ||
        ($file =~ m%isc/util\.h$% &&
         $elided =~ m%^<(stdio|isc/(assertions|error|list))\.h>$%)) {
      next;
    }

    if ($elided =~ m%^<(isc|dns|dst)/result.h>$%) {
      my $dir = $1;

      if ($file =~ m%/result\.h$% && $dir eq "isc") {
        # This is ok; other result.h files provide isc/result.h explicitly,
        # even though they (usually) don't need it themselves.
        next;
      }

      if (! /$nocomment.*\U$dir\E_R_/m) {
        unless ($dir eq "isc" && /$nocomment.*isc_result_t/m) {
          # No {foo}_R_, but it is acceptable to include isc/result.h for
          # isc_result_t ... but not both isc/result.h and isc/types.h.
          # The later check will determine isc/result.h to be redundant,
          # so only the ISC_R_ aspect has to be pointed out.
          warn "$file has <$dir/result.h> without \U$dir\E_R_\n";
          next;
        }
      }
    }

    if ($elided eq "<isc/lang.h>") {
      if (! /^ISC_LANG_BEGINDECLS$/m) {
        warn "$file includes <isc/lang.h> but has no ISC_LANG_BEGINDECLS\n";
      } elsif (! /^ISC_LANG_ENDDECLS$/m) {
        warn "$file has ISC_LANG_BEGINDECLS but no ISC_LANG_ENDDECLS\n";
      } elsif (! /^$nocomment(?!#define)[a-z].*([a-zA-Z0-9]\()/m) {
        warn "$file has <isc/lang.h> apparently not function declarations\n";
      }
      next;
    }

    if ($elided eq "<isc/eventclass.h>") {
      if (! /$nocomment.*ISC_EVENTCLASS_/m) {
        warn "$file has <isc/eventclass.h> without ISC_EVENTCLASS_\n";
      }
      next;
    }

    if ($elided eq "<isc/resultclass.h>") {
      if (! /$nocomment.*ISC_RESULTCLASS_/m) {
        warn "$file has <isc/resultclass.h> without ISC_RESULTCLASS_\n";
      }
      next;
    }

    if ($elided eq "<isc/types.h>") {
      if (! /^$nocomment.*isc_\S+_t\s/m) {
        warn "$file has <isc/types.h> but apparently no isc_*_t uses\n";
      }
      next;
    }

    if ($elided eq "<isc/boolean.h>") {
      if (! /^$nocomment.*ISC_(TRUE|FALSE|TF)\W/m &&
          ! /^$nocomment.*isc_boolean_t/m) {
        warn "$file has <isc/boolean.h>, no ISC_TRUE/FALSE/TF/isc_boolean_t\n";
      }
      next;
    }

    if ($elided eq "<isc/platform.h>") {
      if (! /^$nocomment.*ISC_PLATFORM_/m) {
        warn "$file has <isc/platform.h> but no ISC_PLATFORM_\n";
      }
      next;
    }

    open(TMP, "> $tmpfile");
    print TMP "$body";
    close(TMP);

    my $objfile = $tmpfile;
    $objfile =~ s/\.c$/\.o/;

    warn "$file elided $elided, compiling\n" if $debug;

    my $stderr = $debug ? "" : "2>/dev/null";

    #XXX -Iflags are a pain.  this needs mending.
    system("cc " .
           "-Ilib/isc/include -Ilib/isc/unix/include " .
           "-Ilib/isc/pthreads/include " .
           "-Ilib/dns/include " .
           "-Ilib/dns/sec/dst/include " .
           "-c $tmpfile -o $objfile $stderr");

    print "$file does not need $elided\n" if ($? == 0);

    unlink($tmpfile, $objfile);

  } continue {
    $prefix .= $prefix_extend;
  }
}
