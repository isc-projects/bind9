#! /usr/local/bin/perl -w
# $Id: generate_normalize_data.pl,v 1.4 2000/09/27 02:55:40 ishisone Exp $
#
# Copyright (c) 2000 Japan Network Information Center.  All rights reserved.
#  
# By using this file, you agree to the terms and conditions set forth bellow.
# 
# 			LICENSE TERMS AND CONDITIONS 
# 
# The following License Terms and Conditions apply, unless a different
# license is obtained from Japan Network Information Center ("JPNIC"),
# a Japanese association, Fuundo Bldg., 1-2 Kanda Ogawamachi, Chiyoda-ku,
# Tokyo, Japan.
# 
# 1. Use, Modification and Redistribution (including distribution of any
#    modified or derived work) in source and/or binary forms is under this
#    License Terms and Conditions.
# 
# 2. Redistribution of source code must retain the copyright notices as they
#    appear in each source code file, this License Terms and Conditions.
# 
# 3. Redistribution in binary form must reproduce the Copyright Notice,
#    this License Terms and Conditions, in the documentation and/or other
#    materials provided with the distribution.  For the purposes of binary
#    distribution the "Copyright Notice" refers to the following language:
#    "Copyright (c) Japan Network Information Center.  All rights reserved."
# 
# 4. Neither the name of JPNIC may be used to endorse or promote products
#    derived from this Software without specific prior written approval of
#    JPNIC.
# 
# 5. Disclaimer/Limitation of Liability: THIS SOFTWARE IS PROVIDED BY JPNIC
#    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
#    PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL JPNIC BE LIABLE
#    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#    OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#    ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
# 
# 6. Indemnification by Licensee
#    Any person or entities using and/or redistributing this Software under
#    this License Terms and Conditions shall defend indemnify and hold
#    harmless JPNIC from and against any and all judgements damages,
#    expenses, settlement liabilities, cost and other liabilities of any
#    kind as a result of use and redistribution of this Software or any
#    claim, suite, action, litigation or proceeding by any third party
#    arising out of or relates to this License Terms and Conditions.
# 
# 7. Governing Law, Jurisdiction and Venue
#    This License Terms and Conditions shall be governed by and and
#    construed in accordance with the law of Japan. Any person or entities
#    using and/or redistributing this Software under this License Terms and
#    Conditions hereby agrees and consent to the personal and exclusive
#    jurisdiction and venue of Tokyo District Court of Japan.
#

# 
# Generate lib/unicodedata.c from UnicodeData.txt and
# CompositionExclusions-1.txt, both available from
# ftp://ftp.unicode.org/Public/UNIDATA/.
#
# Usage: generate_normalize_data.pl UnicodeData.txt CompositionExclusions-1.txt
#

package Unicode::UnicodeData;
use strict;
use integer;
use vars qw(@ISA @EXPORT_OK %EXPORT_TAGS);
use Exporter;
use Carp;

@ISA = qw(Exporter);

@EXPORT_OK = qw(code_value character_name general_category
		canonical_combining_class bidirectional_category
		character_decomposition_mapping
		decimal_digit_value digit_value numeric_value
		mirrored unicode_10_name iso10646_comment_field
		uppercase_mapping lowercase_mapping
		titlecase_mapping composition_exclusion
		specialcasing_source specialcasing_type
		specialcasing_mapping specialcasing_cond);

%EXPORT_TAGS =
    (accessor => [qw(code_value character_name general_category
		     canonical_combining_class bidirectional_category
		     character_decomposition_mapping
		     decimal_digit_value digit_value numeric_value
		     mirrored unicode_10_name iso10646_comment_field
		     uppercase_mapping lowercase_mapping
		     titlecase_mapping composition_exclusion
		     specialcasing_source specialcasing_type
		     specialcasing_mapping specialcasing_cond)]);

my @unicode_data;
my @composition_exclusion;
my %composition_exclusion;
my @unicode_bycode;
my %unicode_byname;
my @specialcasing_data;

sub CODE {0;}
sub NAME {1;}
sub CATEGORY {2;}
sub CLASS {3;}
sub BIDIRECTIONAL {4;}
sub DECOMPOSITION {5;}
sub DECIMAL {6;}
sub DIGIT {7;}
sub NUMERIC {8;}
sub MIRRORED {9;}
sub OLDNAME {10;}
sub COMMENT {11;}
sub UPPERCASE {12;}
sub LOWERCASE {13;}
sub TITLECASE {14;}
sub EXCLUSION {15;}

sub code_value ($) {
    hex((split /;/, $_[0], 2+CODE)[CODE]);
}
sub character_name ($) {
    my $s = (split /;/, $_[0], 2+NAME)[NAME];
}
sub general_category ($) {
    (split /;/, $_[0], 2+CATEGORY)[CATEGORY];
}
sub canonical_combining_class ($) {
    (split /;/, $_[0], 2+CLASS)[CLASS] + 0;
}
sub bidirectional_category ($) {
    (split /;/, $_[0], 2+BIDIRECTIONAL)[BIDIRECTIONAL];
}
sub character_decomposition_mapping ($) {
    dcmap((split /;/, $_[0], 2+DECOMPOSITION)[DECOMPOSITION]);
}
sub decimal_digit_value ($) {
    dvalue((split /;/, $_[0], 2+DECIMAL)[DECIMAL]);
}
sub digit_value ($) {
    dvalue((split /;/, $_[0], 2+DIGIT)[DIGIT]);
}
sub numeric_value ($) {
    dvalue((split /;/, $_[0], 2+NUMERIC)[NUMERIC]);
}
sub mirrored ($) {
    (split /;/, $_[0], 2+MIRRORED)[MIRRORED] eq 'Y';
}
sub unicode_10_name ($) {
    (split /;/, $_[0], 2+OLDNAME)[OLDNAME];
}
sub iso10646_comment_field ($) {
    (split /;/, $_[0], 2+COMMENT)[COMMENT];
}
sub uppercase_mapping ($) {
    ucode((split /;/, $_[0], 2+UPPERCASE)[UPPERCASE]);
}
sub lowercase_mapping ($) {
    ucode((split /;/, $_[0], 2+LOWERCASE)[LOWERCASE]);
}
sub titlecase_mapping ($) {
    ucode((split /;/, $_[0], 2+TITLECASE)[TITLECASE]);
}
sub composition_exclusion($) {
    my $s = shift;
    return 1 if exists $composition_exclusion{code_value($s)};
    my @d = character_decomposition_mapping($s);
    return 0 if @d == 0;	# no decomposition
    return 1 if @d == 2;	# singleton
    my $x = bycode($d[1]);
    defined($x) and canonical_combining_class($x) != 0;	# non-starter
}
sub specialcasing_source($) {
    my $r = shift;
    $r->[0];
}
sub specialcasing_type($) {
    my $r = shift;
    $r->[1];
}
sub specialcasing_mapping($) {
    my $r = shift;
    @{$r->[2]};
}
sub specialcasing_cond($) {
    my $r = shift;
    $r->[3];
}

sub list () {
    init();
    @unicode_data;
}

sub specialcasing_list() {
    specialcasing_init();
    @specialcasing_data;
}

sub script_specific_exclusions () {
    init();
    @composition_exclusion;
}

sub bycode ($) {
    my $code = shift;
    init_bycode();
    ${$unicode_bycode[$code]};
}

sub byname ($) {
    my $name = shift;
    init_byname();
    ${$unicode_byname{$name}};
}

sub grep (&) {
    my $prog = shift;
    init();
    grep {&$prog} @unicode_data;
}

sub init_bycode {
    init();
    return if @unicode_bycode > 0;
    $#unicode_bycode = 65535;
    foreach my $d (@unicode_data) {
	$unicode_bycode[code_value($d)] = \$d;
    }
}

sub init_byname {
    init();
    return if scalar(keys %unicode_byname);
    keys %unicode_byname = 4000;
    foreach my $d (@unicode_data) {
	$unicode_byname{character_name($d)} = \$d;
    }
}

sub init {
    @unicode_data > 0 or croak "Unicode::UnicodeData: not initialized\n";
}

sub specialcasing_init {
    @specialcasing_data > 0
	or croak "Unicode::UnicodeData: not initialized\n";
}

sub initialize {
    my ($data_file, $exclusion_file, $specialcase_file) = @_;
    local $_;

    @unicode_data = ();
    @composition_exclusion = ();
    %composition_exclusion = ();
    @specialcasing_data = ();

    open F, $data_file or croak "cannot open $data_file: $!\n";
    while (<F>) {
	chomp;
	push @unicode_data, $_;
    }

    open F, $exclusion_file or croak "cannot open $exclusion_file: $!\n";
    while (<F>) {
	chomp;
	next if /^#/;
	next if /^\s*$/;
	next unless /^([0-9A-Fa-f]+)/;
	my $n = hex($1);
	push @composition_exclusion, $n;
	$composition_exclusion{$n} = 1;
    }

    open F, $specialcase_file or croak "cannot open $specialcase_file: $!\n";
    while (<F>) {
	chomp;
	last if /\# Locale-sensitive/;	# no locale-dependent mapping
	next if /^#/;
	next if /^\s*$/;
	s/#.*$//;			# remove trailing comment
	s/\s*;\s*/;/g;			# remove spaces around semicolons

	parse_specialcasing_data($_);
    }
}

sub parse_specialcasing_data {
    my $s = shift;
    my @a = split /;/, $_;
    my @cond = ();

    # Check condition.
    if (defined($a[4])) {
	if ($a[4] eq 'FINAL' or $a[4] eq 'NON_FINAL') {
	    push @cond, $a[4];
	} else {
	    croak "Unicode::UnicodeData: unknown special casing condition \"$a[4]\"\n";
	}
    }
    if ($a[0] ne $a[1]) {
	# mapping to lowercase
	my $src = hex($a[0]);
	my @dst = map(hex, split ' ', $a[1]);
	unless (@dst == 1 and @cond == 0 and
		lowercase_mapping(bycode($src)) == $dst[0]) {
	    push @specialcasing_data, [$src, 'L', \@dst, @cond];
	}
    }
    if ($a[0] ne $a[3]) {
	# mapping to uppercase
	my $src = hex($a[0]);
	my @dst = map(hex, split ' ', $a[3]);
	unless (@dst == 1 and @cond == 0 and
	    uppercase_mapping(bycode($src)) == $dst[0]) {
	    push @specialcasing_data, [$src, 'U', \@dst, @cond];
	}
    }
}

sub dcmap {
    my $v = shift;
    return () if $v eq '';
    $v =~ /^(?:(<[^>]+>)\s*)?(\S.*)/
	or die "invalid decomposition mapping \"$v\"";
    my $tag = $1 || '';
    ($tag, map {hex($_)} split(' ', $2));
}

sub ucode {
    my $v = shift;
    return undef if $v eq '';
    hex($v);
}

sub dvalue {
    my $v = shift;
    return undef if $v eq '';
    $v+0;
}

#------------------------------------------------------------------------------

package main;

use strict;
use Data::Dumper;

#use Unicode::UnicodeData qw(:accessor);
import Unicode::UnicodeData qw(:accessor);

my $canon_class_bits = 11;
my $decomp_bits = 10;
my $compose_bits = 11;
my $casemap_bits = 11;
my $context_secsize = 512;

(my $myid = '$Id: generate_normalize_data.pl,v 1.4 2000/09/27 02:55:40 ishisone Exp $') =~ s/\$([^\$]+)\$/\$-$1-\$/;

my $unicodedatafile = shift or usage();
my $exclusionfile = shift or usage();
my $specialcasefile = shift or usage();

Unicode::UnicodeData::initialize($unicodedatafile, $exclusionfile,
				 $specialcasefile);

print <<"END";
/* \$Id\$ */
/* $myid */
/*
 * Do not edit this file!
 * This file is generated from UnicodeData.txt and
 * CompositionExclusions-1.txt.
 *
 */

END

# Actual data generation.
canon_class();
composition();
decomposition();
casemap();
letter_context();

exit;

sub usage {
    die "Usage: $0 unicode-data-file compoisition-exclusion-file special-casing-file\n"
}

#
# composition -- generate data for canonical composition
#
sub composition {
    my @comp_data;
    my $bm = create_bitmap($compose_bits);

    foreach my $r (Unicode::UnicodeData::list) {
	my ($tag, @map) = character_decomposition_mapping($r);
	next unless defined($tag) and $tag eq '';
	next if composition_exclusion($r);

	die "too long decomposition sequence for \"",
	    character_name($r), "\"\n" if @map != 2;

	push @comp_data, [@map, code_value($r)];
	set_bitmap($bm, $map[0]);
    }

    # Hangul composition
    if (0) {
	my $lbase = 0x1100;
	my $lcount = 19;
	my $sbase = 0xac00;
	my $scount = 19 * 21 * 28;
	range_set($bm, $lbase, $lbase + $lcount - 1);
	range_set($bm, $sbase, $sbase + $scount - 1);
    }

    my $bitmap_str = sprint_bitmap($bm);
    my $hash_str = sprint_composition_hash(@comp_data);

    print <<"END";

/*
 * Canonical Composition
 */

#define COMPOSE_BM_SHIFT	(16 - $compose_bits)

static unsigned long compose_bitmap[] = {
$bitmap_str
};

static struct composition compose_seq[] = {
$hash_str
};

END
}

#
# decomposition -- generate data for canonical/compatibility decomposition
#
sub decomposition {
    my @canon_data;
    my @canon_buf;
    my @compat_data;
    my @compat_buf;
    my $canon_bm = create_bitmap($decomp_bits);
    my $compat_bm = create_bitmap($decomp_bits);

    foreach my $r (Unicode::UnicodeData::list) {
	my ($tag, @map) = character_decomposition_mapping($r);
	next unless defined $tag;

	my $n = code_value($r);
	my $is_compat = $tag ne '';

	if ($is_compat) {
	    # compatibility decomposition
	    set_bitmap($compat_bm, $n);
	    push @compat_data, [$n, scalar(@compat_buf), scalar(@map)];
	    push @compat_buf, @map;
	} else {
	    # canonical composition
	    set_bitmap($canon_bm, $n);
	    push @canon_data, [$n, scalar(@canon_buf), scalar(@map)];
	    push @canon_buf, @map;
	}
    }
    # Compatibility decomposition implies canonical decomposition
    $compat_bm = or_bitmap($compat_bm, $canon_bm);

    my $canon_bitmap_str = sprint_bitmap($canon_bm);
    my $compat_bitmap_str = sprint_bitmap($compat_bm);
    my $canon_decomp_hash = sprint_decomposition_hash(@canon_data);
    my $compat_decomp_hash = sprint_decomposition_hash(@compat_data);
    my $canon_data_str = sprint_decomposition_buf(@canon_buf);
    my $compat_data_str = sprint_decomposition_buf(@compat_buf);
    print <<"END";

/*
 * Canonical/Compatibility Decomposition
 */

#define DECOMPOSE_BM_SHIFT	(16 - $decomp_bits)

static unsigned long canon_decompose_bitmap[] = {
$canon_bitmap_str
};

static struct decomposition canon_decompose_seq[] = {
$canon_decomp_hash
};

static unicode_t canon_decompose_data[] = {
$canon_data_str
};

static unsigned long compat_decompose_bitmap[] = {
$compat_bitmap_str
};

static struct decomposition compat_decompose_seq[] = {
$compat_decomp_hash
};

static unicode_t compat_decompose_data[] = {
$compat_data_str
};

END
}

#
# canon_class -- generate data for canonical class
#
sub canon_class {
    my $bm = create_bitmap($canon_class_bits);
    my @cldata;
    my @classes;

    foreach my $r (Unicode::UnicodeData::list) {
	my $class = canonical_combining_class($r);
	next unless $class > 0;
	my $n = code_value($r);
	set_bitmap($bm, $n);
	push @cldata, $n, $class;
    }

    my $bitmap_str = sprint_bitmap($bm);
    my $canon_hash_str = sprint_canon_class_hash(@cldata);

    print <<"END";

/*
 * Canonical Class
 */

#define CANON_CLASS_BM_SHIFT	(16 - $canon_class_bits)

static unsigned long canon_class_bitmap[] = {
$bitmap_str
};

static struct canon_class canon_class[] = {
$canon_hash_str
};

END
}

#
# casemap -- generate data for case mapping
#
sub casemap {
    my (@toupper_data, @tolower_data);
    my $toupper_bm = create_bitmap($casemap_bits);
    my $tolower_bm = create_bitmap($casemap_bits);
    my (@special_toupper_data, @special_tolower_data);
    my @multi_mapping_data = ();

    foreach my $r (Unicode::UnicodeData::list) {
	if (defined uppercase_mapping($r)) {
	    my $n = code_value($r);
	    set_bitmap($toupper_bm, $n);
	    push @toupper_data, $n, uppercase_mapping($r);
	}
	if (defined lowercase_mapping($r)) {
	    my $n = code_value($r);
	    set_bitmap($tolower_bm, $n);
	    push @tolower_data, $n, lowercase_mapping($r);
	}
    }

    foreach my $r (Unicode::UnicodeData::specialcasing_list) {
	my $src = specialcasing_source($r);
	my $type = specialcasing_type($r);
	my @dst = specialcasing_mapping($r);
	my $cond = specialcasing_cond($r);
	my $dst;
	my $len;

	$len = scalar(@dst);
	if ($len == 1) {
	    $dst = $dst[0];
	} else {
	    $dst = scalar(@multi_mapping_data);
	    push @multi_mapping_data, @dst;
	}
	if ($type eq 'L') {
	    # tolower mapping
	    set_bitmap($tolower_bm, $src);
	    push @special_tolower_data, $src, $dst, $len, $cond;
	} elsif ($type eq 'U') {
	    # toupper mapping
	    set_bitmap($toupper_bm, $src);
	    push @special_toupper_data, $src, $dst, $len, $cond;
	} else {
	    die "unknown mapping type \"$type\"\n";
	}
    }

    my $toupper_bitmap_str = sprint_bitmap($toupper_bm);
    my $tolower_bitmap_str = sprint_bitmap($tolower_bm);
    my $toupper_hash_str = sprint_casemap_hash(@toupper_data);
    my $tolower_hash_str = sprint_casemap_hash(@tolower_data);
    my $special_toupper_hash_str =
	sprint_specialcasemap_hash(@special_toupper_data);
    my $special_tolower_hash_str =
	sprint_specialcasemap_hash(@special_tolower_data);
    my $multichar_mapping_str = sprint_decomposition_buf(@multi_mapping_data);

    print <<"END";

/*
 * Flags for special case mapping.
 */
#define CMF_MULTICHAR	0x1
#define CMF_FINAL	0x2
#define CMF_NONFINAL	0x4
#define CMF_CTXDEP	(CMF_FINAL|CMF_NONFINAL)

/*
 * Lowercase <-> Uppercase mapping
 */

#define CASEMAP_BM_SHIFT	(16 - $casemap_bits)

static unsigned long toupper_bitmap[] = {
$toupper_bitmap_str
};

static struct casemap toupper_map[] = {
	/* non-conditional one-to-one mapping */
$toupper_hash_str
	/* conditional or one-to-many mapping */
$special_toupper_hash_str
};

static unsigned long tolower_bitmap[] = {
$tolower_bitmap_str
};

static struct casemap tolower_map[] = {
	/* non-conditional one-to-one mapping */
$tolower_hash_str
	/* conditional or one-to-many mapping */
$special_tolower_hash_str
};

static unicode_t multichar_casemap_data[] = {
$multichar_mapping_str
};
END
}

#
# letter_context -- gerarate data for determining context (final/non-final)
#
sub letter_context {
    my @ctx_data = ();
    my $letter_bit = 1;
    my $nspmark_bit = 2;
    foreach my $r (Unicode::UnicodeData::list) {
	my $cat = general_category($r);
	if ($cat =~ /L[ult]/) {
	    push @ctx_data, code_value($r), $letter_bit;
	} elsif ($cat eq 'Mn') {
	    push @ctx_data, code_value($r), $nspmark_bit;
	}
    }

    my @sections;
    while (@ctx_data >= 2) {
	my $code = shift @ctx_data;
	my $type = shift @ctx_data;
	my $sec_idx = int($code / $context_secsize);
	my $sec_off = $code % $context_secsize;

	if (!defined $sections[$sec_idx]) {
	    my $bm = "\0" x ($context_secsize * 2 / 8);
	    $sections[$sec_idx] = \$bm;
	}
	vec(${$sections[$sec_idx]}, $sec_off, 2) = $type;
    }

    my $nsections = 65536 / $context_secsize;

    print <<"END";

/*
 * Cased characters and non-spacing marks (for casemap context)
 */

#define CTX_BLOCK_SZ	$context_secsize
#define CTX_CASED	$letter_bit	/* cased character */
#define CTX_NSM		$nspmark_bit	/* non-spacing mark */

END

    for (my $i = 0; $i < $nsections; $i++) {
	if (defined $sections[$i]) {
	    my $bm_str = sprint_rawbitmap(${$sections[$i]});
	    print <<"END";
static unsigned long casemap_ctx_section$i\[] = {
$bm_str
};

END
	}
    }

    print <<"END";
static unsigned long *casemap_ctx_sections[] = {
END

    for (my $i = 0; $i < $nsections; $i++) {
	if (defined $sections[$i]) {
	    print "\tcasemap_ctx_section$i,\n";
	} else {
	    print "\tNULL,\n";
	}
    }

    print <<"END";
};

END
}

sub sprint_canon_class_hash {
    my $i = 0;
    my $s = '';
    while (@_ > 0) {
	my $code = shift;
	my $class = shift;
	if ($i % 4 == 0) {
	    $s .= "\n" if $i != 0;
	    $s .= "\t";
	}
	$s .= sprintf "{0x%04x, %3d}, ", $code, $class;
	$i++;
    }
    $s;
}

sub sprint_composition_hash {
    my $i = 0;
    my $s = '';
    foreach my $r (@_) {
	if ($i % 2 == 0) {
	    $s .= "\n" if $i != 0;
	    $s .= "\t";
	}
	$s .= sprintf "{0x%04x, 0x%04x, 0x%04x}, ", @{$r};
	$i++;
    }
    $s;
}

sub sprint_decomposition_hash {
    my $i = 0;
    my $s = '';
    foreach my $r (@_) {
	if ($i % 3 == 0) {
	    $s .= "\n" if $i != 0;
	    $s .= "\t";
	}
	$s .= sprintf "{0x%04x, %4d, %2d}, ", @{$r};
	$i++;
    }
    $s;
}

sub sprint_casemap_hash {
    my $i = 0;
    my $s = '';
    while (@_ > 0) {
	my $org = shift;
	my $map = shift;
	if ($i % 4 == 0) {
	    $s .= "\n" if $i != 0;
	    $s .= "\t";
	}
	$s .= sprintf "{0x%04x, 0x%04x}, ", $org, $map;
	$i++;
    }
    $s;
}

sub sprint_specialcasemap_hash {
    my $i = 0;
    my $s = '';
    while (@_ > 0) {
	my $src = shift;
	my $dst = shift;
	my $len = shift;
	my $cond = shift;
	my @flags = ();

	if ($i % 2 == 0) {
	    $s .= "\n" if $i != 0;
	    $s .= "\t";
	}
	$i++;

	if ($len > 1) {
	    push @flags, 'CMF_MULTICHAR';
	}
	if (defined $cond) {
	    if ($cond eq 'FINAL') {
		push @flags, 'CMF_FINAL';
	    } elsif ($cond eq 'NON_FINAL') {
		push @flags, 'CMF_NONFINAL';
	    } else {
		die "unknown case mapping condition \"$cond\"\n";
	    }
	}
	if ($len > 1) {
	    $s .= sprintf "{0x%04x, 0x%04x, %s, %d}, ", $src, $dst,
		(@flags > 0) ? join('|', @flags) : '0', $len;
	} else {
	    $s .= sprintf "{0x%04x, 0x%04x, %s}, ", $src, $dst,
		(@flags > 0) ? join('|', @flags) : '0';
	}
    }
    $s;
}

sub sprint_decomposition_buf {
    my $i = 0;
    my $s = '';
    foreach my $d (@_) {
	if ($i % 10 == 0) {
	    $s .= "\n" if $i != 0;
	    $s .= "\t";
	}
	$s .= sprintf "%5d, ", $d;
	$i++;
    }
    $s;
}

sub create_bitmap {
    my $bits = shift;
    my $shift = 16 - $bits;
    my $bmlen = 1 << ($bits - 3);
    my $bitmap = "\0" x $bmlen;
    [$bitmap, $shift];
}

sub set_bitmap {
    my ($bm, $n) = @_;
    vec($bm->[0], $n >> $bm->[1], 1) = 1;
}

sub range_set {
    my ($bm, $start, $end) = @_;
    my $shift = $bm->[1];
    $start >>= $shift;
    $end >>= $shift;
    vec($bm->[0], $_, 1) = 1 foreach $start .. $end;
}

sub or_bitmap {
    my ($bm1, $bm2) = @_;
    die "incompatible bitmap\n"
	if length($bm1->[0]) != length($bm2->[0]) or $bm1->[1] != $bm2->[1];
    my $bitmap = $bm1->[0] | $bm2->[0];
    [$bitmap, $bm1->[1]];
}

sub sprint_bitmap {
    my $bm = shift;
    my $data = $bm->[0];
    my $i = 0;
    my $s = '';
    foreach my $v (unpack('V*', $data)) {
	if ($i % 4 == 0) {
	    $s .= "\n" if $i != 0;
	    $s .= "\t";
	}
	$s .= sprintf "0x%08x, ", $v;
	$i++;
    }
    $s;
}

sub sprint_rawbitmap {
    my $data = shift;
    my $i = 0;
    my $s = '';
    foreach my $v (unpack('V*', $data)) {
	if ($i % 4 == 0) {
	    $s .= "\n" if $i != 0;
	    $s .= "\t";
	}
	$s .= sprintf "0x%08x, ", $v;
	$i++;
    }
    $s;
}
