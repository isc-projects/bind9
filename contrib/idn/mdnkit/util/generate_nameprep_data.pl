#! /usr/local/bin/perl -w
# $Id: generate_nameprep_data.pl,v 1.1.2.1 2002/02/08 12:15:46 marka Exp $
#
# Copyright (c) 2001 Japan Network Information Center.  All rights reserved.
#  
# By using this file, you agree to the terms and conditions set forth bellow.
# 
# 			LICENSE TERMS AND CONDITIONS 
# 
# The following License Terms and Conditions apply, unless a different
# license is obtained from Japan Network Information Center ("JPNIC"),
# a Japanese association, Kokusai-Kougyou-Kanda Bldg 6F, 2-3-4 Uchi-Kanda,
# Chiyoda-ku, Tokyo 101-0047, Japan.
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

use v5.6.0;		# for pack('U')
use bytes;

use lib qw(.);

use SparseMap;
use Getopt::Long;

(my $myid = '$Id: generate_nameprep_data.pl,v 1.1.2.1 2002/02/08 12:15:46 marka Exp $') =~ s/\$([^\$]+)\$/\$-$1-\$/;

my @map_bits = (9, 7, 5);
my @proh_bits = (7, 7, 7);
my @unas_bits = (7, 7, 7);

my $dir = '.';

GetOptions('dir=s', \$dir) or die usage();

print_header();

bits_definition("MAP", @map_bits);
bits_definition("PROH", @proh_bits);
bits_definition("UNAS", @unas_bits);

generate_data($_) foreach @ARGV;

sub usage {
    die "Usage: $0 [-dir dir] version..\n";
}

sub generate_data {
    my $version = shift;
    generate_mapdata($version, "$dir/nameprep.$version.map");
    generate_prohibiteddata($version, "$dir/nameprep.$version.prohibited");
    generate_unassigneddata($version, "$dir/nameprep.$version.unassigned");
}

#
# Generate mapping data.
#
sub generate_mapdata {
    my $version = shift;
    my $file = shift;
    my $top = 1;

    my $map = SparseMap::Int->new(BITS => [@map_bits],
				  MAX => 0x110000,
				  MAPALL => 1,
				  DEFAULT => 0);
    open FILE, $file or die "cannot open $file: $!\n";

    my $mapbuf = "\0";	# dummy
    my %maphash = ();
    while (<FILE>) {
	if ($top and /^%\s*SAME-AS\s+(\S+)/) {
	    generate_map_ref($version, $1);
	    close FILE;
	    return;
	}
	$top = 0;
	next if /^\#/;
	next if /^\s*$/;
	register_map($map, \$mapbuf, \%maphash, $_);
    }
    close FILE;
    generate_map($version, $map, \$mapbuf);
}

#
# Generate prohibited character data.
#
sub generate_prohibiteddata {
    my $version = shift;
    my $file = shift;
    my $top = 1;

    my $proh = SparseMap::Bit->new(BITS => [@proh_bits],
				   MAX => 0x110000);
    open FILE, $file or die "cannot open $file: $!\n";
    while (<FILE>) {
	if ($top and /^%\s*SAME-AS\s+(\S+)/) {
	    generate_prohibited_ref($version, $1);
	    close FILE;
	    return;
	}
	$top = 0;
	next if /^\#/;
	next if /^\s*$/;
	register_prohibited($proh, $_);
    }
    close FILE;
    generate_prohibited($version, $proh);
}

#
# Generate unassigned codepoint data.
#
sub generate_unassigneddata {
    my $version = shift;
    my $file = shift;
    my $top = 1;

    my $unas = SparseMap::Bit->new(BITS => [@unas_bits],
				   MAX => 0x110000);
    open FILE, $file or die "cannot open $file: $!\n";
    while (<FILE>) {
	if ($top and /^%\s*SAME-AS\s+(\S+)/) {
	    generate_unassigned_ref($version, $1);
	    close FILE;
	    return;
	}
	$top = 0;
	next if /^\#/;
	next if /^\s*$/;
	register_unassigned($unas, $_);
    }
    close FILE;
    generate_unassigned($version, $unas);
}

sub print_header {
    print <<"END";
/* \$Id\$ */
/* $myid */
/*
 * Do not edit this file!
 * This file is generated from NAMEPREP specification.
 */

END
}

sub bits_definition {
    my $name = shift;
    my @bits = @_;
    my $i = 0;

    foreach my $n (@bits) {
	print "#define ${name}_BITS_$i\t$n\n";
	$i++;
    }
    print "\n";
}

sub register_map {
    my ($map, $bufref, $hashref, $line) = @_;

    my ($from, $to) = split /;/, $line;
    my @fcode = map {hex($_)} split ' ', $from;
    my @tcode = map {hex($_)} split ' ', $to;

    my $utf8 = pack 'U*', @tcode;

    my $offset;
    if (exists $hashref->{$utf8}) {
	$offset = $hashref->{$utf8};
    } else {
	$offset = length $$bufref;
	$$bufref .= $utf8 . "\0";
	$hashref->{$utf8} = $offset;
    }

    die "unrecognized line: $line" if @fcode != 1;
    $map->add($fcode[0], $offset);
}

sub generate_map {
    my ($version, $map, $bufref) = @_;

    $map->fix();

    print $map->cprog(NAME => "nameprep_${version}_map");
    print "\nstatic const unsigned char nameprep_${version}_map_data[] = \{\n";
    print_uchararray($$bufref);
    print "};\n\n";
}

sub generate_map_ref {
    my ($version, $refversion) = @_;
    print <<"END";
#define nameprep_${version}_map_imap	nameprep_${refversion}_map_imap
#define nameprep_${version}_map_table	nameprep_${refversion}_map_table
#define nameprep_${version}_map_data	nameprep_${refversion}_map_data

END
}

sub print_uchararray {
    my @chars = unpack 'C*', $_[0];
    my $i = 0;
    foreach my $v (@chars) {
	if ($i % 12 == 0) {
	    print "\n" if $i != 0;
	    print "\t";
	}
	printf "%3d, ", $v;
	$i++;
    }
    print "\n";
}

sub register_prohibited {
    my $proh = shift;
    register_bitmap($proh, @_);
}

sub register_unassigned {
    my $unas = shift;
    register_bitmap($unas, @_);
}

sub generate_prohibited {
    my ($version, $proh) = @_;
    generate_bitmap($proh, "nameprep_${version}_prohibited");
}

sub generate_prohibited_ref {
    my ($version, $refversion) = @_;
    print <<"END";
#define nameprep_${version}_prohibited_imap	nameprep_${refversion}_prohibited_imap
#define nameprep_${version}_prohibited_bitmap	nameprep_${refversion}_prohibited_bitmap

END
}

sub generate_unassigned {
    my ($version, $unas) = @_;
    generate_bitmap($unas, "nameprep_${version}_unassigned");
}

sub generate_unassigned_ref {
    my ($version, $refversion) = @_;
    print <<"END";
#define nameprep_${version}_unassigned_imap	nameprep_${refversion}_unassigned_imap
#define nameprep_${version}_unassigned_bitmap	nameprep_${refversion}_unassigned_bitmap

END
}

sub register_bitmap {
    my $bm = shift;
    my $line = shift;

    /^([0-9A-Fa-f]+)(?:-([0-9A-Fa-f]+))?/ or die "unrecognized line: $line";
    my $v1 = hex($1);
    my $v2 = defined($2) ? hex($2) : undef;
    if (defined $v2) {
	$bm->add($v1 .. $v2);
    } else {
	$bm->add($v1);
    }
}

sub generate_bitmap {
    my $bm = shift;
    my $name = shift;
    $bm->fix();
    #$map->stat();
    print $bm->cprog(NAME => $name);
}
