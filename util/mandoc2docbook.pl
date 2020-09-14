#!/usr/bin/perl
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

#
# Do a quick-and-dirty conversion of .mandoc man pages to
# DocBook SGML.
#
# Minor hand editing of the output is usually required.
# This has only been tested with library function man pages
# (section 3); it probably does not work well for program
# man pages.
#

print <<\END;
<!DOCTYPE refentry PUBLIC "-//OASIS//DTD DocBook V4.1//EN">
<!--
 - Copyright (C) 2000, 2001  Internet Systems Consortium, Inc. ("ISC")
 -
 - This Source Code Form is subject to the terms of the Mozilla Public
 - License, v. 2.0. If a copy of the MPL was not distributed with this
 - file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<refentry>
<refentryinfo>
END

my $cursection = undef;

my $in_para = 0;

sub begin_para() {
	if (! $in_para) {
		print "<para>\n";
		$in_para = 1;
	}
}
sub end_para() {
	if ($in_para) {
		print "</para>\n";
		$in_para = 0;
	}
}


sub end_section {
	if ($cursection) {
		print "</$cursection>\n"
	}
}

sub section {
	my ($tag) = @_;
	end_para();
	end_section();
	print "<$tag>\n";
	$cursection = $tag;
}

my %tagmap = (
	Er => errorcode,
	Dv => type,
	Pa => filename,
        Li => constant, 		# XXX guess
	Ar => parameter,
	Va => parameter,
);
	    
while (<>) {
	next if m/^\.\\\"/;
	if (/^\.Dd (.*)$/) {
		print "<date>$1<\/date>\n<\/refentryinfo>\n";
		next;
	}
	elsif (/^\.Dt ([^ ]+) ([^ ]+)$/) {
		my $title = lc $1;
		my $volume = $2;
		chomp $volume;
		print <<END;
<refmeta>
<refentrytitle>$title</refentrytitle>
<manvolnum>$volume</manvolnum>
<refmiscinfo>BIND9</refmiscinfo>
</refmeta>
END
		next;
	}
	elsif (/^\.Os (.*)$/) {
		next;
	}
	elsif (/^\.ds (.*)$/) {
		next;
	}
	elsif (/^\.Nm (.*)$/) {
		if ($cursection eq "refnamediv") {
			my $t = $1;
			$t =~ s/ ,$//;
			print "<refname>$t<\/refname>\n";
		} else {
			print "<command>$1<\/command>\n";
		}
		next;
	}
	elsif (/^\.Nd (.*)$/) {
		print "<refpurpose>$1</refpurpose>\n";
		next;
	}
	elsif (/^\.Sh NAME/) { section("refnamediv"); next; }
	elsif (/^\.Sh SYNOPSIS/) { section("refsynopsisdiv"); next; }
	elsif (/^\.Sh (.*)$/) {
		section("refsect1");
		print "<title>$1</title>\n"; next;
	}
	# special: spaces can occur in arg
	elsif (/^\.Fd (.*)$/) {
		$_ = $1;
		s/</&lt;/g;
		s/>/&gt;/g;
		print "<funcsynopsisinfo>$_<\/funcsynopsisinfo>\n";
		next;
	}
	elsif (/^\.Fn (.*?)( ([^"]+))?$/) {
		# special: add parenthesis
		print "<function>$1()<\/function>$3\n";
	}
	elsif (/^\.Op Fl (.*?)( ([^"]+))?$/) {
		# special: add dash
		print "<option>-$1<\/option>$3\n";
	}
	elsif (/^\.Fl (.*?)( ([^"]+))?$/) {
		# special: add dash
		print "<option>-$1<\/option>$3\n";
	}
	elsif (/^\.Ft (.*)$/) {
		print "<funcprototype>\n";		
		print "<funcdef>\n";
		print "$1\n";
		next;
	}
	elsif (/^\.Fa (.*?)( ([^"]+))?$/) {
		if ($cursection eq "refsynopsisdiv") {
			my $t = $1;
			$t =~ s/^"//;
			$t =~ s/"$//;
			print "<paramdef>$t<\/paramdef>\n";
		} else {
			print "<parameter>$1<\/parameter>$3\n";
		}
		next;
	}
	elsif (/^\.Fo (.*)$/) {
		print "<function>$1<\/function></funcdef>\n";
		next;
	}
	elsif (/^\.Xr ([^ ]+) ([^ ]+)( ([^ ]+))?$/) {
		print "<citerefentry>\n";
		print "<refentrytitle>$1</refentrytitle><manvolnum>$2</manvolnum>\n";
		print "</citerefentry>$4\n";
		next;
	}
	elsif (/^\.([A-Z][a-z]) (.*?)( ([^"]+))?$/ && defined($tagmap{$1})) {
		my $tag = $tagmap{$1};
		my $t = $2;
		my $punct = $4;
		$t =~ s/^"//;
		$t =~ s/"$//;
		$t =~ s/</&lt;/g;
		$t =~ s/>/&gt;/g;
		print "<$tag>$t<\/$tag>$punct\n";
		next;
	}
	elsif (/^\.Fc$/) {
		print "</funcprototype>\n";
		next;
	}
	elsif (/^\.Pp$/) {
		end_para();
		begin_para();
	}
	elsif (/^\.Bd /) {
		print "<programlisting>\n";
	}
	elsif (/^\.Ed$/) {
		print "</programlisting>\n";	       
	}
	elsif (/^\.Bl /) {
		print "<variablelist>\n";
	}
	elsif (/^\.El$/) {
		print "</para>\n";
		print "</listitem>\n";		
		print "</variablelist>\n";
	        $in_list = 0;
	}
	elsif (/^\.It .. (.*)$/) {
		if ($in_list) {
			print "</listitem>\n";
		}
		print "<varlistentry><term><constant>$1</constant></term>\n";
		print "<listitem>\n";
		print "<para>\n";
		$in_list = 1;
	}
	elsif (/^\.It Dv (.*)$/) {
		if ($in_list) {
			print "</listitem>\n";
		}
		print "<varlistentry><term><errorcode>$1</errorcode></term>\n";
		print "<listitem>\n";
		print "<para>\n";
		$in_list = 1;
	} else {
		if (/./) {
			begin_para();
		}
		print;
	}
}

end_para();
end_section();
print "</refentry>\n";
