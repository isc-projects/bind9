# Copyright (C) 1999, 2000  Internet Software Consortium.
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

#
# aggregate reports from all bind9 build environments
# write a summary of results in html format
#

$Debug		= 1;
$Home		= $ENV{"HOME"};
$DebugFile	= "$Home/b9t/b9tsummary.dbg";

#
# level of severity at which a fatal error is considered to have occurred
#

$HaltLevel	= 2;

$Module			= "bind9";
$HttpHostURL		= "http://status.isc.org/$Module/hosts";

# path to directory containing host specific control info
$HomePath		= "$Home/b9t/hosts";
$WkbpFile		= ".wkbp";
$WktpFile		= ".wktp";
$RxFile			= ".b9trx";
$UnameFile		= "uname";

# path to directory containing host specific data files and www reports
$HostPath		= "/proj/build-reports/$Module/hosts";
$ConfigFile		= ".config";
$BuildFile		= ".build";
$TestFile		= ".test";
$TestStatusFile		= "tstatus.html";
$BuildStatusFile	= "bstatus.html";

# number of fatal build problems
$Nfbp		= 0;

# number of other build problems
$Nobp		= 0;

# number of fatal test problems
$Nftp		= 0;

# number of other test problems
$Notp		= 0;

# flag to signal bad test journal format
$BadTest	= 0;
$BadTestReason	= "";

#
# initialize the host array
#

open(DEBUG, "> $DebugFile") if ($Debug);

opendir(HDIR, $HostPath);
@entries = readdir(HDIR);
closedir(HDIR);

foreach $entry (@entries) {
	next if $entry =~ /^\.\.*$/;
	next unless -d "$HostPath/$entry";
	push(hosts, $entry);
}

#
# put the page top
#

$when = `date`;
chop $when;

printf("<?php \$title = \"ISC Status Server\"; ?>\n");
printf("<?php include(\"status-isc-header.inc\") ?>\n");
printf("\n");

printf("<CENTER>\n");
printf("<TABLE BORDER=0>\n");
printf("\t<TR HEIGHT=36><TD COLSPAN=4>&nbsp</TD></TR>\n");
printf("\t<TR><TD COLSPAN=4 ALIGN=CENTER><FONT SIZE=+1><EM>bind9 status %s</EM></FONT></TD></TR>\n", $when);
printf("\t<TR HEIGHT=36><TD COLSPAN=4>&nbsp</TD></TR>\n");
printf("\t<TR>\n");
printf("\t\t<TD WIDTH=150 ALIGN=LEFT><B>host</B></TD>\n");
printf("\t\t<TD WIDTH=100 ALIGN=LEFT><B>build status</B></TD>\n");
printf("\t\t<TD WIDTH=100 ALIGN=LEFT><B>fatal/other</B></TD>\n");
printf("\t\t<TD WIDTH=100 ALIGN=LEFT><B>test status</B></TD>\n");
printf("\t</TR>\n");
printf("<TR><TD COLSPAN=4><HR></TD></TR>\n");

#
# produce status info for each host
#

foreach $host (sort @hosts) {
	&doHost($host);
}

#
# output end of page
#

printf("\n");
printf("</TABLE>\n");
printf("\n");
printf("<?php include(\"isc-footer.inc\") ?>\n");

close(DEBUG) if ($Debug);

#
# produce status for host @ $hostpath
#

sub doHost {
	local($hostid) = @_;
	local($entry, $prob, $line, $bstatus, $tstatus);
	local(@junk, $junk, $hostname, $bcolor, $tcolor);
	local(%buildprobs, %testprobs);
	local($severity, $filename, $linenumber, $message, $lastfilename);

	mkdir("$HostPath/$hostid", 0755) if (! -d "$HostPath/$hostid");

	#
	# get the host name
	#

	$hostname = "n/a";
	if ((-r "$HomePath/$hostid/$UnameFile") && (-s _)) {
		open(XXX, "< $HomePath/$hostid/$UnameFile");
		$junk = <XXX>;
		close(XXX);
		@junk = split(/\s/, $junk);
		$hostname = $junk[1];
		$hostname =~ s/\..*//; 
	}

	print DEBUG "Host: $hostid, Hostname: $hostname\n" if ($Debug);

	#
	# scan the build and test results files for problems
	#

	$Nfbp = 0;
	$Nobp = 0;
	$Nftp = 0;
	$Notp = 0;
	$BadTest = 0;
	$BadTestReason = "";

	if ((-r "$HostPath/$hostid/$BuildFile") && (-s _)) {
		%buildprobs = &buildCheck($hostid);
		if ($Nfbp == 0) {
			$bstatus = "ok";
			$bcolor = "green";

			if ((-r "$HostPath/$hostid/$TestFile") && (-s _)) {
				%testprobs = &testCheck($hostid);
				if ($BadTest) {
					$tstatus = "inspect ($BadTestReason)";
					$tcolor = "blue";
				}
				else {
					if ($Nftp) {
						$tstatus = "fail";
						$tcolor = "red";
					}
					else {
						$tstatus = "pass";
						$tcolor = "green";
					}
				}
			}
			else {
				$tstatus = "none (no journal)";
				$tcolor = "red";
			}
		}
		else {
			$bstatus = "broken";
			$tstatus = "none (build status)";
			$bcolor = "red";
			$tcolor = "black";
		}
	}
	else {
		$bstatus = "none";
		$tstatus = "none (build status)";
		$bcolor = "red";
		$tcolor = "black";
	}

	printf(DEBUG "Host %s(%s) STATUS: bstatus %s, tstatus %s, badtest %d, reason %s\n", $hostid, $hostname, $bstatus, $tstatus, $BadTest, $BadTestReason) if ($Debug);

	printf("\t<TR>\n");
	printf("\t\t<TD><B>%s</B>&nbsp;%s</TD>\n", $hostid, $hostname);
	if ($bstatus =~ /none/) {
		printf("\t\t<TD>%s</TD>\n", $bstatus);
		printf("\t\t<TD>&nbsp</TD>\n");
	}
	else {
		printf("\t\t<TD>");
		printf("<A HREF=\"$HttpHostURL/$hostid/$BuildFile\"><FONT COLOR=\"%s\">%s</FONT></A>", $bcolor, $bstatus);
		printf("</TD>\n");
		printf("\t\t<TD>");
		printf("<A HREF=\"$HttpHostURL/$hostid/$BuildStatusFile\"><FONT COLOR=\"%s\">%d/%d</FONT></A>", $bcolor, $Nfbp, $Nobp);
		printf("</TD>\n");
	}
	if ($tstatus =~ /none/) {
		printf("\t\t<TD><FONT COLOR=\"%s\">%s</FONT></TD>\n", $tcolor, $tstatus);
	}
	else {
		printf("\t\t<TD><A HREF=\"$HttpHostURL/$hostid/$TestStatusFile\"><FONT COLOR=\"%s\">%s</FONT></A></TD>\n", $tcolor, $tstatus);
	}
	printf("\t</TR>\n");

	#
	# write the build problems file
	#

	&wbpf($hostid, %buildprobs) if ($Nfbp + $Nobp);
}

#
# scan the build results file for host at $hostpath for build problems
# return %probs
#	format key == filename:linenumber:severity, content == text of problem line
# set $Nfbp and $Nobp as a side effect
#

sub buildCheck {
	local($hostid) = @_;
	local($filename, $linenumber, $severity);
	local(%probs, %wkbp, @rxset);
	local($matched, $exp, $entry, $ccrx);

	# initialize the well known build problems array, if available
	if (-r "$HomePath/$hostid/$WkbpFile") {
		open(XXX, "< $HomePath/$hostid/$WkbpFile");
		while(<XXX>) {
			next if /^\#/;		# skip comments
			next if /^\s*$/;	# and blank lines
			chop;
			($filename, $linenumber) = split;
			$wkbp{"$filename:$linenumber"} = 1;
		}
		close(XXX);
	}

	# initialize the host specific regex array, if available
	if (-r "$HomePath/$hostid/$RxFile") {
		open(XXX, "< $HomePath/$hostid/$RxFile");
		while(<XXX>) {
			next if /^\#/;		# skip comments
			next if /^\s*$/;	# and blank lines
			chop;
			printf(DEBUG "RX: <%s>\n", $_) if ($Debug);
			push(@rxset, $_);
		}
		close(XXX);
	}

	# scan stdout/stderr of make all for problems
	open(XXX, "< $HostPath/$hostid/$BuildFile");
	while (<XXX>) {

		undef $filename;
		undef $linenumber;
		undef $severity;
		undef $1;
		undef $2;

		$matched = 0;

		chop;

		foreach $entry (@rxset) {
			($severity, $exp) = split(/\s/, $entry, 2);
			if (/$exp/) {
				$filename   = $1 if defined($1);
				$linenumber = $2 if defined($2);
				$matched    = 1;

				last;
			}
		}


		next unless $matched;

		if ($Debug) {
			printf(DEBUG "LINE %d: %s\n", $., $_);
			printf(DEBUG "MATCHES: exp<%s>\tfn<%s>\tln<%s>\tsev<%s>\n", $exp, $filename, $linenumber, $severity);
		}

		if (length($filename) && length($linenumber)) {

			$filename = $1 if ($filename =~ /.*(bind9.*)/);

			# ignore it if its in the well known build problems list
			if (defined($wkbp{"$filename:$linenumber"})) {
				print DEBUG "IGNORED\n" if ($Debug);
				# by convention, ignore all severity 0 problems
				$severity = 0;
			}
		}
		else {
			$filename = "MISC";
			$linenumber = "0";
		}

		# avoid duplicates
		next if (index($probs{"$filename:$linenumber:$severity"}, $_) >= 0);

		$probs{"$filename:$linenumber:$severity"} .= "$_\n";
		if ($severity >= $HaltLevel) {
			++$Nfbp;
		}
		else {
			++$Nobp;
		}
		printf(DEBUG "PROBLEM: fn<%s>\tln<%s>\tsev<%s>\n\n", $filename, $linenumber, $severity) if ($Debug);
	}
	close(XXX);
	return(%probs);
}

#
# run thru the test results file for $hostid
# write the test results file
# return %probs
#	format key == funcname:assertion_number, value == test_result
# set $Nftp and $Notp as a side effect
#

sub testCheck {
	local($hostid) = @_;
	local($funcname, $anum, $atext);
	local(%probs, @junk, $junk);
	local($intest, $intestcase, $inassert, $ininfo, $inresult, $ntestsets);

	# initialize the well known test problems array
	if (-f "$HomePath/$hostid/$WktpFile") {
		open(XXX, "< $HomePath/$hostid/$WktpFile");
		while(<XXX>) {
			next if /^\#/; # skip comments
			chop;
			($funcname, $anum) = split;
			$wktp{"$funcname:$anum"} = 1;
		}
		close(XXX);
	}

	if (! -r "$HostPath/$hostid/$TestFile") {
		$BadTest = 1;
		$BadTestReason = "no journal file";
		printf(DEBUG "No test journal at %s\n", "$hostpath/$TestFile") if ($Debug);
		return;
	}

	$intest = 0;

	open(XXX, "< $HostPath/$hostid/$TestFile");
	open(YYY, "> $HostPath/$hostid/$TestStatusFile");

	printf(YYY "<?php \$title = \"ISC Status Server $hostid Bind9 Test Results\"; ?>\n");
	printf(YYY "<?php include(\"status-isc-header.inc\") ?>\n");
	printf(YYY "\n");

	while (<XXX>) {
		next unless ($_ =~ /^(S|I|T|A|R|E):/);
		chop;

		if (/^S:([^:]*):(Mon|Tue|Wed|Thu|Fri|Sat|Sun)/) {
			$intest = 1;
			$testname = $1;
			++$ntestsets;
			printf(YYY "%s\n<BR>\n", $_);
			next;
		}

		if (/^E:[^:]*:(Mon|Tue|Wed|Thu|Fri|Sat|Sun)/) {
			if ($inresult == 0) {
				# no reported result
				$BadTest = 1;
				$BadTestReason = "E$.";
			}
			$intest = 0;
			printf(YYY "%s\n<BR>\n", $_);
			next;
		}

		if (/^T:([^:]*):([^:]*):/) {
			if ($intest == 0) {
				$BadTest = 1;
				$BadTestReason = "T$.";
			}
			$funcname = $1;
			$anum = $2;
			$intestcase = 1;
			$inassert = 0;
			$ininfo = 0;
			$inresult = 0;
			($junk = $funcname) =~ s/\//\\\//g;
			s/$junk/<B>$1<\/B>/;
			printf(YYY "%s\n<BR>\n", $_);
			next;
		}
		if (/^A:(.*)$/) {
			if (($intest == 0) || ($intestcase == 0) || ($inresult == 1)) {
				$BadTest = 1;
				$BadTestReason = "A$.";
			}
			$atext = $1;
			$inassert = 1;
			s/A:(.*)/A:<FONT COLOR=\"blue\">$1<\/FONT>/;
			printf(YYY "%s\n<BR>\n", $_);
			next;
		}
		if (/^I:(.*)$/) {
			if (($intest == 0) || ($intestcase == 0) || ($inassert == 0)) {
				$BadTest = 1;
				$BadTestReason = "I$.";
			}
			$ininfo = 1;
			s/</\&lt;/g;
			s/>/\&gt;/g;
			printf(YYY "%s\n<BR>\n", $_);
			next;
		}
		if (/^R:(.*)$/) {
			if (($intest == 0) || ($intestcase ==  0) || ($inassert == 0)) {
				$BadTest = 1;
				$BadTestReason = "R:$intest:$intestcase:$inassert:$.";
			}
			$result = $1;
			$inresult = 1;
			if ($result =~ /FAIL|UNRESOLVED|UNINITIATED/) {
				#
				# skip if in the (ignorable) well known test problems list
				#
				if (defined($wktp{"$funcname:$anum"})) {
					++$Notp;
				}
				else {
					$probs{"$funcname:$anum"} = $result;
					++$Nftp;
					s/(FAIL|UNINITIATED)/<FONT COLOR=\"red\">$1<\/FONT>/;
					s/(UNRESOLVED)/<FONT COLOR=\"orange\">$1<\/FONT>/;

				}
			}
			elsif ($result =~ /PASS|UNTESTED/) {
					s/(PASS|UNTESTED)/<FONT COLOR=\"green\">$1<\/FONT>/;
			}
			printf(YYY "%s\n<BR>\n", $_);
			next;
		}
	}
	close(XXX);
	printf(YYY "<?php include(\"isc-footer.inc\") ?>\n");
	close(YYY);

	if ($ntestsets == 0) {
		$BadTest = 1;
		$BadTestReason = "no tests";
	}
	if ($intest) {
		$BadTest = 1;
		$BadTestReason = "incomplete";
	}
	return(%probs);
}

#
# write the build problems file
#

sub wbpf {
	local($hostid, %buildprobs) = @_;
	local($prob, $filename, $lastfilename, $linenumber, $severity);
	local(@messageset, $message);

	open(XXX, "> $HostPath/$hostid/$BuildStatusFile");

	printf(XXX "<?php \$title = \"ISC Status Server $hostid Bind9 Build Problems\"; ?>\n");
	printf(XXX "<?php include(\"status-isc-header.inc\") ?>\n");
	printf(XXX "\n");

	foreach $prob (sort keys %buildprobs) {

		($filename, $linenumber, $severity) = split(/\:/, $prob);

		printf(XXX "<P><B>%s</B>\n<BR>\n", $filename) if ($filename ne $lastfilename);

		@messageset = split(/\n/, $buildprobs{$prob});
		foreach $message (@messageset) {
			if ($severity >= $HaltLevel) {
				printf(XXX "<FONT COLOR=\"red\">%s</FONT>\n<BR>\n", $message);
			}
			elsif ($severity == 0) {
				printf(XXX "<FONT COLOR=\"orange\">%s</FONT>\n<BR>\n", $message);
			}
			else {
				printf(XXX "%s\n<BR>\n", $message);
			}
		}
		$lastfilename = $filename;
	}

	printf(XXX "<?php include(\"isc-footer.inc\") ?>\n");
	close(XXX);
}

