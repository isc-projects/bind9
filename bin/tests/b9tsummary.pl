
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

#
# name of file containing stdout/stderr of host specific autoconf config
#

$ConfigFile	= ".configure";

#
# name of file containing stdout/stderr of host specific make all
#

$BuildFile	= ".build";

#
# name of file containing build problems abstracted from $BuildFile
#

$BuildProblemsFile	= "buildproblems.html";

#
# name of file containing stdout/stderr of host specific make test
#

$TestFile	= ".test";

#
# where the host specific builds take place
#

$HostDir	= "$Home/b9t/hosts";

#
# name of the well known build problems file
# build problems described in this file are ignored
# format is filename\sline\n
#

$WkbpFile	= ".wkbp";

#
# name of the well known test problems file
# test problems described in this file are ignored
# format is: function_name\sassertion_number\n
#

$WktpFile	= ".wktp";

#
# name of file containing perl style regular
# expressions used to identify build problems
# in make output. $1 should, if possible,
# identify the source filename and $2 should,
# if possible, identify the linenumber of the problem
#

$RxFile		= ".b9trx";


# number of fatal build problems
$Nfbp		= 0;

# number of other build problems
$Nobp		= 0;

# number of test problems
$Ntprobs	= 0;

#
# name of host serving the bind9 reports
#

$B9Host		= "status.isc.org";

#
# path to the www accessable bind9 reports directory
#

$B9HomePath	= "/proj/build-reports/bind9";

#
# path to the www accessable bind9 hosts specific directory
#

$B9HostPath	= "$B9HomePath/hosts";

#
# URL of the bind9 report directory
#

$B9HomeURL	= "http://$B9Host/bind9";

#
# URL of the bind9 hosts specific directory
#

$B9HostURL	= "$B9HomeURL/hosts";

#
# initialize the host array
#

open(DEBUG, "> $DebugFile") if ($Debug);

opendir(HDIR, $HostDir);
@entries = readdir(HDIR);
closedir(HDIR);

foreach $entry (@entries) {
	next if $entry =~ /^\.\.*$/;
	next unless -d "$HostDir/$entry";
	push(hosts, $entry);
}

#
# put the page top
#

$when = `date`;
chop $when;

printf("<HTML>\n");
printf("<HEAD>\n");
printf("<TITLE>bind9 status %s</TITLE>\n", $when);
printf("<META HTTP-EQUIV=\"Pragma\" CONTENT=\"no-cache\">\n");
printf("</HEAD>\n");
printf("<BODY BGCOLOR=\"white\">\n");
printf("<P>\n");
printf("<P>\n");
printf("<CENTER>\n");
printf("<TABLE BORDER=0>\n");
printf("\t<TR HEIGHT=36><TD COLSPAN=4>&nbsp</TD></TR>\n");
printf("\t<TR><TD COLSPAN=4 ALIGN=CENTER><FONT SIZE=+1><EM>bind9 status %s</EM></FONT></TD></TR>\n", $when);
printf("\t<TR HEIGHT=36><TD COLSPAN=4>&nbsp</TD></TR>\n");
printf("\t<TR>\n");
printf("\t\t<TD WIDTH=150 ALIGN=LEFT><B>host</EM></B>\n");
printf("\t\t<TD WIDTH=100 ALIGN=LEFT><B>build status</B></TD>\n");
printf("\t\t<TD WIDTH=100 ALIGN=LEFT><B>fatal/other</B></TD>\n");
printf("\t\t<TD WIDTH=100 ALIGN=LEFT><B>test status</B></TD>\n");
printf("\t</TR>\n");
printf("<TR><TD COLSPAN=4><HR></TD></TR>\n");

#
# produce status info for each host
#

foreach $host (sort @hosts) {
	&doHost("$HostDir/$host");
}

#
# output end of page
#

printf("</TABLE>\n");
printf("</CENTER>\n");
printf("</BODY>\n");
printf("</HTML>\n");

close(DEBUG) if ($Debug);

#
# produce status for host @ $hostpath
#

sub doHost {
	local($hostpath) = @_;
	local($entry, $prob, $line, $bstatus, $tstatus);
	local(@junk, $junk, $hostid, $bcolor, $tcolor);
	local(%buildprobs, %testprobs);
	local($severity, $filename, $linenumber, $message, $lastfilename);

	@junk = split(/\//, $hostpath);
	$hostid = $junk[$#junk];

	print DEBUG "Host: $hostid\n" if ($Debug);

	#
	# scan the build and test results files for problems
	#
	$Nfbp = 0;
	$Nobp = 0;
	$Ntprobs = 0;

	%buildprobs = &buildCheck("$hostpath") if (-r "$hostpath/$BuildFile");
	%testprobs = &testCheck("$hostpath") if (-r "$hostpath/$TestFile");

	#
	# then print summary data in html format with links to the raw and processed data
	#

	if (! -r "$hostpath/$BuildFile") {
		$bcolor = "red";
		$bstatus = "not available";
	}
	elsif ($Nfbp) {
		$bcolor = "red";
		$bstatus = "broken";
	}
	else {
		$bcolor = "green";
		$bstatus = "ok";
	}

	if ($Nfbp) {
		$tstatus = "not available";
	}
	elsif ($Ntprobs) {
		$tstatus = "broken";
	}
	else {
		$tstatus = "ok";
	}

	printf("\t<TR>\n");
	printf("\t\t<TD>%s</TD>\n", $hostid);
	if ($bstatus =~ /not available/) {
		printf("\t\t<TD>%s</TD>\n", $bstatus);
		printf("\t\t<TD>&nbsp</TD>\n");
	}
	else {
		printf("\t\t<TD>");
		printf("<A HREF=\"$B9HostURL/$hostid/$BuildFile\"><FONT COLOR=\"%s\">%s</FONT></A>", $bcolor, $bstatus);
		printf("</TD>\n");
		printf("\t\t<TD>");
		printf("<A HREF=\"$B9HostURL/$hostid/$BuildProblemsFile\">%d/%d</A>", $Nfbp, $Nobp);
		printf("</TD>\n");
	}
	if ($tstatus =~ /not available/) {
		printf("\t\t<TD>%s</TD>\n", $tstatus);
	}
	else {
		printf("\t\t<TD><A HREF=\"$B9HostURL/$hostid/$TestFile\">%s</A></TD>\n", $tstatus);
	}
	printf("\t</TR>\n");

	#
	# copy raw data to www-accessable area
	#

	mkdir("$B9HostPath/$hostid", 0755) if (! -d "$B9HostPath/$hostid");
	`cp "$hostpath/$ConfigFile" "$B9HostPath/$hostid"` if (-r "$hostpath/$ConfigFile");
	`cp "$hostpath/$BuildFile"  "$B9HostPath/$hostid"` if (-r "$hostpath/$BuildFile");
	`cp "$hostpath/$TestFile"   "$B9HostPath/$hostid"` if (-r "$hostpath/$TestFile");

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
	local($hostpath) = @_;
	local($filename, $linenumber, $severity);
	local(%probs, %wkbp, @rxset);
	local($matched, $exp, $entry, $ccrx);

	# initialize the well known build problems array, if available
	if (-r "$hostpath/$WkbpFile") {
		open(XXX, "< $hostpath/$WkbpFile");
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
	if (-r "$hostpath/$RxFile") {
		open(XXX, "< $hostpath/$RxFile");
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
	open(XXX, "< $hostpath/$BuildFile");
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
				next;
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
# run thru the test results file for host at $hostpath
# return %probs
#	format key == funcname:assertion_number, value == test_result
# set $Ntprobs as a side effect
#

sub testCheck {
	local($hostpath) = @_;
	local($funcname, $anum, $atext);
	local(%probs);

	$Ntprobs = 0;

	# initialize the well known test problems array
	if (-f "$hostpath/$WktpFile") {
		open(XXX, "< $hostpath/$WktpFile");
		while(<XXX>) {
			next if /^\#/; # skip comments
			chop;
			($funcname, $anum) = split;
			$wktp{"$funcname:$anum"} = 1;
		}
		close(XXX);
	}

	open(XXX, "< $hostpath/$TestFile");
	while (<XXX>) {
		if (/^T:([^:]*):([^:]*):/) {
			$funcname = $1;
			$anum = $2;
			next;
		}
		if (/^A:(.*)$/) {
			$atext = 1;
			next;
		}
		if (/^R:(.*)$/) {
			$result = $1;
			if ($result =~ /FAIL|UNRESOLVED|UNINITIATED/) {
				#
				# skip if in the (ignorable) well known test problems list
				#
				next if defined($wktp{"$funcname:$anum"});
				$probs{"$funcname:$anum"} = $result;
				++$Ntprobs;
			}
		}
	}
	close(XXX);
	return(%probs);
}

sub wbpf {
	local($hostid, %buildprobs) = @_;
	local($prob, $filename, $lastfilename, $linenumber, $severity);
	local(@messageset, $message);

	open(XXX, "> $B9HostPath/$hostid/$BuildProblemsFile");
	printf(XXX "<HTML>\n<HEAD>\n");
	printf(XXX "<META HTTP-EQUIV=\"Pragma\" CONTENT=\"no-cache\">\n");
	printf(XXX "<TITLE>bind9 %s build problems by filename</TITLE>\n", $hostid);
	printf(XXX "</HEAD>\n<BODY BGCOLOR=\"white\">\n");

	foreach $prob (sort keys %buildprobs) {

		($filename, $linenumber, $severity) = split(/\:/, $prob);

		printf(XXX "<P><B>%s</B>\n<BR>\n", $filename) if ($filename ne $lastfilename);

		@messageset = split(/\n/, $buildprobs{$prob});
		foreach $message (@messageset) {
			if ($severity >= $HaltLevel) {
				printf(XXX "<FONT COLOR=\"red\">%s</FONT>\n<BR>\n", $message);
			}
			else {
				printf(XXX "%s\n<BR>\n", $message);
			}
		}
		$lastfilename = $filename;
	}

	printf(XXX "</BODY>\n</HTML>\n");
	close(XXX);
}

