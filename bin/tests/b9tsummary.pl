
#
# aggregate reports from all bind9 build environments
# write a summary of results in html format
#

$Debug		= 1;
$Home		= $ENV{"HOME"};
$DebugFile	= "$Home/b9t/b9tsummary.dbg";

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

$BuildProblemsFile	= ".buildproblems";

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
# in make output
#

$BadRxFile	= ".badrx";

#
# name of file containing perl style regular
# expression identifying cc warning messages
# and allowing extraction of filename into
# $1 and line number into $2
#

$CcrxFile	= ".ccrx";

$Nbprobs	= 0;
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

$B9HomeURL	= "http://$B9Host/support/build-reports/bind9";

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
printf("\t<TR HEIGHT=36><TD COLSPAN=3>&nbsp</TD></TR>\n");
printf("\t<TR><TD COLSPAN=3 ALIGN=CENTER><FONT SIZE=+1><EM>bind9 status %s</EM></FONT></TD></TR>\n", $when);
printf("\t<TR HEIGHT=36><TD COLSPAN=3>&nbsp</TD></TR>\n");
printf("\t<TR>\n");
printf("\t\t<TD WIDTH=150 ALIGN=LEFT><B>host</EM></B>\n");
printf("\t\t<TD WIDTH=150 ALIGN=LEFT><B>build status</B></TD>\n");
printf("\t\t<TD WIDTH=150 ALIGN=LEFT><B>test status</B></TD>\n");
printf("\t</TR>\n");
printf("<TR><TD COLSPAN=3><HR></TD></TR>\n");

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
	local(@junk, $junk, $hostid);
	local(%buildprobs, %testprobs);
	local($filename, $linenumber, $message, $lastfilename);

	@junk = split(/\//, $hostpath);
	$hostid = $junk[$#junk];

	print DEBUG "Host: $hostid\n" if ($Debug);

	#
	# scan the build and test results files for problems
	#
	$Nbprobs = 0;
	$Ntprobs = 0;

	%buildprobs = &buildCheck("$hostpath") if (-r "$hostpath/$BuildFile");
	%testprobs = &testCheck("$hostpath") if (-r "$hostpath/$TestFile");

	#
	# then print summary data in html format with links to the raw and processed data
	#

	if (! -r "$hostpath/$BuildFile") {
		$bstatus = "not available";
	}
	elsif ($Nbprobs) {
		$bstatus = "broken";
	}
	else {
		$bstatus = "ok";
	}

	if ($Nbprobs) {
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
	}
	else {
		printf("\t\t<TD>");
		printf("<A HREF=\"$B9HostURL/$hostid/$BuildFile\">%s</A>", $bstatus);
		if ($bstatus =~ /broken/) {
			printf("&nbsp&nbsp&nbsp<A HREF=\"$B9HostURL/$hostid/$BuildProblemsFile\">(%d)</A>", $Nbprobs);
		}
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

	if ($Nbprobs) {
		open(XXX, "> $B9HostPath/$hostid/$BuildProblemsFile");
		printf(XXX "bind9 %s build problems by filename\n\n", $hostid);
		foreach $prob (sort keys %buildprobs) {
			($filename, $linenumber) = split(/\:/, $prob);
			next if ($filename eq "SYSTEM");
			$message = $buildprobs{$prob};
			if ($filename ne $lastfilename) {
				printf(XXX "%s\n", $filename);
			}
			chop $message ;
			$message =~ s/\n/\n\t/g;
			printf(XXX "\t%s\n", $message);
			$lastfilename = $filename;
		}
		if (defined($buildprobs{"SYSTEM:GENERAL"})) {
			printf(XXX "MISC\n");
			$message = $buildprobs{"SYSTEM:GENERAL"};
			chop $message;
			$message =~ s/\n/\n\t/g;
			printf(XXX "\t%s\n", $message);
		}
		close(XXX);
	}

	&printBuildProblems($hostid, %buildprobs) if ($Debug);
}

#
# scan the build results file for host at $hostpath for build problems
# return %probs
#	format key == filename:linenumber, content == text of problem line
# set $Nbprobs as a side effect
#

sub buildCheck {
	local($hostpath) = @_;
	local(%probs, $filename, $linenumber, $class);
	local(%wkbp, @badrx, $matched, $exp, $ccrx);

	# initialize the well known build problems array, if available
	if (-r "$hostpath/$WkbpFile") {
		open(XXX, "< $hostpath/$WkbpFile");
		while(<XXX>) {
			next if /^\#/; # skip comments
			chop;
			($filename, $linenumber) = split;
			$wkbp{"$filename:$linenumber"} = 1;
		}
		close(XXX);
	}

	# initialize the host specific bad regex array, if available
	if (-r "$hostpath/$BadRxFile") {
		open(XXX, "< $hostpath/$BadRxFile");
		while(<XXX>) {
			next if /^\#/; # skip comments
			chop;
			push(@badrx, $_);
		}
		close(XXX);
	}

	# intitialize the host specific cc messages regex, if available
	if (-r "$hostpath/$CcrxFile") {
		open(XXX, "< $hostpath/$CcrxFile");
		while(<XXX>) {
			next if /^\#/; # skip comments
			$ccrx = $_;
		}
		close(XXX);
		chop($ccrx);
		print DEBUG "ccrx:<$ccrx>\n" if ($Debug);
	}

	# scan stdout/stderr of make all for problems
	open(XXX, "< $hostpath/$BuildFile");
	while (<XXX>) {

		undef $filename;
		undef $linenumber;
		$matched = 0;

		chop;

		#
		# first check for common generic warning messages
		#
		$matched = 1 if (/(([eE]rror)|([wW]arning)|([fF]ail)|([sS]top)|([eE]xit))\s/);

		print DEBUG "matched default: $_\n" if ($Debug && $matched);

		#
		# now check all regexes in @badrx
		#
		if (! $matched) {
			foreach $exp (@badrx) {
				if (/$exp/) {
					print DEBUG "badrx $exp matched: $_\n" if ($Debug);
					$matched = 1;
					last;
				}
			}
		}

		#
		# now check for host specific or generic compiler warnings
		#
		if (defined($ccrx)) {
			if (/$ccrx/) {
				$filename = $1;
				$linenumber = $2;
				$matched = 1;
				print DEBUG "matched ccrx: $_\n" if ($Debug);
			}
		}
		elsif (/\s*"?([^\s]*)"?,?\s*line\s*([0-9]*):/) {
			$filename = $1;
			$filename =~ s/\"//;
			$filename =~ s/,//;
			$linenumber = $2;
			$matched = 1;
		}

		next unless $matched;

		print DEBUG "problem: $_\n" if ($Debug);

		if (defined($filename) && defined($linenumber)) {

			$filename = $1 if ($filename =~ /.*(bind9.*)/);
			# ignore it if its in the well known build problems list
			if (defined($wkbp{"$filename:$linenumber"})) {
				print DEBUG "ignoring build problem\n" if ($Debug);
				next;
			}
		}
		else {
			$filename = "SYSTEM";
			$linenumber = "GENERAL";
		}
		$probs{"$filename:$linenumber"} .= "$_\n";
		++$Nbprobs;
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

sub printBuildProblems {
	local($host, %probs) = @_;
	local($key, $prob, $filename, $linenumber);

	printf(DEBUG "Host:$host\n");
	foreach $key (sort keys %probs) {
		($filename, $linenumber) = split(/:/, $key);
		$prob = $probs{$key};
		printf(DEBUG "%s:%s:%s", $filename, $linenumber, $prob);
	}
	printf(DEBUG "\n");
}

