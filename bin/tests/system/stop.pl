#!/usr/bin/perl -w
#
# Copyright (C) 2001  Internet Software Consortium.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
# DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
# FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# $Id: stop.pl,v 1.2 2001/02/14 23:57:33 gson Exp $

# Framework for stopping test servers
# Based on the type of server specified, signal the server to stop, wait
# briefly for it to die, and then kill it if it is still alive.
# If a server is specified, stop it. Otherwise, stop all servers for test.

use strict;
use Cwd 'abs_path';

# Option handling
#   test [server]
#
#   test - name of the test directory
#   server - name of the server directory

my $usage = "usage: $0 test-directory [server-directory]";
my $test = $ARGV[0];
my $server = $ARGV[1];

if (!$test) {
	print "$usage\n";
}
if (!-d $test) {
	print "No test directory: \"$test\"\n";
}
if ($server && !-d $server) {
	print "No server directory: \"$test\"\n";
}

# Global variables
my $testdir = abs_path("$test");

# Stop the server(s)

if ($server) {
	&stop_server($server);
	if ($server !~ /^ans/) {
		sleep 5;
		&kill_server($server);
	}
} else {
	# Determine which servers need to be stopped for this test.
	opendir DIR, $testdir;
	my @files = sort readdir DIR;
	closedir DIR;

	my @ns = grep /^ns[0-9]*$/, @files;
	my @lwresd = grep /^lwresd[0-9]*$/, @files;
	my @ans = grep /^ans[0-9]*$/, @files;

	# Stop the servers we found.
	foreach (@ns, @lwresd, @ans) {
		&stop_server($_);
	}
	sleep 5;
	foreach (@ns, @lwresd) {
		&kill_server($_);
	}
}

# Subroutines

sub stop_server {
	my $server = shift;

	my $pid_file;

	if ($server =~ /^ns/) {
		$pid_file = "named.pid";
	} elsif ($server =~ /^lwresd/) {
		$pid_file = "lwresd.pid";
	} elsif ($server =~ /^ans/) {
		$pid_file = "ans.pid";
	} else {
		print "I:Unknown server type $server\n";
		exit 1;
	}

	#  print "I:stopping server $server\n";

	chdir "$testdir/$server";

	if (-f $pid_file) {
		my $result = kill 'TERM', `cat $pid_file`;
		if ($result != 1) {
			print "I:$server died before a SIGTERM was sent\n";
			unlink $pid_file;
		}
	}
}

sub kill_server {
	my $server = shift;

	my $pid_file;

	if ($server =~ /^ns/) {
		$pid_file = "named.pid";
	} elsif ($server =~ /^lwresd/) {
		$pid_file = "lwresd.pid";
	} else {
		print "I:Unknown server type $server\n";
		exit 1;
	}

	chdir "$testdir/$server";

	if (-f $pid_file) {
		print "I:$server didn't die when sent a SIGTERM\n";
		my $result = kill 'KILL', `cat $pid_file`;
		if ($result != 1) {
			print "I:$server died before a SIGKILL was sent\n";
		}
		unlink $pid_file;
	}
}
