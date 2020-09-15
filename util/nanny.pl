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

# A simple nanny to make sure named stays running.

$pid_file_location = '/var/run/named.pid';
$nameserver_location = 'localhost';
$dig_program = 'dig';
$named_program =  'named';

fork() && exit();

for (;;) {
  $pid = 0;
  open(FILE, $pid_file_location) || goto restart;
  $pid = <FILE>;
  close(FILE);
  chomp($pid);

  $ps_command = "ps -axw | grep named | grep $pid | grep -v grep |";
  # ps_command MUST end in a pipe (|) character!

  # Make sure there's a named on the pid we just got.  Since there is no
  # good way to test this, use the output from ps.
  open(PIPE, $ps_command) || die($ps_command);
  $line = <PIPE>;
  close(PIPE);
  chomp($line);

  goto restart if ($line eq "");

  $dig_command = "$dig_program +short . \@$nameserver_location > /dev/null";
  $return = system($dig_command);
  goto restart if ($return == 9);

  sleep 30;
  next;

 restart:
  if ($pid != 0) {
    kill 15, $pid;
    sleep 30;
  }
  system ($named_program);
  sleep 120;
}
