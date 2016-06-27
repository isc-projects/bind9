#!/usr/bin/perl -w
#
# Copyright (C) 2011, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id$

# Convert a hexdump to binary format.
#
# To convert binary data to the input format for this command,
# use the following:
#
# perl -e 'while (read(STDIN, my $byte, 1)) {
#              print unpack("H2", $byte);
#          }
#          print "\n";' < file > file.in

use strict;
chomp(my $line = <STDIN>);
print pack("H*", $line);
