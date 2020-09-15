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

# Massage the output from ISC_MEM_DEBUG to extract mem_get() calls
# with no corresponding mem_put().

$mem_stats = '';

while (<>) {
    $gets{$1.$2} = $_ if (/add (?:0x)?([0-9a-f]+) size (?:0x)?([0-9]+) file/);
    delete $gets{$1.$2} if /del (?:0x)?([0-9a-f]+) size (?:0x)?([0-9]+) file/;
    $mem_stats .= $_ if /\d+ gets, +(\d+) rem/ && $1 > 0;
}
print join('', values %gets);
print $mem_stats;

exit(0);
