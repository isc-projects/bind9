#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) Internet Software Consortium.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

#
# Do glue tests.
#

DIGOPTS="+norec -p ${PORT}"

status=0

echo_i "testing that a ccTLD referral gets a full glue set from the root zone"
$DIG $DIGOPTS @10.53.0.1 foo.bar.fi. A >dig.out || status=1
digcomp --lc fi.good dig.out || status=1

echo_i "testing that we find glue A RRs we are authoritative for"
$DIG +norec @10.53.0.1 -p ${PORT} foo.bar.xx. a >dig.out || status=1
$PERL ../digcomp.pl xx.good dig.out || status=1

echo_i "testing that we find glue A/AAAA RRs in the cache"
$DIG +norec @10.53.0.1 -p ${PORT} foo.bar.yy. a >dig.out || status=1
$PERL ../digcomp.pl yy.good dig.out || status=1

echo_i "testing that we don't find out-of-zone glue"
$DIG $DIGOPTS @10.53.0.1 example.net. a > dig.out || status=1
digcomp noglue.good dig.out || status=1

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
