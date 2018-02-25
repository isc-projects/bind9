#!/bin/sh
#
# Copyright (C) 2004, 2007, 2010, 2012, 2015, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) 2001  Internet Software Consortium.
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

DIGOPTS="-p ${PORT}"

status=0
n=0

ret=0
n=`expr $n + 1`
echo_i "test master file \$INCLUDE semantics ($n)"
$DIG $DIGOPTS +nostats +nocmd include. axfr @10.53.0.1 >dig.out.$n

echo_i "test master file BIND 8 compatibility TTL and \$TTL semantics ($n)"
$DIG $DIGOPTS +nostats +nocmd ttl2. axfr @10.53.0.1 >>dig.out.$n

echo_i "test of master file RFC1035 TTL and \$TTL semantics ($n)"
$DIG $DIGOPTS +nostats +nocmd ttl2. axfr @10.53.0.1 >>dig.out.$n

$DIFF  dig.out.$n knowngood.dig.out || status=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

ret=0
n=`expr $n + 1`
echo_i "test that the nameserver is running with a missing master file ($n)"
$DIG $DIGOPTS +tcp +noall +answer example soa @10.53.0.2 > dig.out.$n
grep SOA dig.out.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

ret=0
n=`expr $n + 1`
echo_i "test that the nameserver returns SERVFAIL for a missing master file ($n)"
$DIG $DIGOPTS +tcp +all missing soa @10.53.0.2 > dig.out.$n
grep "status: SERVFAIL" dig.out.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

ret=0
n=`expr $n + 1`
echo_i "test owner inheritence after "'$INCLUDE'" ($n)"
$CHECKZONE -Dq example zone/inheritownerafterinclude.db > checkzone.out$n
$DIFF checkzone.out$n zone/inheritownerafterinclude.good || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
