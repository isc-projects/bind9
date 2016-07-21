# Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
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

status=0
n=0

n=`expr $n + 1`
echo "I:querying for non-existing zone data ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 -p 5300 a.added.example a > dig.out.ns1.$n || ret=1
grep 'status: REFUSED' dig.out.ns1.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:adding a new zone into default NZD using rndc addzone ($n)"
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 addzone "added.example { type master; file \"added.db\"; };" 2>&1 | sed 's/^/I:ns1 /';
sleep 2

n=`expr $n + 1`
echo "I:querying for existing zone data ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 -p 5300 a.added.example a > dig.out.ns1.$n || ret=1
grep 'status: NOERROR' dig.out.ns1.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:stopping ns1"
$PERL $SYSTEMTESTTOP/stop.pl . ns1

n=`expr $n + 1`
echo "I:dumping _default.nzd to _default.nzf ($n)"
$NZD2NZF ns1/_default.nzd > ns1/_default.nzf || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that _default.nzf contains the expected content ($n)"
grep 'zone added.example { type master; file "added.db"; };' ns1/_default.nzf > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:deleting _default.nzd database"
rm -f ns1/_default.nzd

echo "I:starting ns1 which should migrate the .nzf to .nzd"
$PERL $SYSTEMTESTTOP/start.pl --noclean --restart . ns1

n=`expr $n + 1`
echo "I:querying for zone data from migrated zone config ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 -p 5300 a.added.example a > dig.out.ns1.$n || ret=1
grep 'status: NOERROR' dig.out.ns1.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
exit $status
