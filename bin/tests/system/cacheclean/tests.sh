#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
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

RNDCOPTS="-c ../common/rndc.conf -s 10.53.0.2 -p ${CONTROLPORT}"
DIGOPTS="+nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm \
         +nostat @10.53.0.2 -p ${PORT}"

# fill the cache with nodes from flushtest.example zone
load_cache () {
        # empty all existing cache data
        $RNDC $RNDCOPTS flush

	# load the positive cache entries
	$DIG $DIGOPTS -f - << EOF > /dev/null 2>&1
txt top1.flushtest.example
txt second1.top1.flushtest.example
txt third1.second1.top1.flushtest.example
txt third2.second1.top1.flushtest.example
txt second2.top1.flushtest.example
txt second3.top1.flushtest.example
txt second1.top2.flushtest.example
txt second2.top2.flushtest.example
txt second3.top2.flushtest.example
txt top3.flushtest.example
txt second1.top3.flushtest.example
txt third1.second1.top3.flushtest.example
txt third2.second1.top3.flushtest.example
txt third1.second2.top3.flushtest.example
txt third2.second2.top3.flushtest.example
txt second3.top3.flushtest.example
EOF

	# load the negative cache entries
        # nxrrset:
	$DIG $DIGOPTS a third1.second1.top1.flushtest.example > /dev/null
        # nxdomain:
	$DIG $DIGOPTS txt top4.flushtest.example > /dev/null
        # empty nonterminal:
	$DIG $DIGOPTS txt second2.top3.flushtest.example > /dev/null

	# sleep 2 seconds ensure the TTLs will be lower on cached data
	sleep 2
}

dump_cache () {
        $RNDC $RNDCOPTS dumpdb -cache
        for i in 0 1 2 3 4 5 6 7 8 9
        do
                grep '^; Dump complete$' ns2/named_dump.db > /dev/null && break
                sleep 1
        done
        mv ns2/named_dump.db ns2/named_dump.db.$n
}

clear_cache () {
        $RNDC $RNDCOPTS flush
}

in_cache () {
        ttl=`$DIG $DIGOPTS "$@" | awk '{print $2}'`
        [ -z "$ttl" ] && {
                ttl=`$DIG $DIGOPTS +noanswer +auth "$@" | awk '{print $2}'`
                [ "$ttl" -ge 3599 ] && return 1
                return 0
        }
        [ "$ttl" -ge 3599 ] && return 1
        return 0
}

n=`expr $n + 1`
echo_i "check correctness of routine cache cleaning ($n)"
$DIG $DIGOPTS +tcp +keepopen -b 10.53.0.7 -f dig.batch > dig.out.ns2 || status=1

digcomp --lc dig.out.ns2 knowngood.dig.out || status=1

n=`expr $n + 1`
echo_i "only one tcp socket was used ($n)"
tcpclients=`grep "client 10.53.0.7#[0-9]*:" ns2/named.run | awk '{print $4}' | sort | uniq -c | wc -l`

test $tcpclients -eq 1 || { status=1; echo_i "failed"; }

n=`expr $n + 1`
echo_i "reset and check that records are correctly cached initially ($n)"
ret=0
load_cache
dump_cache
nrecords=`grep flushtest.example ns2/named_dump.db.$n | grep -v '^;' | wc -l`
[ $nrecords -eq 20 ] || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check flushing of the full cache ($n)"
ret=0
clear_cache
dump_cache
nrecords=`grep flushtest.example ns2/named_dump.db.$n | grep -v '^;' | wc -l`
[ $nrecords -eq 0 ] || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check flushing of individual nodes (interior node) ($n)"
ret=0
clear_cache
load_cache
# interior node
in_cache txt top1.flushtest.example || ret=1
$RNDC $RNDCOPTS flushname top1.flushtest.example
in_cache txt top1.flushtest.example && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check flushing of individual nodes (leaf node, under the interior node) ($n)"
ret=0
# leaf node, under the interior node (should still exist)
in_cache txt third2.second1.top1.flushtest.example || ret=1
$RNDC $RNDCOPTS flushname third2.second1.top1.flushtest.example
in_cache txt third2.second1.top1.flushtest.example && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check flushing of individual nodes (another leaf node, with both positive and negative cache entries) ($n)"
ret=0
# another leaf node, with both positive and negative cache entries
in_cache a third1.second1.top1.flushtest.example || ret=1
in_cache txt third1.second1.top1.flushtest.example || ret=1
$RNDC $RNDCOPTS flushname third1.second1.top1.flushtest.example
in_cache a third1.second1.top1.flushtest.example && ret=1
in_cache txt third1.second1.top1.flushtest.example && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check flushing a nonexistent name ($n)"
ret=0
$RNDC $RNDCOPTS flushname fake.flushtest.example || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check flushing of namespaces ($n)"
ret=0
clear_cache
load_cache
# flushing leaf node should leave the interior node:
in_cache txt third1.second1.top1.flushtest.example || ret=1
in_cache txt top1.flushtest.example || ret=1
$RNDC $RNDCOPTS flushtree third1.second1.top1.flushtest.example
in_cache txt third1.second1.top1.flushtest.example && ret=1
in_cache txt top1.flushtest.example || ret=1
in_cache txt second1.top1.flushtest.example || ret=1
in_cache txt third2.second1.top1.flushtest.example || ret=1
$RNDC $RNDCOPTS flushtree second1.top1.flushtest.example
in_cache txt top1.flushtest.example || ret=1
in_cache txt second1.top1.flushtest.example && ret=1
in_cache txt third2.second1.top1.flushtest.example && ret=1

# flushing from an empty node should still remove all its children
in_cache txt second1.top2.flushtest.example || ret=1
$RNDC $RNDCOPTS flushtree top2.flushtest.example
in_cache txt second1.top2.flushtest.example && ret=1
in_cache txt second2.top2.flushtest.example && ret=1
in_cache txt second3.top2.flushtest.example && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check flushing a nonexistent namespace ($n)"
ret=0
$RNDC $RNDCOPTS flushtree fake.flushtest.example || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check the number of cached records remaining ($n)"
ret=0
dump_cache
nrecords=`grep flushtest.example ns2/named_dump.db.$n | grep -v '^;' | wc -l`
[ $nrecords -eq 19 ] || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check the check that flushname of a partial match works ($n)"
ret=0
in_cache txt second2.top1.flushtest.example || ret=1
$RNDC $RNDCOPTS flushtree example
in_cache txt second2.top1.flushtest.example && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check the number of cached records remaining ($n)"
ret=0
dump_cache
nrecords=`grep flushtest.example ns2/named_dump.db.$n | grep -v '^;' | egrep '(TXT|ANY)' |  wc -l`
[ $nrecords -eq 1 ] || { ret=1; echo_i "found $nrecords records expected 1"; }
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
