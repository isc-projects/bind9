#!/bin/sh
#
# Copyright (C) 2015-2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# touch dnsrps-off to not test with DNSRPS
# touch dnsrps-only to not test with classic RPZ

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh
. $SYSTEMTESTTOP/getopts.sh

status=0

t=0

DEBUG=
DNSRPS_TEST_MODE=	# "" to test with and then without DNSRPS
ARGS=

USAGE="$0: [-x] [-D {1,2}]"
while getopts "xSD:" c; do
    case $c in
	x) set -x; DEBUG=-x; ARGS="$ARGS -x";;
	D) DNSRPS_TEST_MODE="$OPTARG";;		# with or without DNSRPS
	*) echo "$USAGE" 1>&2; exit 1;;
    esac
done
shift `expr $OPTIND - 1 || true`
if test "$#" -ne 0; then
    echo "$USAGE" 1>&2
    exit 1
fi
# really quit on control-C
trap 'exit 1' 1 2 15

DNSRPSCMD=../rpz/dnsrps
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${controlport} -s"

# Run the tests twice, first without DNSRPS and then with if it is available
if [ -z "$DNSRPS_TEST_MODE" ]; then
    if [ -e dnsrps-only ]; then
        echo_i "'dnsrps-only' found: skipping native RPZ sub-test"
    else
        echo_i "running native RPZ sub-test"
        # The "--" between the port specificatiion switches and the argumens
        # to this script are required bacuse of the two-stage parsing: the
        # ports are parsed with the "getopt" statement in getopts.sh, and
        # the "-D" switch with the "getopt" statement in this file.  This
        # parsing also requires that the port switches must be specified first.
	    $SHELL ./$0 -p ${port} -- -D1 $ARGS || status=1
    fi

    if [ -e dnsrps-off ]; then
	echo_i "'dnsrps-off' found: skipping DNSRPS sub-test"
    else
	echo_i "attempting to configure servers with DNSRPS..."
	$SHELL ./setup.sh -p ${port} -- -D $DEBUG
	echo_i `sed -n 's/^## /I:/p' dnsrps.conf`
	if grep '^#fail' dnsrps.conf >/dev/null; then
	    echo_i "exit status: 1"
	    exit 1
	fi
	if test -z "`grep '^#skip' dnsrps.conf`"; then
	    $RNDCCMD 10.53.0.2 reload
	    $RNDCCMD 10.53.0.3 reload
	    $RNDCCMD 10.53.0.2 flush
	    $RNDCCMD 10.53.0.3 flush
	    echo_i "running DNSRPS sub-test"
	    $SHELL ./$0 -p ${port} -- -D2 $ARGS || status=1
        else
            echo_i "DNSRPS sub-test skipped"
	fi
    fi

    echo_i "exit status: $status"
    exit $status
fi

# $1 = test name (such as 1a, 1b, etc. for which named.$1.conf exists)
run_server() {
    TEST_NAME=$1

    echo_i "stopping resolver"
    $PERL $SYSTEMTESTTOP/stop.pl . ns2

    sleep 1

    echo_i "starting resolver using named.$TEST_NAME.conf"
    copy_setports ns2/named.$TEST_NAME.conf ns2/named.conf
    $PERL $SYSTEMTESTTOP/start.pl --noclean --restart . ns2
    sleep 3
}

run_query() {
    TEST_NAME=$1
    LINE=$2

    NAME=`sed -n -e "$LINE,"'$p' ns2/$TEST_NAME.queries | head -n 1`
    $DIG $DIGOPTS $NAME a @10.53.0.2 -p ${port} -b 127.0.0.1 > dig.out.${t}
    grep "status: SERVFAIL" dig.out.${t} > /dev/null 2>&1 && return 1
    return 0
}

# $1 = test name (such as 1a, 1b, etc. for which $1.queries exists)
# $2 = line number in query file to test (the name to query is taken from this line)
expect_norecurse() {
    TEST_NAME=$1
    LINE=$2

    NAME=`sed -n -e "$LINE,"'$p' ns2/$TEST_NAME.queries | head -n 1`
    t=`expr $t + 1`
    echo_i "testing $NAME doesn't recurse (${t})"
    run_query $TEST_NAME $LINE || {
	echo_i "test ${t} failed"
	status=1
    }
}

# $1 = test name (such as 1a, 1b, etc. for which $1.queries exists)
# $2 = line number in query file to test (the name to query is taken from this line)
expect_recurse() {
    TEST_NAME=$1
    LINE=$2

    NAME=`sed -n -e "$LINE,"'$p' ns2/$TEST_NAME.queries | head -n 1`
    t=`expr $t + 1`
    echo_i "testing $NAME recurses (${t})"
    run_query $TEST_NAME $LINE && {
	echo_i "test ${t} failed"
	status=1
    }
}

# show whether and why DNSRPS is enabled or disabled
sed -n 's/^## /I:/p' dnsrps.conf

t=`expr $t + 1`
echo_i "testing that l1.l0 exists without RPZ (${t})"
$DIG $DIGOPTS l1.l0 ns @10.53.0.2 -p ${port} > dig.out.${t}
grep "status: NOERROR" dig.out.${t} > /dev/null 2>&1 || {
    echo_i "test ${t} failed"
    status=1
}

t=`expr $t + 1`
echo_i "testing that l2.l1.l0 returns SERVFAIL without RPZ (${t})"
$DIG $DIGOPTS l2.l1.l0 ns @10.53.0.2 -p ${port} > dig.out.${t}
grep "status: SERVFAIL" dig.out.${t} > /dev/null 2>&1 || {
    echo_i "test ${t} failed"
    status=1
}

# Group 1
run_server 1a
expect_norecurse 1a 1
run_server 1b
expect_norecurse 1b 1
expect_recurse 1b 2
run_server 1c
expect_norecurse 1c 1

# Group 2
run_server 2a
for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32
do
    expect_norecurse 2a $n
done
expect_recurse 2a 33

# Group 3
run_server 3a
expect_recurse 3a 1
run_server 3b
expect_recurse 3b 1
run_server 3c
expect_recurse 3c 1
run_server 3d
expect_norecurse 3d 1
expect_recurse 3d 2
run_server 3e
expect_norecurse 3e 1
expect_recurse 3e 2
run_server 3f
expect_norecurse 3f 1
expect_recurse 3f 2

# Group 4
testlist="aa ap bf"
values="1 16 32"
# Uncomment the following to test every skip value instead of 
# only a sample of values
#
#testlist="aa ab ac ad ae af ag ah ai aj ak al am an ao ap \
#          aq ar as at au av aw ax ay az ba bb bc bd be bf"
#values="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 \
#        21 22 23 24 25 26 27 28 29 30 31 32"
set -- $values
for n in $testlist; do
    run_server 4$n
    ni=$1
    t=`expr $t + 1`
    echo_i "testing that ${ni} of 33 queries skip recursion (${t})"
    c=0
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 \
	     17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33
    do
	run_query 4$n $i
	c=`expr $c + $?`
    done
    skipped=`expr 33 - $c`
    if [ $skipped != $ni ]; then
	echo_i "test $t failed (actual=$skipped, expected=$ni)"
	status=1
    fi
    shift
done

# Group 5
run_server 5a
expect_norecurse 5a 1
expect_norecurse 5a 2
expect_recurse 5a 3
expect_recurse 5a 4
expect_recurse 5a 5
expect_recurse 5a 6

# Group 6
echo_i "check recursive behavior consistency during policy update races"
run_server 6a
sleep 1
t=`expr $t + 1`
echo_i "running dig to cache CNAME record (${t})"
$DIG $DIGOPTS @10.53.0.2 -p ${port} www.test.example.org CNAME > dig.out.${t}
sleep 1
echo_i "suspending authority server"
if [ "$CYGWIN" ]; then
    WINPID=`cat ns1/named.pid`
    PID=`ps | sed 's/^..//' | awk '$4 == '$WINPID | awk '{print $1}'`
else
    PID=`cat ns1/named.pid`
fi
kill -TSTP $PID
echo_i "adding an NSDNAME policy"
cp ns2/db.6a.00.policy.local ns2/saved.policy.local
cp ns2/db.6b.00.policy.local ns2/db.6a.00.policy.local
echo_i "`$RNDCCMD 10.53.0.2 reload 6a.00.policy.local 2>&1 | sed 's/^/ns2 /'`"
test -f dnsrpzd.pid && kill -USR1 `cat dnsrpzd.pid`
sleep 1
t=`expr $t + 1`
echo_i "running dig to follow CNAME (blocks, so runs in the background) (${t})"
$DIG $DIGOPTS @10.53.0.2 -p ${port} www.test.example.org A > dig.out.${t} &
sleep 1
echo_i "removing the NSDNAME policy"
cp ns2/db.6c.00.policy.local ns2/db.6a.00.policy.local
echo_i "`$RNDCCMD 10.53.0.2 reload 6a.00.policy.local 2>&1 | sed 's/^/ns2 /'`"
test -f dnsrpzd.pid && kill -USR1 `cat dnsrpzd.pid`
sleep 1
echo_i "resuming authority server"
if [ "$CYGWIN" ]; then
    WINPID=`cat ns1/named.pid`
    PID=`ps | sed 's/^..//' | awk '$4 == '$WINPID | awk '{print $1}'`
else
    PID=`cat ns1/named.pid`
fi
kill -CONT $PID
for n in 1 2 3 4 5 6 7 8 9; do
    sleep 1
    [ -s dig.out.${t} ] || continue
    grep "status: NOERROR" dig.out.${t} > /dev/null 2>&1 || {
	echo_i "test ${t} failed"
	status=1
    }
done

echo_i "check recursive behavior consistency during policy removal races"
cp ns2/saved.policy.local ns2/db.6a.00.policy.local
run_server 6a
sleep 1
t=`expr $t + 1`
echo_i "running dig to cache CNAME record (${t})"
$DIG $DIGOPTS @10.53.0.2 -p ${port} www.test.example.org CNAME > dig.out.${t}
sleep 1
echo_i "suspending authority server"
if [ "$CYGWIN" ]; then
    WINPID=`cat ns1/named.pid`
    PID=`ps | sed 's/^..//' | awk '$4 == '$WINPID | awk '{print $1}'`
else
    PID=`cat ns1/named.pid`
fi
kill -TSTP $PID
echo_i "adding an NSDNAME policy"
cp ns2/db.6b.00.policy.local ns2/db.6a.00.policy.local
echo_i "`$RNDCCMD 10.53.0.2 reload 6a.00.policy.local 2>&1 | sed 's/^/ns2 /'`"
test -f dnsrpzd.pid && kill -USR1 `cat dnsrpzd.pid`
sleep 1
t=`expr $t + 1`
echo_i "running dig to follow CNAME (blocks, so runs in the background) (${t})"
$DIG $DIGOPTS @10.53.0.2 -p ${port} www.test.example.org A > dig.out.${t} &
sleep 1
echo_i "removing the policy zone"
cp ns2/named.default.conf ns2/named.conf
$RNDCCMD 10.53.0.2 reconfig 2>&1 | sed 's/^/I:ns2 /'
test -f dnsrpzd.pid && kill -USR1 `cat dnsrpzd.pid`
sleep 1
echo_i "resuming authority server"
if [ "$CYGWIN" ]; then
    WINPID=`cat ns1/named.pid`
    PID=`ps | sed 's/^..//' | awk '$4 == '$WINPID | awk '{print $1}'`
else
    PID=`cat ns1/named.pid`
fi
kill -CONT $PID
for n in 1 2 3 4 5 6 7 8 9; do
    sleep 1
    [ -s dig.out.${t} ] || continue
    grep "status: NOERROR" dig.out.${t} > /dev/null 2>&1 || {
	echo_i "test ${t} failed"
	status=1
    }
done

# Check CLIENT-IP behavior
t=`expr $t + 1`
echo_i "testing CLIENT-IP behavior (${t})"
run_server clientip
$DIG $DIGOPTS l2.l1.l0 a @10.53.0.2 -p ${port} -b 10.53.0.4 > dig.out.${t}
grep "status: NOERROR" dig.out.${t} > /dev/null 2>&1 || {
    echo_i "test $t failed: query failed"
    status=1
}
grep "^l2.l1.l0.[ 	]*[0-9]*[ 	]*IN[ 	]*A[ 	]*10.53.0.2" dig.out.${t} > /dev/null 2>&1 || {
    echo_i "test $t failed: didn't get expected answer"
    status=1
}

# Check CLIENT-IP behavior #2
t=`expr $t + 1`
echo_i "testing CLIENT-IP behavior #2 (${t})"
run_server clientip2
$DIG $DIGOPTS l2.l1.l0 a @10.53.0.2 -p ${port} -b 10.53.0.1 > dig.out.${t}.1
grep "status: SERVFAIL" dig.out.${t}.1 > /dev/null 2>&1 || {
    echo_i "test $t failed: query failed"
    status=1
}
$DIG $DIGOPTS l2.l1.l0 a @10.53.0.2 -p ${port} -b 10.53.0.2 > dig.out.${t}.2
grep "status: NXDOMAIN" dig.out.${t}.2 > /dev/null 2>&1 || {
    echo_i "test $t failed: query failed"
    status=1
}
$DIG $DIGOPTS l2.l1.l0 a @10.53.0.2 -p ${port} -b 10.53.0.3 > dig.out.${t}.3
grep "status: NOERROR" dig.out.${t}.3 > /dev/null 2>&1 || {
    echo_i "test $t failed: query failed"
    status=1
}
grep "^l2.l1.l0.[ 	]*[0-9]*[ 	]*IN[ 	]*A[ 	]*10.53.0.1" dig.out.${t}.3 > /dev/null 2>&1 || {
    echo_i "test $t failed: didn't get expected answer"
    status=1
}
$DIG $DIGOPTS l2.l1.l0 a @10.53.0.2 -p ${port} -b 10.53.0.4 > dig.out.${t}.4
grep "status: SERVFAIL" dig.out.${t}.4 > /dev/null 2>&1 || {
    echo_i "test $t failed: query failed"
    status=1
}

# Check RPZ log clause
t=`expr $t + 1`
echo_i "testing RPZ log clause (${t})"
run_server log
cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`
$DIG $DIGOPTS l2.l1.l0 a @10.53.0.2 -p ${port} -b 10.53.0.4 > dig.out.${t}
$DIG $DIGOPTS l2.l1.l0 a @10.53.0.2 -p ${port} -b 10.53.0.3 >> dig.out.${t}
$DIG $DIGOPTS l2.l1.l0 a @10.53.0.2 -p ${port} -b 10.53.0.2 >> dig.out.${t}
sed -n "$cur,"'$p' < ns2/named.run | grep "view recursive: rpz CLIENT-IP Local-Data rewrite l2.l1.l0 via 32.4.0.53.10.rpz-client-ip.log1" > /dev/null && {
    echo_i " failed: unexpected rewrite message for policy zone log1 was logged"
    status=1
}
sed -n "$cur,"'$p' < ns2/named.run | grep "view recursive: rpz CLIENT-IP Local-Data rewrite l2.l1.l0 via 32.3.0.53.10.rpz-client-ip.log2" > /dev/null || {
    echo_i " failed: expected rewrite message for policy zone log2 was not logged"
    status=1
}
sed -n "$cur,"'$p' < ns2/named.run | grep "view recursive: rpz CLIENT-IP Local-Data rewrite l2.l1.l0 via 32.2.0.53.10.rpz-client-ip.log3" > /dev/null || {
    echo_i " failed: expected rewrite message for policy zone log3 was not logged"
    status=1
}

# Check wildcard behavior

t=`expr $t + 1`
echo_i "testing wildcard behavior with 1 RPZ zone (${t})"
run_server wildcard1
$DIG $DIGOPTS www.test1.example.net a @10.53.0.2 -p ${port} > dig.out.${t}.1
grep "status: NXDOMAIN" dig.out.${t}.1 > /dev/null || {
    echo_i "test ${t} failed"
    status=1
}
$DIG $DIGOPTS test1.example.net a @10.53.0.2 -p ${port} > dig.out.${t}.2
grep "status: NXDOMAIN" dig.out.${t}.2 > /dev/null || {
    echo_i "test ${t} failed"
    status=1
}

t=`expr $t + 1`
echo_i "testing wildcard behavior with 2 RPZ zones (${t})"
run_server wildcard2
$DIG $DIGOPTS www.test1.example.net a @10.53.0.2 -p ${port} > dig.out.${t}.1
grep "status: NXDOMAIN" dig.out.${t}.1 > /dev/null || {
    echo_i "test ${t} failed"
    status=1
}
$DIG $DIGOPTS test1.example.net a @10.53.0.2 -p ${port} > dig.out.${t}.2
grep "status: NXDOMAIN" dig.out.${t}.2 > /dev/null || {
    echo_i "test ${t} failed"
    status=1
}

t=`expr $t + 1`
echo_i "testing wildcard behavior with 1 RPZ zone and no non-wildcard triggers (${t})"
run_server wildcard3
$DIG $DIGOPTS www.test1.example.net a @10.53.0.2 -p ${port} > dig.out.${t}.1
grep "status: NXDOMAIN" dig.out.${t}.1 > /dev/null || {
    echo_i "test ${t} failed"
    status=1
}
$DIG $DIGOPTS test1.example.net a @10.53.0.2 -p ${port} > dig.out.${t}.2
grep "status: NOERROR" dig.out.${t}.2 > /dev/null || {
    echo_i "test ${t} failed"
    status=1
}

t=`expr $t + 1`
echo_i "checking 'nsip-wait-recurse no' is faster than 'nsip-wait-recurse yes' ($t)"
echo_i "timing 'nsip-wait-recurse yes' (default)"
ret=0
t1=`$PERL -e 'print time()."\n";'`
$DIG -p ${port} @10.53.0.3 foo.child.example.tld a > dig.out.yes.$t
t2=`$PERL -e 'print time()."\n";'`
p1=`expr $t2 - $t1`
echo_i "elasped time $p1 seconds"

$RNDCCMD 10.53.0.3 flush
copy_setports ns3/named2.conf.in ns3/named.conf
$RNDCCMD 10.53.0.3 reload > /dev/null

echo_i "timing 'nsip-wait-recurse no'"
t3=`$PERL -e 'print time()."\n";'`
$DIG -p ${port} @10.53.0.3 foo.child.example.tld a > dig.out.no.$t
t4=`$PERL -e 'print time()."\n";'`
p2=`expr $t4 - $t3`
echo_i "elasped time $p2 seconds"

if test $p1 -le $p2; then ret=1; fi
if test $ret != 0; then echo_i "failed"; fi
status=`expr $status + $ret`

[ $status -ne 0 ] && pf=fail || pf=pass
case $DNSRPS_TEST_MODE in
        1) echo_i "status (native RPZ sub-test): $status ($pf)";;
        2) echo_i "status (DNSRPS sub-test): $status ($pf)";;
    *) echo_i "invalid test mode";;
esac
[ $status -eq 0 ] || exit 1
