#!/bin/sh
#
# Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=0

DIGOPTS="@10.53.0.1 -p 5300"

newtest() {
	n=`expr $n + 1`
	echo "${1} (${n})"
	ret=0
}

test_add() {
    host="$1"
    type="$2"
    ip="$3"

    cat <<EOF > ns1/update.txt
server 10.53.0.1 5300
ttl 86400
update add $host $type $ip
send
EOF

    newtest "I:adding $host $type $ip"
    $NSUPDATE ns1/update.txt > /dev/null 2>&1 || {
	[ "$should_fail" ] || \
             echo "I:update failed for $host $type $ip"
	return 1
    }

    out=`$DIG $DIGOPTS +noall +answer -t $type -q $host`
    echo $out > added.a.out.$n
    lines=`echo "$out" | grep "$ip" | wc -l`
    [ $lines -eq 1 ] || {
	[ "$should_fail" ] || \
            echo "I:dig output incorrect for $host $type $cmd: $out"
	return 1
    }

    out=`$DIG $DIGOPTS +noall +answer -x $ip`
    echo $out > added.ptr.out.$n
    lines=`echo "$out" | grep "$host" | wc -l`
    [ $lines -eq 1 ] || {
	[ "$should_fail" ] || \
            echo "I:dig reverse output incorrect for $host $type $cmd: $out"
	return 1
    }

    return 0
}

test_del() {
    host="$1"
    type="$2"

    ip=`$DIG $DIGOPTS +short $host $type`

    cat <<EOF > ns1/update.txt
server 10.53.0.1 5300
update del $host $type
send
EOF

    newtest "I:deleting $host $type (was $ip)"
    $NSUPDATE ns1/update.txt > /dev/null 2>&1 || {
	[ "$should_fail" ] || \
             echo "I:update failed deleting $host $type"
	return 1
    }

    out=`$DIG $DIGOPTS +noall +answer -t $type -q $host`
    echo $out > deleted.a.out.$n
    lines=`echo "$out" | grep "$ip" | wc -l`
    [ $lines -eq 0 ] || {
	[ "$should_fail" ] || \
            echo "I:dig output incorrect for $host $type $cmd: $out"
	return 1
    }

    out=`$DIG $DIGOPTS +noall +answer -x $ip`
    echo $out > deleted.ptr.out.$n
    lines=`echo "$out" | grep "$host" | wc -l`
    [ $lines -eq 0 ] || {
	[ "$should_fail" ] || \
            echo "I:dig reverse output incorrect for $host $type $cmd: $out"
	return 1
    }

    return 0
}

test_add test1.ipv4.example.nil. A "10.53.0.10" || ret=1
status=`expr $status + $ret`

test_add test2.ipv4.example.nil. A "10.53.0.11" || ret=1
status=`expr $status + $ret`

test_add test3.ipv4.example.nil. A "10.53.0.12" || ret=1
status=`expr $status + $ret`

test_add test4.ipv6.example.nil. AAAA "2001:db8::1" || ret=1
status=`expr $status + $ret`

test_del test1.ipv4.example.nil. A || ret=1
status=`expr $status + $ret`

test_del test2.ipv4.example.nil. A || ret=1
status=`expr $status + $ret`

test_del test3.ipv4.example.nil. A || ret=1
status=`expr $status + $ret`

test_del test4.ipv6.example.nil. AAAA || ret=1
status=`expr $status + $ret`

newtest "I:checking parameter logging"
grep "loading params for dyndb 'sample' from .*named.conf:33" ns1/named.run > /dev/null || ret=1
grep "loading params for dyndb 'sample2' from .*named.conf:34" ns1/named.run > /dev/null || ret=1
status=`expr $status + $ret`

echo "I:checking dyndb still works after reload"
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 reload 2>&1 | sed 's/^/I:ns1 /'

test_add test5.ipv4.example.nil. A "10.53.0.10" || ret=1
status=`expr $status + $ret`

test_add test6.ipv6.example.nil. AAAA "2001:db8::1" || ret=1
status=`expr $status + $ret`

test_del test5.ipv4.example.nil. A || ret=1
status=`expr $status + $ret`

test_del test6.ipv6.example.nil. AAAA || ret=1
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
