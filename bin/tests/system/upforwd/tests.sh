#!/bin/sh
#
# Copyright (C) 2004, 2007, 2011-2014, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) 2000, 2001  Internet Software Consortium.
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

# ns1 = stealth master
# ns2 = slave with update forwarding disabled; not currently used
# ns3 = slave with update forwarding enabled

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="+tcp +noadd +nosea +nostat +noquest +nocomm +nocmd -p ${PORT}"

status=0
n=1

sleep 5

echo_i "waiting for servers to be ready for testing ($n)"
for i in 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG +tcp -p ${PORT} example. @10.53.0.1 soa > dig.out.ns1 || ret=1
	grep "status: NOERROR" dig.out.ns1 > /dev/null ||  ret=1
	$DIG +tcp -p ${PORT} example. @10.53.0.2 soa > dig.out.ns2 || ret=1
	grep "status: NOERROR" dig.out.ns2 > /dev/null ||  ret=1
	$DIG +tcp -p ${PORT} example. @10.53.0.3 soa > dig.out.ns3 || ret=1
	grep "status: NOERROR" dig.out.ns3 > /dev/null ||  ret=1
	test $ret = 0 && break
	sleep 1
done
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi
n=`expr $n + 1`

echo_i "fetching master copy of zone before update ($n)"
ret=0
$DIG $DIGOPTS example.\
	@10.53.0.1 axfr > dig.out.ns1 || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi
n=`expr $n + 1`

echo_i "fetching slave 1 copy of zone before update ($n)"
$DIG $DIGOPTS example.\
	@10.53.0.2 axfr > dig.out.ns2 || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi
n=`expr $n + 1`

echo_i "fetching slave 2 copy of zone before update ($n)"
ret=0
$DIG $DIGOPTS example.\
	@10.53.0.3 axfr > dig.out.ns3 || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi
n=`expr $n + 1`

echo_i "comparing pre-update copies to known good data ($n)"
ret=0
$PERL ../digcomp.pl knowngood.before dig.out.ns1 || ret=1
$PERL ../digcomp.pl knowngood.before dig.out.ns2 || ret=1
$PERL ../digcomp.pl knowngood.before dig.out.ns3 || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi

echo_i "updating zone (signed) ($n)"
ret=0
$NSUPDATE -y update.example:c3Ryb25nIGVub3VnaCBmb3IgYSBtYW4gYnV0IG1hZGUgZm9yIGEgd29tYW4K -- - <<EOF || ret=1
server 10.53.0.3 ${PORT}
update add updated.example. 600 A 10.10.10.1
update add updated.example. 600 TXT Foo
send
EOF
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi
n=`expr $n + 1`

echo_i "sleeping 15 seconds for server to incorporate changes"
sleep 15

echo_i "fetching master copy of zone after update ($n)"
ret=0
$DIG $DIGOPTS example.\
	@10.53.0.1 axfr > dig.out.ns1 || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi
n=`expr $n + 1`

echo_i "fetching slave 1 copy of zone after update ($n)"
ret=0
$DIG $DIGOPTS example.\
	@10.53.0.2 axfr > dig.out.ns2 || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi

echo_i "fetching slave 2 copy of zone after update ($n)"
ret=0
$DIG $DIGOPTS example.\
	@10.53.0.3 axfr > dig.out.ns3 || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi
n=`expr $n + 1`

echo_i "comparing post-update copies to known good data ($n)"
ret=0
$PERL ../digcomp.pl knowngood.after1 dig.out.ns1 || ret=1
$PERL ../digcomp.pl knowngood.after1 dig.out.ns2 || ret=1
$PERL ../digcomp.pl knowngood.after1 dig.out.ns3 || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi

echo_i "checking 'forwarding update for zone' is logged ($n)"
ret=0
grep "forwarding update for zone 'example/IN'" ns3/named.run > /dev/null || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi
n=`expr $n + 1`

echo_i "updating zone (unsigned) ($n)"
ret=0
$NSUPDATE -- - <<EOF || ret=1
server 10.53.0.3 ${PORT}
update add unsigned.example. 600 A 10.10.10.1
update add unsigned.example. 600 TXT Foo
send
EOF
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi
n=`expr $n + 1`

echo_i "sleeping 15 seconds for server to incorporate changes"
sleep 15

echo_i "fetching master copy of zone after update ($n)"
ret=0
$DIG $DIGOPTS example.\
	@10.53.0.1 axfr > dig.out.ns1 || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi

echo_i "fetching slave 1 copy of zone after update ($n)"
ret=0
$DIG $DIGOPTS example.\
	@10.53.0.2 axfr > dig.out.ns2 || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi
n=`expr $n + 1`

echo_i "fetching slave 2 copy of zone after update ($n)"
ret=0
$DIG $DIGOPTS example.\
	@10.53.0.3 axfr > dig.out.ns3 || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi

echo_i "comparing post-update copies to known good data ($n)"
ret=0
$PERL ../digcomp.pl knowngood.after2 dig.out.ns1 || ret=1
$PERL ../digcomp.pl knowngood.after2 dig.out.ns2 || ret=1
$PERL ../digcomp.pl knowngood.after2 dig.out.ns3 || ret=1
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi
n=`expr $n + 1`

echo_i "checking update forwarding to dead master ($n)"
count=0
ret=0
while [ $count -lt 5 -a $ret -eq 0 ]
do
(
$NSUPDATE -- - <<EOF 
server 10.53.0.3 ${PORT}
zone nomaster
update add unsigned.nomaster. 600 A 10.10.10.1
update add unsigned.nomaster. 600 TXT Foo
send
EOF
) > /dev/null 2>&1 &
	$DIG -p ${PORT} +noadd +notcp +noauth nomaster. @10.53.0.3 soa > dig.out.ns3 || ret=1
	grep "status: NOERROR" dig.out.ns3 > /dev/null || ret=1
	count=`expr $count + 1`
done
if [ $ret != 0 ] ; then echo_i "failed"; status=`expr $status + $ret`; fi
n=`expr $n + 1`

if test -f keyname
then
	echo_i "checking update forwarding to with sig0 ($n)"
	ret=0
	keyname=`cat keyname`
	$NSUPDATE -k $keyname.private -- - <<EOF
	server 10.53.0.3 ${PORT}
	zone example2
	update add unsigned.example2. 600 A 10.10.10.1
	update add unsigned.example2. 600 TXT Foo
	send
EOF
	$DIG unsigned.example2 A @10.53.0.1 -p ${PORT} > dig.out.ns1.test$n
	grep "status: NOERROR" dig.out.ns1.test$n > /dev/null || ret=1
	if [ $ret != 0 ] ; then echo_i "failed"; fi
	status=`expr $status + $ret`
	n=`expr $n + 1`
fi

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
