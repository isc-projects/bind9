#!/bin/sh
#
# Copyright (C) 2004, 2007, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
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

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="+tcp +noadd +nosea +nostat +noquest +nocomm +nocmd +noauth -p ${PORT}"
SHORTOPTS="+tcp +short -p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

status=0

echo_i "fetching a.example from ns2's initial configuration"
$DIG $DIGOPTS a.example. @10.53.0.2 any > dig.out.ns2.1 || status=1

echo_i "fetching a.example from ns3's initial configuration"
$DIG $DIGOPTS a.example. @10.53.0.3 any > dig.out.ns3.1 || status=1

echo_i "copying in new configurations for ns2 and ns3"
rm -f ns2/named.conf ns3/named.conf ns2/example.db
cp -f ns2/example2.db ns2/example.db
copy_setports ns2/named2.conf.in ns2/named.conf
copy_setports ns3/named2.conf.in ns3/named.conf

echo_i "reloading ns2 and ns3 with rndc"
nextpart ns2/named.run > /dev/null
nextpart ns3/named.run > /dev/null
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
$RNDCCMD 10.53.0.3 reload 2>&1 | sed 's/^/ns3 /' | cat_i

echo_i "wait for reload"
a=0 b=0
for i in 1 2 3 4 5 6 7 8 9 0; do
        nextpart ns2/named.run | grep "reloading zones succeeded" > /dev/null && a=1
        nextpart ns3/named.run | grep "reloading zones succeeded" > /dev/null && b=1
        [ $a -eq 1 -a $b -eq 1 ] && break
        sleep 1
done

echo_i "fetching a.example from ns2's 10.53.0.4, source address 10.53.0.4"
$DIG $DIGOPTS -b 10.53.0.4 a.example. @10.53.0.4 any > dig.out.ns4.2 || status=1

echo_i "fetching a.example from ns2's 10.53.0.2, source address 10.53.0.2"
$DIG $DIGOPTS -b 10.53.0.2 a.example. @10.53.0.2 any > dig.out.ns2.2 || status=1

echo_i "fetching a.example from ns3's 10.53.0.3, source address defaulted"
$DIG $DIGOPTS @10.53.0.3 a.example. any > dig.out.ns3.2 || status=1

echo_i "comparing ns3's initial a.example to one from reconfigured 10.53.0.2"
$PERL ../digcomp.pl dig.out.ns3.1 dig.out.ns2.2 || status=1

echo_i "comparing ns3's initial a.example to one from reconfigured 10.53.0.3"
$PERL ../digcomp.pl dig.out.ns3.1 dig.out.ns3.2 || status=1

echo_i "comparing ns2's initial a.example to one from reconfigured 10.53.0.4"
$PERL ../digcomp.pl dig.out.ns2.1 dig.out.ns4.2 || status=1

echo_i "comparing ns2's initial a.example to one from reconfigured 10.53.0.3"
echo_i "(should be different)"
if $PERL ../digcomp.pl dig.out.ns2.1 dig.out.ns3.2 >/dev/null
then
	echo_i "no differences found.  something's wrong."
	status=1
fi

if $SHELL ../testcrypto.sh
then
	echo_i "verifying inline zones work with views"
	ret=0
	$DIG -p ${PORT} @10.53.0.2 -b 10.53.0.2 +dnssec DNSKEY inline > dig.out.internal
	$DIG -p ${PORT} @10.53.0.2 -b 10.53.0.5 +dnssec DNSKEY inline > dig.out.external
	grep "ANSWER: 4," dig.out.internal > /dev/null || ret=1
	grep "ANSWER: 4," dig.out.external > /dev/null || ret=1
	int=`awk '$4 == "DNSKEY" { print $8 }' dig.out.internal | sort`
	ext=`awk '$4 == "DNSKEY" { print $8 }' dig.out.external | sort`
	test "$int" != "$ext" || ret=1
	if [ $ret != 0 ]; then echo_i "failed"; fi
	status=`expr $status + $ret`
fi

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
