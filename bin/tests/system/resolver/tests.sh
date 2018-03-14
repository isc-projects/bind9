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
echo .

DIGOPTS="-p ${PORT}"
SAMPLEOPTS="-p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

status=0
n=0

n=`expr $n + 1`
echo_i "checking non-cachable NXDOMAIN response handling ($n)"
ret=0
$DIG $DIGOPTS +tcp nxdomain.example.net @10.53.0.1 a > dig.out.ns1.test${n} || ret=1
grep "status: NXDOMAIN" dig.out.ns1.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if [ -x ${SAMPLE} ] ; then
   n=`expr $n + 1`
   echo_i "checking non-cachable NXDOMAIN response handling using dns_client ($n)"
   ret=0
   ${SAMPLE} $SAMPLEOPTS -t a 10.53.0.1 nxdomain.example.net 2> sample.out.ns1.test${n} || ret=1
   grep "resolution failed: ncache nxdomain" sample.out.ns1.test${n} > /dev/null || ret=1
   if [ $ret != 0 ]; then echo_i "failed"; fi
   status=`expr $status + $ret`
fi

n=`expr $n + 1`
echo_i "checking non-cachable NODATA response handling ($n)"
ret=0
$DIG $DIGOPTS +tcp nodata.example.net @10.53.0.1 a > dig.out.ns1.test${n} || ret=1
grep "status: NOERROR" dig.out.ns1.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if [ -x ${SAMPLE} ] ; then
    n=`expr $n + 1`
    echo_i "checking non-cachable NODATA response handling using dns_client ($n)"
    ret=0
    ${SAMPLE} $SAMPLEOPTS -t a 10.53.0.1 nodata.example.net 2> sample.out.ns1.test${n} || ret=1
    grep "resolution failed: ncache nxrrset" sample.out.ns1.test${n} > /dev/null || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

n=`expr $n + 1`
echo_i "checking handling of bogus referrals ($n)"
# If the server has the "INSIST(!external)" bug, this query will kill it.
$DIG $DIGOPTS +tcp www.example.com. a @10.53.0.1 >/dev/null || { echo_i "failed"; status=`expr $status + 1`; }

if [ -x ${SAMPLE} ] ; then
    n=`expr $n + 1`
    echo_i "checking handling of bogus referrals using dns_client ($n)"
    ret=0
    ${SAMPLE} $SAMPLEOPTS -t a 10.53.0.1 www.example.com 2> sample.out.ns1.test${n} || ret=1
    grep -E "resolution failed: (SERVFAIL|failure)" sample.out.ns1.test${n} > /dev/null || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

n=`expr $n + 1`
echo_i "check handling of cname + other data / 1 ($n)"
$DIG $DIGOPTS +tcp cname1.example.com. a @10.53.0.1 >/dev/null || { echo_i "failed"; status=`expr $status + 1`; }

n=`expr $n + 1`
echo_i "check handling of cname + other data / 2 ($n)"
$DIG $DIGOPTS +tcp cname2.example.com. a @10.53.0.1 >/dev/null || { echo_i "failed"; status=`expr $status + 1`; }

n=`expr $n + 1`
echo_i "check that server is still running ($n)"
$DIG $DIGOPTS +tcp www.example.com. a @10.53.0.1 >/dev/null || { echo_i "failed"; status=`expr $status + 1`; }

n=`expr $n + 1`
echo_i "checking answer IPv4 address filtering (deny) ($n)"
ret=0
$DIG $DIGOPTS +tcp www.example.net @10.53.0.1 a > dig.out.ns1.test${n} || ret=1
grep "status: SERVFAIL" dig.out.ns1.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking answer IPv6 address filtering (deny) ($n)"
ret=0
$DIG $DIGOPTS +tcp www.example.net @10.53.0.1 aaaa > dig.out.ns1.test${n} || ret=1
grep "status: SERVFAIL" dig.out.ns1.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking answer IPv4 address filtering (accept) ($n)"
ret=0
$DIG $DIGOPTS +tcp www.example.org @10.53.0.1 a > dig.out.ns1.test${n} || ret=1
grep "status: NOERROR" dig.out.ns1.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`


if [ -x ${SAMPLE} ] ; then
    n=`expr $n + 1`
    echo_i "checking answer IPv4 address filtering using dns_client (accept) ($n)"
    ret=0
    ${SAMPLE} $SAMPLEOPTS -t a 10.53.0.1 www.example.org > sample.out.ns1.test${n} || ret=1
    grep "www.example.org..*.192.0.2.1" sample.out.ns1.test${n} > /dev/null || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

n=`expr $n + 1`
echo_i "checking answer IPv6 address filtering (accept) ($n)"
ret=0
$DIG $DIGOPTS +tcp www.example.org @10.53.0.1 aaaa > dig.out.ns1.test${n} || ret=1
grep "status: NOERROR" dig.out.ns1.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if [ -x ${SAMPLE} ] ; then
    n=`expr $n + 1`
    echo_i "checking answer IPv6 address filtering using dns_client (accept) ($n)"
    ret=0
    ${SAMPLE} $SAMPLEOPTS -t aaaa 10.53.0.1 www.example.org > sample.out.ns1.test${n} || ret=1
    grep "www.example.org..*.2001:db8:beef::1" sample.out.ns1.test${n} > /dev/null || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

n=`expr $n + 1`
echo_i "checking CNAME target filtering (deny) ($n)"
ret=0
$DIG $DIGOPTS +tcp badcname.example.net @10.53.0.1 a > dig.out.ns1.test${n} || ret=1
grep "status: SERVFAIL" dig.out.ns1.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking CNAME target filtering (accept) ($n)"
ret=0
$DIG $DIGOPTS +tcp goodcname.example.net @10.53.0.1 a > dig.out.ns1.test${n} || ret=1
grep "status: NOERROR" dig.out.ns1.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if [ -x ${SAMPLE} ] ; then
    n=`expr $n + 1`
    echo_i "checking CNAME target filtering using dns_client (accept) ($n)"
    ret=0
    ${SAMPLE} $SAMPLEOPTS -t a 10.53.0.1 goodcname.example.net > sample.out.ns1.test${n} || ret=1
    grep "goodcname.example.net..*.goodcname.example.org." sample.out.ns1.test${n} > /dev/null || ret=1
    grep "goodcname.example.org..*.192.0.2.1" sample.out.ns1.test${n} > /dev/null || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

n=`expr $n + 1`
echo_i "checking CNAME target filtering (accept due to subdomain) ($n)"
ret=0
$DIG $DIGOPTS +tcp cname.sub.example.org @10.53.0.1 a > dig.out.ns1.test${n} || ret=1
grep "status: NOERROR" dig.out.ns1.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if [ -x ${SAMPLE} ] ; then
    n=`expr $n + 1`
    echo_i "checking CNAME target filtering using dns_client (accept due to subdomain) ($n)"
    ret=0
    ${SAMPLE} $SAMPLEOPTS -t a 10.53.0.1 cname.sub.example.org > sample.out.ns1.test${n} || ret=1
    grep "cname.sub.example.org..*.ok.sub.example.org." sample.out.ns1.test${n} > /dev/null || ret=1
    grep "ok.sub.example.org..*.192.0.2.1" sample.out.ns1.test${n} > /dev/null || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

n=`expr $n + 1`
echo_i "checking DNAME target filtering (deny) ($n)"
ret=0
$DIG $DIGOPTS +tcp foo.baddname.example.net @10.53.0.1 a > dig.out.ns1.test${n} || ret=1
grep "status: SERVFAIL" dig.out.ns1.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking DNAME target filtering (accept) ($n)"
ret=0
$DIG $DIGOPTS +tcp foo.gooddname.example.net @10.53.0.1 a > dig.out.ns1.test${n} || ret=1
grep "status: NOERROR" dig.out.ns1.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if [ -x ${SAMPLE} ] ; then
    n=`expr $n + 1`
    echo_i "checking DNAME target filtering using dns_client (accept) ($n)"
    ret=0
    ${SAMPLE} $SAMPLEOPTS -t a 10.53.0.1 foo.gooddname.example.net > sample.out.ns1.test${n} || ret=1
    grep "foo.gooddname.example.net..*.gooddname.example.org" sample.out.ns1.test${n} > /dev/null || ret=1
    grep "foo.gooddname.example.org..*.192.0.2.1" sample.out.ns1.test${n} > /dev/null || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

n=`expr $n + 1`
echo_i "checking DNAME target filtering (accept due to subdomain) ($n)"
ret=0
$DIG $DIGOPTS +tcp www.dname.sub.example.org @10.53.0.1 a > dig.out.ns1.test${n} || ret=1
grep "status: NOERROR" dig.out.ns1.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if [ -x ${SAMPLE} ] ; then
    n=`expr $n + 1`
    echo_i "checking DNAME target filtering using dns_client (accept due to subdomain) ($n)"
    ret=0
    ${SAMPLE} $SAMPLEOPTS -t a 10.53.0.1 www.dname.sub.example.org > sample.out.ns1.test${n} || ret=1
    grep "www.dname.sub.example.org..*.ok.sub.example.org." sample.out.ns1.test${n} > /dev/null || ret=1
    grep "www.ok.sub.example.org..*.192.0.2.1" sample.out.ns1.test${n} > /dev/null || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

n=`expr $n + 1`
echo_i "RT21594 regression test check setup ($n)"
ret=0
# Check that "aa" is not being set by the authoritative server.
$DIG $DIGOPTS +tcp . @10.53.0.4 soa > dig.ns4.out.${n} || ret=1
grep 'flags: qr rd;' dig.ns4.out.${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "RT21594 regression test positive answers ($n)"
ret=0
# Check that resolver accepts the non-authoritative positive answers.
$DIG $DIGOPTS +tcp . @10.53.0.5 soa > dig.ns5.out.${n} || ret=1
grep "status: NOERROR" dig.ns5.out.${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "RT21594 regression test NODATA answers ($n)"
ret=0
# Check that resolver accepts the non-authoritative nodata answers.
$DIG $DIGOPTS +tcp . @10.53.0.5 txt > dig.ns5.out.${n} || ret=1
grep "status: NOERROR" dig.ns5.out.${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "RT21594 regression test NXDOMAIN answers ($n)"
ret=0
# Check that resolver accepts the non-authoritative positive answers.
$DIG $DIGOPTS +tcp noexistant @10.53.0.5 txt > dig.ns5.out.${n} || ret=1
grep "status: NXDOMAIN" dig.ns5.out.${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that replacement of additional data by a negative cache no data entry clears the additional RRSIGs ($n)"
ret=0
$DIG $DIGOPTS +tcp mx example.net @10.53.0.7 > dig.ns7.out.${n} || ret=1
grep "status: NOERROR" dig.ns7.out.${n} > /dev/null || ret=1
if [ $ret = 1 ]; then echo_i "mx priming failed"; fi
$NSUPDATE << EOF
server 10.53.0.6 ${PORT}
zone example.net
update delete mail.example.net A
update add mail.example.net 0 AAAA ::1
send
EOF
$DIG $DIGOPTS +tcp a mail.example.net @10.53.0.7 > dig.ns7.out.${n} || ret=2
grep "status: NOERROR" dig.ns7.out.${n} > /dev/null || ret=2
grep "ANSWER: 0" dig.ns7.out.${n} > /dev/null || ret=2
if [ $ret = 2 ]; then echo_i "ncache priming failed"; fi
$DIG $DIGOPTS +tcp mx example.net @10.53.0.7 > dig.ns7.out.${n} || ret=3
grep "status: NOERROR" dig.ns7.out.${n} > /dev/null || ret=3
$DIG $DIGOPTS +tcp rrsig mail.example.net +norec @10.53.0.7 > dig.ns7.out.${n}  || ret=4
grep "status: NOERROR" dig.ns7.out.${n} > /dev/null || ret=4
grep "ANSWER: 0" dig.ns7.out.${n} > /dev/null || ret=4
if [ $ret != 0 ]; then echo_i "failed"; ret=1; fi
status=`expr $status + $ret`

if [ $ret != 0 ]; then echo_i "failed"; ret=1; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that update a nameservers address has immediate effects ($n)"
ret=0
$DIG $DIGOPTS +tcp TXT foo.moves @10.53.0.7 > dig.ns7.foo.${n} || ret=1
grep "From NS 5" dig.ns7.foo.${n} > /dev/null || ret=1
$NSUPDATE << EOF
server 10.53.0.7 ${PORT}
zone server
update delete ns.server A
update add ns.server 300 A 10.53.0.4
send
EOF
sleep 1
$DIG $DIGOPTS +tcp TXT bar.moves @10.53.0.7 > dig.ns7.bar.${n} || ret=1
grep "From NS 4" dig.ns7.bar.${n} > /dev/null || ret=1

if [ $ret != 0 ]; then echo_i "failed"; status=1; fi

n=`expr $n + 1`
echo_i "checking that update a nameservers glue has immediate effects ($n)"
ret=0
$DIG $DIGOPTS +tcp TXT foo.child.server @10.53.0.7 > dig.ns7.foo.${n} || ret=1
grep "From NS 5" dig.ns7.foo.${n} > /dev/null || ret=1
$NSUPDATE << EOF
server 10.53.0.7 ${PORT}
zone server
update delete ns.child.server A
update add ns.child.server 300 A 10.53.0.4
send
EOF
sleep 1
$DIG $DIGOPTS +tcp TXT bar.child.server @10.53.0.7 > dig.ns7.bar.${n} || ret=1
grep "From NS 4" dig.ns7.bar.${n} > /dev/null || ret=1

if [ $ret != 0 ]; then echo_i "failed"; status=1; fi

n=`expr $n + 1`
echo_i "checking empty RFC 1918 reverse zones ($n)"
ret=0
# Check that "aa" is being set by the resolver for RFC 1918 zones
# except the one that has been deliberately disabled
$DIG $DIGOPTS @10.53.0.7 -x 10.1.1.1 > dig.ns4.out.1.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.1.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 192.168.1.1 > dig.ns4.out.2.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.2.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.16.1.1  > dig.ns4.out.3.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.3.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.17.1.1 > dig.ns4.out.4.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.4.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.18.1.1 > dig.ns4.out.5.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.5.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.19.1.1 > dig.ns4.out.6.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.6.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.21.1.1 > dig.ns4.out.7.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.7.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.22.1.1 > dig.ns4.out.8.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.8.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.23.1.1 > dig.ns4.out.9.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.9.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.24.1.1 > dig.ns4.out.11.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.11.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.25.1.1 > dig.ns4.out.12.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.12.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.26.1.1 > dig.ns4.out.13.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.13.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.27.1.1 > dig.ns4.out.14.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.14.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.28.1.1 > dig.ns4.out.15.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.15.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.29.1.1 > dig.ns4.out.16.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.16.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.30.1.1 > dig.ns4.out.17.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.17.${n} > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.7 -x 172.31.1.1 > dig.ns4.out.18.${n} || ret=1
grep 'flags: qr aa rd ra;' dig.ns4.out.18.${n} > /dev/null || ret=1
# but this one should NOT be authoritative
$DIG $DIGOPTS @10.53.0.7 -x 172.20.1.1 > dig.ns4.out.19.${n} || ret=1
grep 'flags: qr rd ra;' dig.ns4.out.19.${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; status=1; fi

n=`expr $n + 1`
echo_i "checking that removal of a delegation is honoured ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.5 www.to-be-removed.tld A > dig.ns5.prime.${n}
grep "status: NOERROR" dig.ns5.prime.${n} > /dev/null || { ret=1; echo_i "priming failed"; }
cp ns4/tld2.db ns4/tld.db
($RNDCCMD 10.53.0.4 reload tld 2>&1 ) |
sed -e '/reload queued/d' -e 's/^/ns4 /' | cat_i
old=
for i in 0 1 2 3 4 5 6 7 8 9
do
	foo=0
	$DIG $DIGOPTS @10.53.0.5 ns$i.to-be-removed.tld A > /dev/null
	$DIG $DIGOPTS @10.53.0.5 www.to-be-removed.tld A > dig.ns5.out.${n}
	grep "status: NXDOMAIN" dig.ns5.out.${n} > /dev/null || foo=1
	[ $foo = 0 ] && break
	$NSUPDATE << EOF
server 10.53.0.6 ${PORT}
zone to-be-removed.tld
update add to-be-removed.tld 100 NS ns${i}.to-be-removed.tld
update delete to-be-removed.tld NS ns${old}.to-be-removed.tld
send
EOF
	old=$i
	sleep 1
done
[ $ret = 0 ] && ret=$foo;
if [ $ret != 0 ]; then echo_i "failed"; status=1; fi

n=`expr $n + 1`
echo_i "check for improved error message with SOA mismatch ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 www.sub.broken aaaa > dig.out.ns1.test${n} || ret=1
grep "not subdomain of zone" ns1/named.run > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

copy_setports ns7/named2.conf.in ns7/named.conf
$RNDCCMD 10.53.0.7 reconfig 2>&1 | sed 's/^/ns7 /' | cat_i

n=`expr $n + 1`
echo_i "check resolution on the listening port ($n)"
ret=0
$DIG $DIGOPTS +tcp +tries=2 +time=5 mx example.net @10.53.0.7 > dig.ns7.out.${n} || ret=2
grep "status: NOERROR" dig.ns7.out.${n} > /dev/null || ret=1
grep "ANSWER: 1" dig.ns7.out.${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; ret=1; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that '-t aaaa' in .digrc does not have unexpected side effects ($n)"
ret=0
echo "-t aaaa" > .digrc
env HOME=`pwd` $DIG $DIGOPTS @10.53.0.4 . > dig.out.1.${n} || ret=1
env HOME=`pwd` $DIG $DIGOPTS @10.53.0.4 . A > dig.out.2.${n} || ret=1
env HOME=`pwd` $DIG $DIGOPTS @10.53.0.4 -x 127.0.0.1 > dig.out.3.${n} || ret=1
grep ';\..*IN.*AAAA$' dig.out.1.${n} > /dev/null || ret=1
grep ';\..*IN.*A$' dig.out.2.${n} > /dev/null || ret=1
grep 'extra type option' dig.out.2.${n} > /dev/null && ret=1
grep ';1\.0\.0\.127\.in-addr\.arpa\..*IN.*PTR$' dig.out.3.${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that CNAME nameserver is logged correctly (${n})"
ret=0
$DIG $DIGOPTS soa all-cnames @10.53.0.5 > dig.out.ns5.test${n} || ret=1
grep "status: SERVFAIL" dig.out.ns5.test${n} > /dev/null || ret=1
grep "skipping nameserver 'cname.tld' because it is a CNAME, while resolving 'all-cnames/SOA'" ns5/named.run > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that SOA query returns data for delegation-only apex (${n})"
ret=0
$DIG $DIGOPTS soa delegation-only @10.53.0.5 > dig.out.ns5.test${n} || ret=1
grep "status: NOERROR" dig.out.ns5.test${n} > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns5.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

n=`expr $n + 1`
echo_i "check that NS query returns data for delegation-only apex (${n})"
ret=0
$DIG $DIGOPTS ns delegation-only @10.53.0.5 > dig.out.ns5.test${n} || ret=1
grep "status: NOERROR" dig.out.ns5.test${n} > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns5.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that A query returns data for delegation-only A apex (${n})"
ret=0
$DIG $DIGOPTS a delegation-only @10.53.0.5 > dig.out.ns5.test${n} || ret=1
grep "status: NOERROR" dig.out.ns5.test${n} > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns5.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that CDS query returns data for delegation-only apex (${n})"
ret=0
$DIG $DIGOPTS cds delegation-only @10.53.0.5 > dig.out.ns5.test${n} || ret=1
grep "status: NOERROR" dig.out.ns5.test${n} > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns5.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that AAAA query returns data for delegation-only AAAA apex (${n})"
ret=0
$DIG $DIGOPTS a delegation-only @10.53.0.5 > dig.out.ns5.test${n} || ret=1
grep "status: NOERROR" dig.out.ns5.test${n} > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns5.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo_i "check that DNSKEY query returns data for delegation-only apex (${n})"
ret=0
$DIG $DIGOPTS dnskey delegation-only @10.53.0.5 > dig.out.ns5.test${n} || ret=1
grep "status: NOERROR" dig.out.ns5.test${n} > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns5.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that CDNSKEY query returns data for delegation-only apex (${n})"
ret=0
$DIG $DIGOPTS cdnskey delegation-only @10.53.0.5 > dig.out.ns5.test${n} || ret=1
grep "status: NOERROR" dig.out.ns5.test${n} > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns5.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that NXDOMAIN is returned for delegation-only non-apex A data (${n})"
ret=0
$DIG $DIGOPTS a a.delegation-only @10.53.0.5 > dig.out.ns5.test${n} || ret=1
grep "status: NXDOMAIN" dig.out.ns5.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that NXDOMAIN is returned for delegation-only non-apex CDS data (${n})"
ret=0
$DIG $DIGOPTS cds cds.delegation-only @10.53.0.5 > dig.out.ns5.test${n} || ret=1
grep "status: NXDOMAIN" dig.out.ns5.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that NXDOMAIN is returned for delegation-only non-apex AAAA data (${n})"
ret=0
$DIG $DIGOPTS aaaa aaaa.delegation-only @10.53.0.5 > dig.out.ns5.test${n} || ret=1
grep "status: NXDOMAIN" dig.out.ns5.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo_i "check that NXDOMAIN is returned for delegation-only non-apex CDNSKEY data (${n})"
ret=0
$DIG $DIGOPTS cdnskey cdnskey.delegation-only @10.53.0.5 > dig.out.ns5.test${n} || ret=1
grep "status: NXDOMAIN" dig.out.ns5.test${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check zero ttl not returned for learnt non zero ttl records (${n})"
ret=0
# use prefetch disabled server
$DIG $DIGOPTS @10.53.0.7 non-zero.example.net txt > dig.out.1.${n} || ret=1
ttl1=`awk '/"A" "short" "ttl"/ { print $2 - 2 }' dig.out.1.${n}`
# sleep so we are in expire range
sleep ${ttl1:-0}
# look for ttl = 1, allow for one miss at getting zero ttl
zerotonine="0 1 2 3 4 5 6 7 8 9"
zerotonine="$zerotonine $zerotonine $zerotonine"
for i in $zerotonine $zerotonine $zerotonine $zerotonine
do
	$DIG $DIGOPTS @10.53.0.7 non-zero.example.net txt > dig.out.2.${n} || ret=1
	ttl2=`awk '/"A" "short" "ttl"/ { print $2 }' dig.out.2.${n}`
	test ${ttl2:-1} -eq 0 && break
	test ${ttl2:-1} -ge ${ttl1:-0} && break
	$PERL -e 'select(undef, undef, undef, 0.05);'
done
test ${ttl2:-1} -eq 0 && ret=1
test ${ttl2:-1} -ge ${ttl1:-0} || break
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check zero ttl is returned for learnt zero ttl records (${n})"
ret=0
$DIG $DIGOPTS @10.53.0.7 zero.example.net txt > dig.out.1.${n} || ret=1
ttl=`awk '/"A" "zero" "ttl"/ { print $2 }' dig.out.1.${n}`
test ${ttl:-1} -eq 0 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that 'ad' in not returned in truncated answer with empty answer and authority sections to request with +ad (${n})"
ret=0
$DIG $DIGOPTS @10.53.0.6 dnskey ds.example.net +bufsize=512 +ad +nodnssec +ignore +norec > dig.out.$n
grep "flags: qr aa tc; QUERY: 1, ANSWER: 0, AUTHORITY: 0" dig.out.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that 'ad' in not returned in truncated answer with empty answer and authority sections to request with +dnssec (${n})"
ret=0
$DIG $DIGOPTS @10.53.0.6 dnskey ds.example.net +bufsize=512 +noad +dnssec +ignore +norec > dig.out.$n
grep "flags: qr aa tc; QUERY: 1, ANSWER: 0, AUTHORITY: 0" dig.out.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that the resolver accepts a reply with empty question section with TC=1 and retries over TCP ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.5 truncated.no-questions. a > dig.ns5.out.${n} || ret=1
grep "status: NOERROR" dig.ns5.out.${n} > /dev/null || ret=1
grep "ANSWER: 1," dig.ns5.out.${n} > /dev/null || ret=1
grep "1.2.3.4" dig.ns5.out.${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that the resolver rejects a reply with empty question section with TC=0 ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.5 not-truncated.no-questions. a > dig.ns5.out.${n} || ret=1
grep "status: NOERROR" dig.ns5.out.${n} > /dev/null && ret=1
grep "ANSWER: 1," dig.ns5.out.${n} > /dev/null && ret=1
grep "1.2.3.4" dig.ns5.out.${n} > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
