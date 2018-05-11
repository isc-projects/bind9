#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="-p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"
CLEANQL="rm -f ans*/query.log"
status=0
n=0

n=`expr $n + 1`
echo_i "query for .good is not minimized when qname-minimization is off ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.5 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.good. @10.53.0.5 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "icky.icky.icky.ptang.zoop.boing.good. 1	IN A	192.0.2.1" dig.out.test$n > /dev/null || ret=1
cat << __EOF | diff ans2/query.log - > /dev/null || ret=1
A icky.icky.icky.ptang.zoop.boing.good.
A ns3.good.
AAAA ns3.good.
A a.bit.longer.ns.name.good.
AAAA a.bit.longer.ns.name.good.
__EOF
echo "A icky.icky.icky.ptang.zoop.boing.good." | diff ans3/query.log - > /dev/null || ret=1
echo "A icky.icky.icky.ptang.zoop.boing.good." | diff ans4/query.log - > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .bad is not minimized when qname-minimization is off ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.5 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.bad. @10.53.0.5 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "icky.icky.icky.ptang.zoop.boing.bad. 1 IN A	192.0.2.1" dig.out.test$n > /dev/null || ret=1
cat << __EOF | diff ans2/query.log - > /dev/null || ret=1
A icky.icky.icky.ptang.zoop.boing.bad.
A ns3.bad.
AAAA ns3.bad.
A a.bit.longer.ns.name.bad.
AAAA a.bit.longer.ns.name.bad.
__EOF
echo "A icky.icky.icky.ptang.zoop.boing.bad." | diff ans3/query.log - > /dev/null || ret=1
echo "A icky.icky.icky.ptang.zoop.boing.bad." | diff ans4/query.log - > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .slow is not minimized when qname-minimization is off ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.5 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.slow. @10.53.0.5 > dig.out.test$n
sleep 5
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "icky.icky.icky.ptang.zoop.boing.slow. 1	IN A	192.0.2.1" dig.out.test$n > /dev/null || ret=1
cat << __EOF | diff ans2/query.log - > /dev/null || ret=1
A icky.icky.icky.ptang.zoop.boing.slow.
A ns3.slow.
AAAA ns3.slow.
A a.bit.longer.ns.name.slow.
AAAA a.bit.longer.ns.name.slow.
__EOF
echo "A icky.icky.icky.ptang.zoop.boing.slow." | diff ans3/query.log - > /dev/null || ret=1
echo "A icky.icky.icky.ptang.zoop.boing.slow." | diff ans4/query.log - > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .good is properly minimized when qname-minimization is on ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.6 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.good. @10.53.0.6 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "icky.icky.icky.ptang.zoop.boing.good. 1	IN A	192.0.2.1" dig.out.test$n > /dev/null || ret=1
# Duplicated NS queries are there because we're not creating
# a separate fetch when doing qname minimization - so two
# queries running for the same name but different RRTYPE 
# (A and AAAA in this case) will create separate queries
# for NSes on the way. Those will be cached though, so it
# should not be a problem
cat << __EOF | diff ans2/query.log - > /dev/null || ret=1
NS boing.good.
NS zoop.boing.good.
A ns3.good.
AAAA ns3.good.
NS name.good.
NS name.good.
NS ns.name.good.
NS ns.name.good.
NS longer.ns.name.good.
NS longer.ns.name.good.
A a.bit.longer.ns.name.good.
AAAA a.bit.longer.ns.name.good.
__EOF
cat << __EOF | diff ans3/query.log - > /dev/null || ret=1
NS ptang.zoop.boing.good.
NS icky.ptang.zoop.boing.good.
__EOF
cat << __EOF | diff ans4/query.log - > /dev/null || ret=1
NS icky.icky.ptang.zoop.boing.good.
A icky.icky.icky.ptang.zoop.boing.good.
__EOF
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .bad fails when qname-minimization is in strict mode ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.6 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.bad. @10.53.0.6 > dig.out.test$n
grep "status: NXDOMAIN" dig.out.test$n > /dev/null || ret=1
echo "NS boing.bad." | diff ans2/query.log - > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .bad succeds when qname-minimization is in relaxed mode ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.7 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.bad. @10.53.0.7 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "icky.icky.icky.ptang.zoop.boing.bad. 1 IN A	192.0.2.1" dig.out.test$n > /dev/null || ret=1
cat << __EOF | diff ans2/query.log - > /dev/null || ret=1
NS boing.bad.
A icky.icky.icky.ptang.zoop.boing.bad.
A ns3.bad.
AAAA ns3.bad.
NS name.bad.
NS name.bad.
A a.bit.longer.ns.name.bad.
AAAA a.bit.longer.ns.name.bad.
__EOF
echo "A icky.icky.icky.ptang.zoop.boing.bad." | diff ans3/query.log - > /dev/null || ret=1
echo "A icky.icky.icky.ptang.zoop.boing.bad." | diff ans4/query.log - > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .slow is properly minimized when qname-minimization is on ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.6 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.slow. @10.53.0.6 > dig.out.test$n
sleep 5
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "icky.icky.icky.ptang.zoop.boing.slow. 1	IN A	192.0.2.1" dig.out.test$n > /dev/null || ret=1
cat << __EOF | diff ans2/query.log - > /dev/null || ret=1
NS boing.slow.
NS zoop.boing.slow.
A ns3.slow.
AAAA ns3.slow.
NS name.slow.
NS name.slow.
NS ns.name.slow.
NS ns.name.slow.
NS longer.ns.name.slow.
NS longer.ns.name.slow.
A a.bit.longer.ns.name.slow.
AAAA a.bit.longer.ns.name.slow.
__EOF
cat << __EOF | diff ans3/query.log - > /dev/null || ret=1
NS ptang.zoop.boing.slow.
NS icky.ptang.zoop.boing.slow.
__EOF
cat << __EOF | diff ans4/query.log - > /dev/null || ret=1
NS icky.icky.ptang.zoop.boing.slow.
A icky.icky.icky.ptang.zoop.boing.slow.
__EOF
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .ip6.arpa succeds and skips on proper boundaries when qname-minimization is on ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.6 flush
$DIG $DIGOPTS -x 2001:4f8::1 @10.53.0.6 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa. 1 IN PTR nee.com." dig.out.test$n > /dev/null || ret=1
cat << __EOF | diff ans2/query.log - > /dev/null || ret=1
NS 1.0.0.2.ip6.arpa.
NS 8.f.4.0.1.0.0.2.ip6.arpa.
NS 0.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa.
NS 0.0.0.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa.
NS 0.0.0.0.0.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa.
PTR 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa.
__EOF
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for multiple label name skips after 3rd no-delegation response ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.6 flush
$DIG $DIGOPTS many.labels.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.good. @10.53.0.6 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "many.labels.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.good. 1	IN A 192.0.2.2" dig.out.test$n > /dev/null || ret=1
# We skipped after third no-delegation.
cat << __EOF | diff ans2/query.log - > /dev/null || ret=1
NS z.good.
NS y.z.good.
NS x.y.z.good.
A many.labels.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.good.
__EOF
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for multiple label name skips after 7th label ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.6 flush
$DIG $DIGOPTS more.icky.icky.icky.ptang.zoop.boing.good. @10.53.0.6 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "more.icky.icky.icky.ptang.zoop.boing.good. 1 IN	A 192.0.2.2" dig.out.test$n > /dev/null || ret=1
cat << __EOF | diff ans2/query.log - > /dev/null || ret=1
NS boing.good.
NS zoop.boing.good.
A ns3.good.
AAAA ns3.good.
NS name.good.
NS name.good.
NS ns.name.good.
NS ns.name.good.
NS longer.ns.name.good.
NS longer.ns.name.good.
A a.bit.longer.ns.name.good.
AAAA a.bit.longer.ns.name.good.
__EOF
cat << __EOF | diff ans3/query.log - > /dev/null || ret=1
NS ptang.zoop.boing.good.
NS icky.ptang.zoop.boing.good.
__EOF
# There's no NS icky.icky.ptang.zoop.boing.good. query - we skipped it.
cat << __EOF | diff ans4/query.log - > /dev/null || ret=1
NS icky.icky.ptang.zoop.boing.good.
A more.icky.icky.icky.ptang.zoop.boing.good.
__EOF
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
