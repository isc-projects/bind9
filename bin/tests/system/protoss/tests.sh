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

RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"
DIGOPTS="-p ${PORT}"

status=0
n=1

echo_i "check PROTOSS option is logged correctly ($n)"
ret=0
nextpart ns2/named.run > /dev/null
$PYTHON protoss.py > /dev/null
nextpart ns2/named.run | grep "PROTOSS:" > protoss.out
lines=`cat protoss.out | wc -l`
[ "$lines" -eq 4 ] || ret=1
grep "org:1816793/ipv4:10.0.0.4" protoss.out > /dev/null || ret=1
grep "dev:deadbeef/org:1816793/ipv4:10.0.0.4" protoss.out > /dev/null || ret=1
grep "dev:deadbeef/org:1816793/ipv6:fe0f::1" protoss.out > /dev/null || ret=1
grep "va:30280231/ipv4:10.0.0.4/org:1816793" protoss.out > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check PROTOSS is not sent when not configured ($n)"
ret=0
nextpart ns3/named.run > /dev/null
$DIG $DIGOPTS @10.53.0.5 -b 10.53.0.4 a.example > dig.out.ns5.test$n || ret=1
nextpart ns3/named.run | grep "PROTOSS:" > protoss.out
lines=`cat protoss.out | wc -l`
[ "$lines" -eq 0 ] || ret=1
ttl1=`awk '/^a.example/ {print $2}' dig.out.ns5.test$n`
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check response is cached when PROTOSS is not sent ($n)"
ret=0
sleep 1
$DIG $DIGOPTS @10.53.0.5 -b 10.53.0.4 a.example > dig.out.ns5.test$n || ret=1
ttl2=`awk '/^a.example/ {print $2}' dig.out.ns5.test$n`
[ "$ttl1" -ne "$ttl2" ] || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

# configure protoss-virtual-appliance
copy_setports ns5/named2.conf.in ns5/named.conf
$RNDCCMD 10.53.0.5 reconfig | sed 's/^/I:ns5 /'
$RNDCCMD 10.53.0.5 flush | sed 's/^/I:ns5 /'

echo_i "check response is not cached when PROTOSS is sent ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.5 -b 10.53.0.4 a.example > dig.out.ns5.test$n || ret=1
ttl1=`awk '/^a.example/ {print $2}' dig.out.ns5.test$n`
sleep 1
$DIG $DIGOPTS @10.53.0.5 -b 10.53.0.4 a.example > dig.out.ns5.test$n || ret=1
ttl2=`awk '/^a.example/ {print $2}' dig.out.ns5.test$n`
[ "$ttl1" -eq 0 ] || ret=1
[ "$ttl2" -eq 0 ] || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check Virtual Appliance option is sent when forwarding ($n)"
ret=0
nextpart ns3/named.run > /dev/null
$DIG $DIGOPTS @10.53.0.5 -b 10.53.0.4 a.example > dig.out.ns5.test$n || ret=1
nextpart ns3/named.run | grep "PROTOSS:" > protoss.out
grep "va:30280231" protoss.out > /dev/null || ret=1
grep "ipv4:10.53.0.4" protoss.out > /dev/null || ret=1
grep "ipv6:" protoss.out > /dev/null && ret=1
grep "org:" protoss.out > /dev/null && ret=1
grep "dev:" protoss.out > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if $TESTSOCK6 fd92:7065:b8e:ffff::5 2>/dev/null
then
  echo_i "check Virtual Appliance option is sent when forwarding (ipv6 client) ($n)"
  ret=0
  nextpart ns3/named.run > /dev/null
  $DIG $DIGOPTS @fd92:7065:b8e:ffff::5 -b fd92:7065:b8e:ffff::4 b.example > dig.out.ns5.test$n || ret=1
  nextpart ns3/named.run | grep "PROTOSS:" > protoss.out
  grep "va:30280231" protoss.out > /dev/null || ret=1
  grep "ipv4:" protoss.out > /dev/null && ret=1
  grep "ipv6:fd92:7065:b8e:ffff::4" protoss.out > /dev/null || ret=1
  grep "org:" protoss.out > /dev/null && ret=1
  grep "dev:" protoss.out > /dev/null && ret=1
  n=`expr $n + 1`
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`
fi

# configure protoss-organization
copy_setports ns5/named3.conf.in ns5/named.conf
$RNDCCMD 10.53.0.5 reconfig | sed 's/^/I:ns5 /'

echo_i "check Organization option is sent when forwarding ($n)"
ret=0
nextpart ns3/named.run > /dev/null
$DIG $DIGOPTS @10.53.0.5 -b 10.53.0.4 a.example > dig.out.ns5.test$n || ret=1
nextpart ns3/named.run | grep "PROTOSS:" > protoss.out
grep "va:" protoss.out > /dev/null && ret=1
grep "ipv4:10.53.0.4" protoss.out > /dev/null || ret=1
grep "ipv6:" protoss.out > /dev/null && ret=1
grep "org:1816793" protoss.out > /dev/null || ret=1
grep "dev:" protoss.out > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if $TESTSOCK6 fd92:7065:b8e:ffff::5 2>/dev/null
then
  echo_i "check Organization option is sent when forwarding (ipv6 client) ($n)"
  ret=0
  nextpart ns3/named.run > /dev/null
  $DIG $DIGOPTS @fd92:7065:b8e:ffff::5 -b fd92:7065:b8e:ffff::4 b.example > dig.out.ns5.test$n || ret=1
  nextpart ns3/named.run | grep "PROTOSS:" > protoss.out
  grep "va:" protoss.out > /dev/null && ret=1
  grep "ipv4:" protoss.out > /dev/null && ret=1
  grep "ipv6:fd92:7065:b8e:ffff::4" protoss.out > /dev/null || ret=1
  grep "org:1816793" protoss.out > /dev/null || ret=1
  grep "dev:" protoss.out > /dev/null && ret=1
  n=`expr $n + 1`
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`
fi

# configure protoss-device
copy_setports ns5/named4.conf.in ns5/named.conf
$RNDCCMD 10.53.0.5 reconfig | sed 's/^/I:ns5 /'

echo_i "check Device option is sent when forwarding ($n)"
ret=0
nextpart ns3/named.run > /dev/null
$DIG $DIGOPTS @10.53.0.5 -b 10.53.0.4 a.example > dig.out.ns5.test$n || ret=1
nextpart ns3/named.run | grep "PROTOSS:" > protoss.out
grep "va:" protoss.out > /dev/null && ret=1
grep "ipv4:10.53.0.4" protoss.out > /dev/null || ret=1
grep "ipv6:" protoss.out > /dev/null && ret=1
grep "org:" protoss.out > /dev/null && ret=1
grep "dev:deadbeef" protoss.out > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if $TESTSOCK6 fd92:7065:b8e:ffff::5 2>/dev/null
then
  echo_i "check Device option is sent when forwarding (ipv6 client) ($n)"
  ret=0
  nextpart ns3/named.run > /dev/null
  $DIG $DIGOPTS @fd92:7065:b8e:ffff::5 -b fd92:7065:b8e:ffff::4 b.example > dig.out.ns5.test$n || ret=1
  nextpart ns3/named.run | grep "PROTOSS:" > protoss.out
  grep "va:" protoss.out > /dev/null && ret=1
  grep "ipv4:" protoss.out > /dev/null && ret=1
  grep "ipv6:fd92:7065:b8e:ffff::4" protoss.out > /dev/null || ret=1
  grep "org:" protoss.out > /dev/null && ret=1
  grep "dev:deadbeef" protoss.out > /dev/null || ret=1
  n=`expr $n + 1`
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`
fi

# configure "send-protoss no"
copy_setports ns5/named5.conf.in ns5/named.conf
$RNDCCMD 10.53.0.5 reconfig | sed 's/^/I:ns5 /'

echo_i "check sending of PROTOSS option can be disabled per server ($n)"
ret=0
nextpart ns3/named.run > /dev/null
$DIG $DIGOPTS @10.53.0.5 -b 10.53.0.4 a.example > dig.out.ns5.test$n || ret=1
nextpart ns3/named.run | grep "PROTOSS:" > protoss.out
lines=`cat protoss.out | wc -l`
[ "$lines" -eq 0 ] || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
