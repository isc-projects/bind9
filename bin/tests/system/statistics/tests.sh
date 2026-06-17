#!/bin/sh

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

set -e

. ../conf.sh

DIGCMD="$DIG +tcp -p ${PORT}"
RNDCCMD="$RNDC -p ${CONTROLPORT} -c ../_common/rndc.conf"

status=0

ret=0
n=1
stats=0
nsock0nstat=0
nsock1nstat=0
rndc_stats() {
  _ns=$1
  _ip=$2

  $RNDCCMD -s $_ip stats >/dev/null 2>&1 || return 1
  [ -f "${_ns}/named.stats" ] || return 1

  last_stats=named.stats.$_ns-$stats-$n
  mv ${_ns}/named.stats $last_stats
  stats=$((stats + 1))
}

echo_i "fetching a.example from ns2's initial configuration ($n)"
$DIGCMD +noauth a.example. @10.53.0.2 any >dig.out.ns2.1 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "dumping initial stats for ns2 ($n)"
rndc_stats ns2 10.53.0.2 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "verifying adb records in named.stats ($n)"
grep "ADB stats" $last_stats >/dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

echo_i "checking for 1 entry in adb hash table in named.stats ($n)"
grep "1 Addresses in hash table" $last_stats >/dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "verifying cache statistics in named.stats ($n)"
grep "Cache Statistics" $last_stats >/dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "checking for 2 entries in adb hash table in named.stats ($n)"
$DIGCMD a.example.info. @10.53.0.2 any >/dev/null 2>&1
rndc_stats ns2 10.53.0.2 || ret=1
grep "2 Addresses in hash table" $last_stats >/dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "dumping initial stats for ns3 ($n)"
rndc_stats ns3 10.53.0.3 || ret=1
nsock0nstat=$(grep "UDP/IPv4 sockets active" $last_stats | awk '{print $1}')
[ 0 -ne ${nsock0nstat} ] || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

echo_i "sending queries to ns3"
$DIGCMD +tries=2 +time=1 +recurse @10.53.0.3 foo.info. any >/dev/null 2>&1 || true

ret=0
echo_i "dumping updated stats for ns3 ($n)"
getstats() {
  rndc_stats ns3 10.53.0.3 || return 1
  grep "2 recursing clients" $last_stats >/dev/null || return 1
}
retry_quiet 5 getstats || ret=1
# confirm agreement with 'rndc recursing'
$RNDCCMD -s 10.53.0.3 recursing || ret=1
lines=$(grep -c "; client .*(tcp)" ns3/named.recursing || true)
[ "$lines" -eq 2 ] || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "verifying recursing clients output in named.stats ($n)"
grep "2 recursing clients" $last_stats >/dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "verifying active fetches output in named.stats ($n)"
grep "1 active fetches" $last_stats >/dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "verifying active sockets output in named.stats ($n)"
# After repeated UDP timeouts to the same authoritative server, the
# resolver switches to TCP, so the in-flight socket may be either UDP
# or TCP.  Require at least one extra active socket of either kind.
nsock1udp=$(grep "UDP/IPv4 sockets active" $last_stats | awk '{print $1}')
nsock1tcp=$(grep "TCP/IPv4 sockets active" $last_stats | awk '{print $1}')
[ $((${nsock1udp:-0} + ${nsock1tcp:-0} - nsock0nstat)) -ge 1 ] || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

# There should be 1 query in progress.  After repeated UDP timeouts the
# resolver switches to TCP, so depending on which retry attempt the
# snapshot captures the query may be counted as either UDP or TCP.
ret=0
echo_i "verifying queries in progress in named.stats ($n)"
udp_in_progress=$(awk '/UDP queries in progress/ {print $1}' $last_stats)
tcp_in_progress=$(awk '/TCP queries in progress/ {print $1}' $last_stats)
[ $((${udp_in_progress:-0} + ${tcp_in_progress:-0})) -eq 1 ] || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "verifying bucket size output ($n)"
grep "bucket size" $last_stats >/dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "checking priming queries are counted ($n)"
grep "priming queries" $last_stats >/dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "checking that zones with slash are properly shown in XML output ($n)"
if $FEATURETEST --have-libxml2 && [ -x "${CURL}" ] && [ -x "${XMLLINT}" ]; then
  ${CURL} http://10.53.0.1:${EXTRAPORT1}/xml/v3/zones >curl.out.${n} 2>/dev/null || ret=1
  test -n "$("$XMLLINT" --xpath '/statistics/views/view[@name="_default"]/zones/zone[@name="32/1.0.0.127-in-addr.example"]' curl.out.${n})" || ret=1
else
  echo_i "skipping test as libxml2 and/or curl and/or xmllint was not found"
fi
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "checking that zones return their type ($n)"
if $FEATURETEST --have-libxml2 && [ -x "${CURL}" ] && [ -x "${XMLLINT}" ]; then
  ${CURL} http://10.53.0.1:${EXTRAPORT1}/xml/v3/zones >curl.out.${n} 2>/dev/null || ret=1
  test -n "$("$XMLLINT" --xpath '/statistics/views/view[@name="_default"]/zones/zone[@name="32/1.0.0.127-in-addr.example"]/type[text()="primary"]' curl.out.${n})" || ret=1
else
  echo_i "skipping test as libxml2 and/or curl and/or xmllint was not found"
fi
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "checking bind9.xsl vs xml ($n)"
if $FEATURETEST --have-libxml2 && "${CURL}" --http1.1 http://10.53.0.3:${EXTRAPORT1} >/dev/null 2>&1 && [ -x "${XSLTPROC}" ]; then
  $DIGCMD +notcp +recurse @10.53.0.3 soa . >dig.out.test$n.1 2>&1
  $DIGCMD +notcp +recurse @10.53.0.3 soa example >dig.out.test$n.2 2>&1
  # check multiple requests over the same socket
  time1=$($PERL -e 'print time(), "\n";')
  ${CURL} --http1.1 -o curl.out.${n}.xml http://10.53.0.3:${EXTRAPORT1}/xml/v3 \
    -o curl.out.${n}.xsl http://10.53.0.3:${EXTRAPORT1}/bind9.xsl 2>/dev/null || ret=1
  time2=$($PERL -e 'print time(), "\n";')
  test $((time2 - time1)) -lt 5 || ret=1
  diff ${TOP_SRCDIR}/bin/named/bind9.xsl curl.out.${n}.xsl || ret=1
  ${XSLTPROC} curl.out.${n}.xsl - <curl.out.${n}.xml >xsltproc.out.${n} 2>/dev/null || ret=1
  cp curl.out.${n}.xml stats.xml.out || ret=1

  #
  # grep for expected sections.
  #
  grep "<h1>ISC Bind 9 Configuration and Statistics</h1>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h2>Server Status</h2>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h2>Incoming Requests by DNS Opcode</h2>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h3>Incoming Queries by Query Type</h3>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h2>Outgoing Queries per view</h2>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h3>View " xsltproc.out.${n} >/dev/null || ret=1
  grep "<h2>Server Statistics</h2>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h2>Zone Maintenance Statistics</h2>" xsltproc.out.${n} >/dev/null || ret=1
  # grep "<h2>Resolver Statistics (Common)</h2>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h3>Resolver Statistics for View " xsltproc.out.${n} >/dev/null || ret=1
  grep "<h3>ADB Statistics for View " xsltproc.out.${n} >/dev/null || ret=1
  grep "<h3>Cache Statistics for View " xsltproc.out.${n} >/dev/null || ret=1
  # grep "<h3>Cache DB RRsets for View " xsltproc.out.${n} >/dev/null || ret=1
  grep "<h2>Traffic Size Statistics</h2>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h4>UDP Requests Received</h4>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h4>UDP Responses Sent</h4>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h4>TCP Requests Received</h4>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h4>TCP Responses Sent</h4>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h2>Socket I/O Statistics</h2>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h3>Zones for View " xsltproc.out.${n} >/dev/null || ret=1
  grep "<h2>Received QTYPES per view/zone</h2>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h3>View _default" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h4>Zone example" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h2>Response Codes per view/zone</h2>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h3>View _default" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h4>Zone example" xsltproc.out.${n} >/dev/null || ret=1
  # grep "<h2>Glue cache statistics</h2>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h3>View _default" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h4>Zone example" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h2>Memory Usage Summary</h2>" xsltproc.out.${n} >/dev/null || ret=1
  grep "<h2>Memory Contexts</h2>" xsltproc.out.${n} >/dev/null || ret=1
else
  echo_i "skipping test as libxml2 and/or curl with HTTP/1.1 support and/or xsltproc was not found"
fi
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "checking bind9.xml socket statistics ($n)"
if $FEATURETEST --have-libxml2 && [ -e stats.xml.out ] && [ -x "${XSLTPROC}" ] && [ -x "${XMLLINT}" ]; then
  # Socket statistics (expect no errors)
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="sockstat"]/counter[@name="TCP4AcceptFail" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="sockstat"]/counter[@name="TCP4BindFail" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="sockstat"]/counter[@name="TCP4ConnFail" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="sockstat"]/counter[@name="TCP4OpenFail" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="sockstat"]/counter[@name="TCP4RecvErr" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  # [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="sockstat"]/counter[@name="TCP4SendErr" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1

  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="sockstat"]/counter[@name="TCP6AcceptFail" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="sockstat"]/counter[@name="TCP6BindFail" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="sockstat"]/counter[@name="TCP6ConnFail" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="sockstat"]/counter[@name="TCP6OpenFail" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="sockstat"]/counter[@name="TCP6RecvErr" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="sockstat"]/counter[@name="TCP6SendErr" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
else
  echo_i "skipping test as libxml2 and/or stats.xml.out file and/or xsltproc and/or xmllint was not found"
fi
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

ret=0
echo_i "checking bind9.xml nsstats statistics ($n)"
if $FEATURETEST --have-libxml2 && [ -e stats.xml.out ] && [ -x "${XSLTPROC}" ] && [ -x "${XMLLINT}" ]; then
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="AuthQryRej" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="CookieBadSize" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="CookieBadTime" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="CookieIn" and text()="4"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="CookieMatch" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="CookieNew" and text()="4"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="CookieNoMatch" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="DNS64" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="ECSOpt" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="ExpireOpt" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="KeepAliveOpt" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="KeyTagOpt" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="NSIDOpt" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="OtherOpt" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="PadOpt" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="Prefetch" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryAuthAns" and text()="2"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryBADCOOKIE" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryDoH" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryDoHPlain" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryDoT" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryDropped" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryDuplicate" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryEncryptedProxyDoH" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryEncryptedProxyDoT" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryFORMERR" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryFailure" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryNXDOMAIN" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryNXRedir" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryNXRedirRLookup" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryNoauthAns" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryNxrrset" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryProxyDoH" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryProxyDoHPlain" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryProxyDoT" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryProxyTCP" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryProxyUDP" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryRecursion" and text()="3"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryReferral" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QrySERVFAIL" and text()="1"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QrySuccess" and text()="2"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryTCP" and text()="3"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryTryStale" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryUDP" and text()="2"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="QryUsedStale" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="RPZRewrites" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="RateDropped" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="RateSlipped" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="RecLimitDropped" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="RecQryRej" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="RecursClients" and text()="2"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="RecursHighwater" and text()="3"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="ReqBadEDNSVer" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="ReqBadSIG" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="ReqEdns0" and text()="4"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="ReqSIG0" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="ReqTCP" and text()="3"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="ReqTSIG" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="Requestv4" and text()="5"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="Requestv6" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="RespEDNS0" and text()="2"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="RespSIG0" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="RespTSIG" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="Response" and text()="3"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="SynthNODATA" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="SynthNXDOMAIN" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="SynthWILDCARD" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  # TCPConnHighWater varies across runs
  # [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="TCPConnHighWater" and text()="1"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="TruncatedResp" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="UpdateBadPrereq" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="UpdateDone" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="UpdateFail" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="UpdateFwdFail" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="UpdateQuota" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="UpdateRej" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="UpdateReqFwd" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="UpdateRespFwd" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="XfrRej" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="XfrReqDone" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1
  [ "$("$XMLLINT" --xpath 'count(/statistics/server/counters[@type="nsstat"]/counter[@name="ZoneVersionOpt" and text()="0"])' stats.xml.out)" -eq 1 ] || ret=1

else
  echo_i "skipping test as libxml2 and/or stats.xml.out file and/or xsltproc and/or xmllint was not found"
fi
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

echo_i "Check that 'zone-statistics full;' is processed by 'rndc reconfig' ($n)"
ret=0
# off by default
rndc_stats ns2 10.53.0.2 || ret=1
sed -n '/Per Zone Query Statistics/,/^++/p' $last_stats | grep -F '[example]' >/dev/null && ret=1
sed -n '/Per Zone Glue Cache Statistics/,/^++/p' $last_stats | grep -F '[example]' >/dev/null && ret=1
# turn on
cp ns2/named2.conf ns2/named.conf
rndc_reconfig ns2 10.53.0.2
rndc_stats ns2 10.53.0.2 || ret=1
sed -n '/Per Zone Query Statistics/,/^++/p' $last_stats | grep -F '[example]' >/dev/null || ret=1
sed -n '/Per Zone Glue Cache Statistics/,/^++/p' $last_stats | grep -F '[example]' >/dev/null || ret=1
# turn off
cp ns2/named1.conf ns2/named.conf
rndc_reconfig ns2 10.53.0.2
rndc_stats ns2 10.53.0.2 || ret=1
sed -n '/Per Zone Query Statistics/,/^++/p' $last_stats | grep -F '[example]' >/dev/null && ret=1
sed -n '/Per Zone Glue Cache Statistics/,/^++/p' $last_stats | grep -F '[example]' >/dev/null && ret=1
# turn on
cp ns2/named2.conf ns2/named.conf
rndc_reconfig ns2 10.53.0.2
rndc_stats ns2 10.53.0.2 || ret=1
sed -n '/Per Zone Query Statistics/,/^++/p' $last_stats | grep -F '[example]' >/dev/null || ret=1
sed -n '/Per Zone Glue Cache Statistics/,/^++/p' $last_stats | grep -F '[example]' >/dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))
n=$((n + 1))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
