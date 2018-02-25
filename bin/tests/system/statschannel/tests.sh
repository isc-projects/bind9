#!/bin/sh
#
# Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
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

DIGCMD="$DIG @10.53.0.2 -p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

if [ ! "$HAVEJSONSTATS" ]
then
    unset PERL_JSON
    echo_i "JSON was not configured; skipping" >&2
elif $PERL -e 'use JSON;' 2>/dev/null
then
    PERL_JSON=1
else
    unset PERL_JSON
    echo_i "JSON tests require JSON library; skipping" >&2
fi

if [ ! "$HAVEXMLSTATS" ]
then
    unset PERL_XML
    echo_i "XML was not configured; skipping" >&2
elif $PERL -e 'use XML::Simple;' 2>/dev/null
then
    PERL_XML=1
else
    unset PERL_XML
    echo_i "XML tests require XML::Simple; skipping" >&2
fi

if [ ! "$PERL_JSON" -a ! "$PERL_XML" ]; then
    echo_i "skipping all tests"
    exit 0
fi

status=0
n=1

ret=0
echo_i "checking consistency between named.stats and xml/json ($n)"
rm -f ns2/named.stats
$DIGCMD +tcp example ns > dig.out.$n || ret=1
$RNDCCMD 10.53.0.2 stats 2>&1 | sed 's/^/ns1 /' | cat_i
query_count=`awk '/QUERY/ {print $1}' ns2/named.stats`
txt_count=`awk '/TXT/ {print $1}' ns2/named.stats`
if [ $PERL_XML ]; then
    file=`$PERL fetch.pl -p ${EXTRAPORT1} xml/v3/server`
    mv $file xml.stats
    $PERL server-xml.pl > xml.fmtstats 2> /dev/null
    xml_query_count=`awk '/opcode QUERY/ { print $NF }' xml.fmtstats`
    xml_query_count=${xml_query_count:-0}
    [ "$query_count" -eq "$xml_query_count" ] || ret=1
    xml_txt_count=`awk '/qtype TXT/ { print $NF }' xml.fmtstats`
    xml_txt_count=${xml_txt_count:-0}
    [ "$txt_count" -eq "$xml_txt_count" ] || ret=1
fi
if [ $PERL_JSON ]; then
    file=`$PERL fetch.pl -p ${EXTRAPORT1} json/v1/server`
    mv $file json.stats
    $PERL server-json.pl > json.fmtstats 2> /dev/null
    json_query_count=`awk '/opcode QUERY/ { print $NF }' json.fmtstats`
    json_query_count=${json_query_count:-0}
    [ "$query_count" -eq "$json_query_count" ] || ret=1
    json_txt_count=`awk '/qtype TXT/ { print $NF }' json.fmtstats`
    json_txt_count=${json_txt_count:-0}
    [ "$txt_count" -eq "$json_txt_count" ] || ret=1
fi
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
