#!/bin/sh
#
# Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGCMD="$DIG @10.53.0.2 -p 5300"

if [ ! "$JSONSTATS" ]
then
    unset PERL_JSON
    echo "I:JSON was not configured; skipping" >&2
elif $PERL -e 'use JSON;' 2>/dev/null
then
    PERL_JSON=1
else
    unset PERL_JSON
    echo "I:JSON tests require JSON library; skipping" >&2
fi

if [ ! "$XMLSTATS" ]
then
    unset PERL_XML
    echo "I:XML was not configured; skipping" >&2
elif $PERL -e 'use XML::Simple;' 2>/dev/null
then
    PERL_XML=1
else
    unset PERL_XML
    echo "I:XML tests require XML::Simple; skipping" >&2
fi

if [ ! "$PERL_JSON" -a ! "$PERL_XML" ]; then
    echo "I:skipping all tests"
    exit 0
fi


gettraffic() {
    echo "I:... using $1"
    case $1 in
        xml) path='xml/v3/traffic' ;;
        json) path='json/v1/traffic' ;;
        *) return 1 ;;
    esac
    file=`$PERL fetch.pl $path`
    $PERL traffic-${1}.pl $file 2>/dev/null | sort > traffic.out.$2
    result=$?
    rm -f $file
    return $result
}

status=0
n=1
ret=0
echo "I:fetching traffic size data ($n)"
if [ $PERL_XML ]; then
    gettraffic xml x$n || ret=1
    cmp traffic.out.x$n traffic.expect.$n || ret=1
fi
if [ $PERL_JSON ]; then
    gettraffic json j$n || ret=1
    cmp traffic.out.j$n traffic.expect.$n || ret=1
fi
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I:fetching traffic size data after small UDP query ($n)"
$DIGCMD short.example txt > dig.out.$n || ret=1
if [ $PERL_XML ]; then
    gettraffic xml x$n || ret=1
    cmp traffic.out.x$n traffic.expect.$n || ret=1
fi
if [ $PERL_JSON ]; then
    gettraffic json j$n || ret=1
    cmp traffic.out.j$n traffic.expect.$n || ret=1
fi
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
n=`expr $n + 1`
echo "I:fetching traffic size data after large UDP query ($n)"
$DIGCMD long.example txt > dig.out.$n || ret=1
if [ $PERL_XML ]; then
    gettraffic xml x$n || ret=1
    cmp traffic.out.x$n traffic.expect.$n || ret=1
fi
if [ $PERL_JSON ]; then
    gettraffic json j$n || ret=1
    cmp traffic.out.j$n traffic.expect.$n || ret=1
fi
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I:fetching traffic size data after small TCP query ($n)"
$DIGCMD +tcp short.example txt > dig.out.$n || ret=1
if [ $PERL_XML ]; then
    gettraffic xml x$n || ret=1
    cmp traffic.out.x$n traffic.expect.$n || ret=1
fi
if [ $PERL_JSON ]; then
    gettraffic json j$n || ret=1
    cmp traffic.out.j$n traffic.expect.$n || ret=1
fi
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I:fetching traffic size data after large TCP query ($n)"
$DIGCMD +tcp long.example txt > dig.out.$n || ret=1
if [ $PERL_XML ]; then
    gettraffic xml x$n || ret=1
    cmp traffic.out.x$n traffic.expect.$n || ret=1
fi
if [ $PERL_JSON ]; then
    gettraffic json j$n || ret=1
    cmp traffic.out.j$n traffic.expect.$n || ret=1
fi
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I:checking consistency between named.stats and xml/json ($n)"
rm -f ns2/named.stats
$DIGCMD +tcp example ns > dig.out.$n || ret=1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 stats 2>&1 | sed 's/^/I:ns1 /'
query_count=`awk '/QUERY/ {print $1}' ns2/named.stats`
txt_count=`awk '/TXT/ {print $1}' ns2/named.stats`
noerror_count=`awk '/NOERROR/ {print $1}' ns2/named.stats`
if [ $PERL_XML ]; then
    file=`$PERL fetch.pl xml/v3/server`
    mv $file xml.stats
    $PERL server-xml.pl > xml.fmtstats 2> /dev/null
    xml_query_count=`awk '/opcode QUERY/ { print $NF }' xml.fmtstats`
    xml_query_count=${xml_query_count:-0}
    [ "$query_count" -eq "$xml_query_count" ] || ret=1
    xml_txt_count=`awk '/qtype TXT/ { print $NF }' xml.fmtstats`
    xml_txt_count=${xml_txt_count:-0}
    [ "$txt_count" -eq "$xml_txt_count" ] || ret=1
    xml_noerror_count=`awk '/rcode NOERROR/ { print $NF }' xml.fmtstats`
    xml_noerror_count=${xml_noerror_count:-0}
    [ "$noerror_count" -eq "$xml_noerror_count" ] || ret=1
fi
if [ $PERL_JSON ]; then
    file=`$PERL fetch.pl json/v1/server`
    mv $file json.stats
    $PERL server-json.pl > json.fmtstats 2> /dev/null
    json_query_count=`awk '/opcode QUERY/ { print $NF }' json.fmtstats`
    json_query_count=${json_query_count:-0}
    [ "$query_count" -eq "$json_query_count" ] || ret=1
    json_txt_count=`awk '/qtype TXT/ { print $NF }' json.fmtstats`
    json_txt_count=${json_txt_count:-0}
    [ "$txt_count" -eq "$json_txt_count" ] || ret=1
    json_noerror_count=`awk '/rcode NOERROR/ { print $NF }' json.fmtstats`
    json_noerror_count=${json_noerror_count:-0}
    [ "$noerror_count" -eq "$json_noerror_count" ] || ret=1
fi
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`


ret=0
echo "I:checking consistency between regular and compressed output ($n)"
if [ "$XMLSTATS" ];
then
	URL=http://10.53.0.2:8853/xml/v3/server
else
	URL=http://10.53.0.2:8853/json/v1/server
fi
$CURL -D regular.headers $URL 2>/dev/null | \
	sed -e "s#<current-time>.*</current-time>##g" > regular.out
$CURL -D compressed.headers --compressed $URL 2>/dev/null | \
	sed -e "s#<current-time>.*</current-time>##g" > compressed.out
diff regular.out compressed.out >/dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I:checking if compressed output is really compressed ($n)"
if [ "$ZLIB" ];
then
    REGSIZE=`cat regular.headers | \
	grep -i Content-Length | sed -e "s/.*: \([0-9]*\).*/\1/"`
    COMPSIZE=`cat compressed.headers | \
	grep -i Content-Length | sed -e "s/.*: \([0-9]*\).*/\1/"`
    if [ ! `expr $REGSIZE / $COMPSIZE` -gt 2 ]; then
	ret=1
    fi
else
    echo "I:skipped"
fi
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
