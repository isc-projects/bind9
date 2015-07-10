#!/bin/sh
#
# Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
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

DIGCMD="$DIG @10.53.0.2 -p 5300"

if $PERL -e 'use JSON;' 2>/dev/null
then
    PERL_JSON=1
else
    unset PERL_JSON
    echo "I:JSON tests require JSON library; skipping" >&2
fi

if $PERL -e 'XML::Simple;' 2>/dev/null
then
    PERL_XML=1
else
    unset PERL_XML
    echo "I:XML tests require XML::Simple; skipping" >&2
fi

if [ ! $PERL_JSON -a ! $PERL_XML ]; then
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
    $PERL traffic-${1}.pl $file | sort > traffic.out.$2
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
if [ $PERL_XML ]; then
    file=`$PERL fetch.pl xml/v3/server`
    mv $file xml.stats
    $PERL server-xml.pl > xml.fmtstats 2> /dev/null
    xml_query_count=`awk '/opcode QUERY/ { print $NF }' xml.fmtstats` 
    [ "$query_count" -eq "$xml_query_count" ] || ret=1
    xml_txt_count=`awk '/qtype TXT/ { print $NF }' xml.fmtstats` 
    [ "$txt_count" -eq "$xml_txt_count" ] || ret=1
fi
if [ $PERL_JSON ]; then
    file=`$PERL fetch.pl json/v1/server`
    mv $file json.stats
    $PERL server-xml.pl > json.fmtstats 2> /dev/null
    json_query_count=`awk '/opcode QUERY/ { print $NF }' json.fmtstats` 
    [ "$query_count" -eq "$json_query_count" ] || ret=1
    json_txt_count=`awk '/qtype TXT/ { print $NF }' json.fmtstats` 
    [ "$txt_count" -eq "$json_txt_count" ] || ret=1
fi
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo "I:exit status: $status"
exit $status
