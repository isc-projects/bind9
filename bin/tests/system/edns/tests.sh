#!/bin/sh
#
# Copyright (C) 2011  Internet Systems Consortium, Inc. ("ISC")
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

# $Id: tests.sh,v 1.3 2011/10/27 23:46:30 tbox Exp $ 

# ns1 = forward only server
# ans2 = modified ans.pl master

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0

DIGOPTS="+tcp +noadd +nosea +nostat +noquest +nocomm +nocmd"
DIGCMD="$DIG $DIGOPTS @10.53.0.1 -p 5300"
SENDCMD="$PERL ../send.pl 10.53.0.2 5301"
RNDCCMD="$RNDC -s 10.53.0.1 -p 9953 -c ../common/rndc.conf"

echo "I:Setting up master"
$SENDCMD <<EOF
/SOA/
nil.     0     SOA     ns.nil. root.nil. 1 300 300 604800 300
/TXT/
nil.     0     TXT     ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        "cccccccccccccccccccccccccccccccccccccccccccccccccc"
                        "dddddddddddddddddddddddddddddddddddddddddddddddddd"
                        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                        "ffffffffffffffffffffffffffffffffffffffffffffffffff"
                        "gggggggggggggggggggggggggggggggggggggggggggggggggg"
                        "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
                        "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
                        "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj"
                        "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"
                       )
EOF

echo "I:testing forwarder"
$DIGCMD nil. TXT > /dev/null 2>&1
edns_count=`grep -c "edns size: 4096" ans2/ans.run`
if [ $edns_count -ne 1 ]
then
	echo "I:failed (EDNS4096 attempt)"
	status=1
else
	echo "I: EDNS4096 attempt OK"
fi

edns_count=`grep -c "edns size: 512" ans2/ans.run`
if [ $edns_count -ne 3 ]
then
	echo "I:failed (EDNS512 attempts)"
	status=1
else
	echo "I: Three EDNS512 attempt OK"
fi

trunc_count=`grep -c "Truncating UDP packet" ans2/ans.run`
if [ $trunc_count -ne 1 ]
then
	echo "I:failed (should be 1 truncation but $trunc_count returned)"
	status=1
else
	echo "I: packet truncated"
fi

sleep 15

$DIGCMD nil. TXT > /dev/null 2>&1
trunc_count=`grep -c "Truncating UDP packet" ans2/ans.run`
if [ $trunc_count -ne 2 ]
then
	echo "I:failed (should be 2 truncations but $trunc_count returned)"
	status=1
else
	echo "I: packet truncated"
fi

echo "I:exit status: $status"
exit $status
