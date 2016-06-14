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

DIGOPTS="+nosea +stat +noquest +nocomm +nocmd"

status=0

echo "I:Getting message size with compression enabled"
$DIG $DIGOPTS -b 10.53.0.1 @10.53.0.1 -p 5300 mx example > dig.compen.test
COMPEN=`grep ';; MSG SIZE' dig.compen.test |sed -e "s/.*: //g"`
cat dig.compen.test  |grep -v ';;' |sort > dig.compen.sorted.test

echo "I:Getting message size with compression disabled"
$DIG $DIGOPTS -b 10.53.0.2 @10.53.0.1 -p 5300 mx example > dig.compdis.test
COMPDIS=`grep ';; MSG SIZE' dig.compdis.test |sed -e "s/.*: //g"`
cat dig.compdis.test  |grep -v ';;' |sort > dig.compdis.sorted.test

# the compression disabled message should be at least twice as large as with
# compression disabled, but the content should be the same
echo "I:Checking if responses are identical other than in message size"
diff dig.compdis.sorted.test dig.compen.sorted.test >/dev/null
ret=$?
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:Checking if message with compression disabled is significantly larger"
echo "I: Disabled $COMPDIS vs enabled $COMPEN"
val=`expr \( $COMPDIS \* 3 / 2 \) / $COMPEN`
if [ $val -le 1 ]; then
	echo "I:failed"
	status=`expr $status + 1`
fi;

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
