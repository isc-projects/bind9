#!/bin/sh
#
# Copyright (C) 2010-2015  Internet Systems Consortium, Inc. ("ISC")
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

DIGOPTS="+tcp +nosea +nostat +nocmd +norec +noques +noauth +noadd +nostats +dnssec -p 5300"
status=0
n=0

echo "I:checking normally loaded zone ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

if [ -x "$PYTHON" ]; then 
echo "I:adding and deleting 20000 new zones ($n)"
ret=0
    time (
        echo "I:adding"
        $PYTHON << EOF
import sys
sys.path.insert(0, '../../../../bin/python')
from isc import rndc
r = rndc(('10.53.0.2', 9953), 'hmac-sha256', '1234abcd8765')
for i in range(20000):
    res = r.call('addzone z%d.example { type master; file "added.db"; };' % i)
    if 'text' in res:
        print ('I:n2:' + res['text'])
EOF
    )
    time (
        echo "I:deleting"
        $PYTHON << EOF
import sys
sys.path.insert(0, '../../../../bin/python')
from isc import rndc
r = rndc(('10.53.0.2', 9953), 'hmac-sha256', '1234abcd8765')
for i in range(20000):
    res = r.call('delzone z%d.example' % i)
    if 'text' in res:
        print ('I:n2:' + res['text'])
EOF
    )
    n=`expr $n + 1`
    if [ $ret != 0 ]; then echo "I:failed"; fi
    status=`expr $status + $ret`
fi

echo "I:exit status: $status"
exit $status
