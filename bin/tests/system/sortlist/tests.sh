#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: tests.sh,v 1.9 2007/09/14 01:46:05 marka Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0

echo "I:test 2-element sortlist statement"
cat <<EOF >test1.good
a.example.		300	IN	A	192.168.3.1
a.example.		300	IN	A	192.168.1.1
a.example.		300	IN	A	1.1.1.5
a.example.		300	IN	A	1.1.1.1
a.example.		300	IN	A	1.1.1.3
a.example.		300	IN	A	1.1.1.2
a.example.		300	IN	A	1.1.1.4
EOF
$DIG +tcp +noadd +nosea +nostat +noquest +noauth +nocomm +nocmd a.example. \
	@10.53.0.1 -b 10.53.0.1 -p 5300 >test1.dig
# Note that this can't use digcomp.pl because here, the ordering of the
# result RRs is significant.
diff test1.dig test1.good || status=1

echo "I:test 1-element sortlist statement and undocumented BIND 8 features"
	cat <<EOF >test2.good
b.example.		300	IN	A	10.53.0.$n
EOF

$DIG +tcp +noadd +nosea +nostat +noquest +noauth +nocomm +nocmd \
	b.example. @10.53.0.1 -b 10.53.0.2 -p 5300 | sed 1q | \
        egrep '10.53.0.(2|3)$' > test2.out &&
$DIG +tcp +noadd +nosea +nostat +noquest +noauth +nocomm +nocmd \
	b.example. @10.53.0.1 -b 10.53.0.3 -p 5300 | sed 1q | \
        egrep '10.53.0.(2|3)$' >> test2.out &&
$DIG +tcp +noadd +nosea +nostat +noquest +noauth +nocomm +nocmd \
	b.example. @10.53.0.1 -b 10.53.0.4 -p 5300 | sed 1q | \
        egrep '10.53.0.4$' >> test2.out &&
$DIG +tcp +noadd +nosea +nostat +noquest +noauth +nocomm +nocmd \
	b.example. @10.53.0.1 -b 10.53.0.5 -p 5300 | sed 1q | \
        egrep '10.53.0.5$' >> test2.out || status=1

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
