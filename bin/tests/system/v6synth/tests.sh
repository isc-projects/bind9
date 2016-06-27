#!/bin/sh
#
# Copyright (C) 2001, 2004, 2007, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: tests.sh,v 1.4 2007/06/19 23:47:06 tbox Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

# ns1 = root server
# ns2 = authoritative server
# ns3 = recursive server doing v6 synthesis

status=0

DIGOPTS="+tcp +noadd +nosea +nostat +noquest +nocomm +nocmd"

for name in aaaa a6 chain alias2 aaaa.dname loop loop2
do
    $DIG $DIGOPTS $name.example. aaaa @10.53.0.3 -p 5300
    echo
done >dig.out

for i in 1 2
do
    $DIG $DIGOPTS f.f.$i.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.5.4.3.2.1.ip6.int. PTR @10.53.0.3 -p 5300
    echo
done >>dig.out

cat <<EOF >good.out
aaaa.example.		0	IN	AAAA	12:34:56::ff

a6.example.		0	IN	AAAA	12:34:56::ff

chain.example.		0	IN	AAAA	12:34:56::ff:ff

alias2.example.		0	IN	CNAME	alias.example.
alias.example.		0	IN	CNAME	chain.example.
chain.example.		0	IN	AAAA	12:34:56::ff:ff

aaaa.dname.example.	0	IN	CNAME	aaaa.foo.example.
aaaa.foo.example.	0	IN	AAAA	12:34:56::ff

loop.example.		0	IN	CNAME	loop.example.

loop2.example.		0	IN	CNAME	loop3.example.
loop3.example.		0	IN	CNAME	loop2.example.

f.f.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.5.4.3.2.1.ip6.int. 0 IN PTR foo.

f.f.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.5.4.3.2.1.ip6.int. 0 IN PTR bar.

EOF

diff good.out dig.out || status=1

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
