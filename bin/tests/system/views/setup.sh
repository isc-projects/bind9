#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cp -f ns2/example1.db ns2/example.db
cp -f ns2/named1.conf ns2/named.conf
cp -f ns3/named1.conf ns3/named.conf
rm -f ns2/external/K*
rm -f ns2/external/inline.db.signed
rm -f ns2/external/inline.db.signed.jnl
rm -f ns2/internal/K*
rm -f ns2/internal/inline.db.signed
rm -f ns2/internal/inline.db.signed.jnl

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

test -r $RANDFILE || $GENRANDOM 400 $RANDFILE

#
# We remove k1 and k2 as KEYGEN is deterministic when given the
# same source of "random" data and we want different keys for
# internal and external instances of inline.
#
$KEYGEN -K ns2/internal -r $RANDFILE -3q inline > /dev/null 2>&1
$KEYGEN -K ns2/internal -r $RANDFILE -3qfk inline > /dev/null 2>&1
k1=`$KEYGEN -K ns2/external -r $RANDFILE -3q inline 2> /dev/null`
k2=`$KEYGEN -K ns2/external -r $RANDFILE -3qfk inline 2> /dev/null`
$KEYGEN -K ns2/external -r $RANDFILE -3q inline > /dev/null 2>&1
$KEYGEN -K ns2/external -r $RANDFILE -3qfk inline > /dev/null 2>&1
test -n "$k1" && rm -f ns2/external/$k1.*
test -n "$k2" && rm -f ns2/external/$k2.*
