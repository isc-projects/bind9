#!/bin/sh
#
# Copyright (C) 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: sign.sh,v 1.3 2011/05/26 23:47:28 tbox Exp $

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

zone=example.
infile=example.db.in
outfile=example.db.bad

for i in Xexample.+005+51829.key Xexample.+005+51829.private \
	Xexample.+005+05896.key Xexample.+005+05896.private
do
	cp $i `echo $i | sed s/X/K/`
done

$SIGNER -r $RANDFILE -g -s 20000101000000 -e 20361231235959 -o $zone \
	$infile Kexample.+005+51829 Kexample.+005+51829 \
	> /dev/null 2> signer.err
