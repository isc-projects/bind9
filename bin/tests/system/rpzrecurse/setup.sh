#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

USAGE="$0: [-xD]"
DEBUG=
while getopts "xD" c; do
    case $c in
	x) set -x; DEBUG=-x;;
	N) NOCLEAN=set;;
	*) echo "$USAGE" 1>&2; exit 1;;
    esac
done
shift `expr $OPTIND - 1 || true`
if test "$#" -ne 0; then
    echo "$USAGE" 1>&2
    exit 1
fi
OPTIND=1

[ ${NOCLEAN:-unset} = unset ] && $SHELL clean.sh $DEBUG

$PERL testgen.pl

copy_setports ns1/named.conf.in ns1/named.conf

copy_setports ns2/named.conf.header.in ns2/named.conf.header
copy_setports ns2/named.default.conf ns2/named.conf

copy_setports ns3/named1.conf.in ns3/named.conf
copy_setports ns3/named2.conf.in ns3/named2.conf

copy_setports ns4/named.conf.in ns4/named.conf
