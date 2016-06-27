#!/bin/sh
#
# Copyright (C) 2013, 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0

echo "I:test name to long"
$PERL formerr.pl -a 10.53.0.1 -p 5300 nametoolong > nametoolong.out
ans=`grep got: nametoolong.out`
if [ "${ans}" != "got: 000080010000000000000000" ];
then
	echo "I:failed"; status=`expr $status + 1`;
fi

echo "I:two questions"
$PERL formerr.pl -a 10.53.0.1 -p 5300 twoquestions > twoquestions.out
ans=`grep got: twoquestions.out`
if [ "${ans}" != "got: 000080010000000000000000" ];
then
	echo "I:failed"; status=`expr $status + 1`;
fi

# this one is now NOERROR
echo "I:no questions"
$PERL formerr.pl -a 10.53.0.1 -p 5300 noquestions > noquestions.out
ans=`grep got: noquestions.out`
if [ "${ans}" != "got: 000080000000000000000000" ];
then
	echo "I:failed"; status=`expr $status + 1`;
fi

echo "I:exit status: $status"

[ $status -eq 0 ] || exit 1
