#!/bin/sh
#
# Copyright (C) 2013-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
t=0

echo "I:class list"
$RRCHECKER -C > classlist.out
$DIFF classlist.out classlist.good || { echo "I:failed"; status=`expr $status + 1`; }

echo "I:type list"
$RRCHECKER -T > typelist.out
$DIFF typelist.out typelist.good || { echo "I:failed"; status=`expr $status + 1`; }

echo "I:private type list"
$RRCHECKER -P > privatelist.out
$DIFF privatelist.out privatelist.good || { echo "I:failed"; status=`expr $status + 1`; }

myecho() {
cat << EOF
$*
EOF
}

echo "I:check conversions to canonical format"
ret=0
$SHELL ../genzone.sh 0 > tempzone
$CHECKZONE -Dq . tempzone | sed '/^;/d' |
while read -r n tt cl ty rest
do
	myecho "$cl $ty $rest" | $RRCHECKER -p > checker.out || {
		ret=1
		echo "I: '$cl $ty $rest' not handled."
	}
	read -r cl0 ty0 rest0 < checker.out
	test "$cl $ty $rest" = "$cl0 $ty0 $rest0" || {
		ret=1
		echo "I: '$cl $ty $rest' != '$cl0 $ty0 $rest0'"
	}
done
test $ret -eq 0 || { echo "I:failed"; status=`expr $status + 1`; }

echo "I:check conversions to and from unknown record format"
ret=0
$CHECKZONE -Dq . tempzone | sed '/^;/d' |
while read -r n tt cl ty rest
do
	myecho "$cl $ty $rest" | $RRCHECKER -u > checker.out || {
		ret=1
		echo "I: '$cl $ty $rest' not converted to unknown record format"
	}
	read -r clu tyu restu < checker.out
	myecho "$clu $tyu $restu" | $RRCHECKER -p > checker.out || {
		ret=1
		echo "I: '$cl $ty $rest' not converted back to canonical format"
	}
	read -r cl0 ty0 rest0 < checker.out
	test "$cl $ty $rest" = "$cl0 $ty0 $rest0" || {
		ret=1
		echo "I: '$cl $ty $rest' != '$cl0 $ty0 $rest0'"
	}
done
test $ret -eq 0 || { echo "I:failed"; status=`expr $status + 1`; }

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
