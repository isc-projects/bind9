#!/bin/sh
#
# Copyright (C) 2006-2008, 2011  Internet Systems Consortium, Inc. ("ISC")
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

# $Id: tests.sh,v 1.8.264.3 2011/12/23 23:46:23 tbox Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=0

if grep "^#define DNS_RDATASET_FIXED" $TOP/config.h > /dev/null 2>&1 ; then
        test_fixed=true
else
        echo "I: Order 'fixed' disabled at compile time"
        test_fixed=false
fi

#
#
#
n=`expr $n + 1`
if $test_fixed; then
    echo "I: Checking order fixed (master) ($n)"
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
    do
    ret=0
    $DIG +nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm +nostat +short \
	    -p 5300 @10.53.0.1 fixed.example > dig.out.test$n || ret=1
    cmp -s dig.out.test$n dig.out.fixed.good || ret=1
    [ $ret = 0 ] && break
    done
    if [ $ret != 0 ]; then echo "I:failed"; fi
    status=`expr $status + $ret`
else
    echo "I: Skipped: Checking order fixed (master) ($n)"
fi

#
#
#
n=`expr $n + 1`
echo "I: Checking order cyclic (master) ($n)"
ret=0
for i in 1 2 3 4
do
	eval match$i=0
done
for i in a b c d e f g h
do
$DIG +nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm +nostat +short \
	-p 5300 @10.53.0.1 cyclic.example > dig.out.cyclic || ret=1
	match=0
	for j in 1 2 3 4
	do
		if $test_fixed; then
			cmp -s dig.out.cyclic dig.out.cyclic.fixed$j && {
				eval "match$j=1 match=1";
			}
		else
			cmp -s dig.out.cyclic dig.out.cyclic.good$j && {
				eval "match$j=1 match=1";
			}
		fi
		if [ $match -eq 1 ]; then break; fi
	done
	if [ $match -eq 0 ]; then ret=1; echo "I:unexpected order"; cat dig.out.cyclic; fi
done
match=0
for i in 1 2 3 4
do
	eval "match=\`expr \$match + \$match$i\`"
done
echo "I: Cyclic selection return $match of 4 possible orders in 8 samples"
if [ $match -ne 4 ]; then echo ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Checking order random (master) ($n)"
ret=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
do
	eval match$i=0
done
for i in a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 9
do
$DIG +nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm +nostat +short \
	-p 5300 @10.53.0.1 random.example > dig.out.random || ret=1
	match=0
	for j in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
	do
		eval "cmp -s dig.out.random dig.out.random.good$j && match$j=1 match=1"
		if [ $match -eq 1 ]; then break; fi
	done
	if [ $match -eq 0 ]; then ret=1; fi
done
match=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
do
	eval "match=\`expr \$match + \$match$i\`"
done
echo "I: Random selection return $match of 24 possible orders in 36 samples"
if [ $match -lt 8 ]; then echo ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

#
#
#
n=`expr $n + 1`
if $test_fixed; then
    echo "I: Checking order fixed (slave) ($n)"
    ret=0
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
    do
    $DIG +nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm +nostat +short \
	    -p 5300 @10.53.0.2 fixed.example > dig.out.test$n || ret=1
    cmp -s dig.out.test$n dig.out.fixed.good || ret=1
    done
    if [ $ret != 0 ]; then echo "I:failed"; fi
    status=`expr $status + $ret`
else
    echo "I: Skipped: Checking order fixed (slave) ($n)"
fi

#
#
#
n=`expr $n + 1`
echo "I: Checking order cyclic (slave) ($n)"
ret=0
for i in 1 2 3 4
do
	eval match$i=0
done
for i in a b c d e f g h
do
$DIG +nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm +nostat +short \
	-p 5300 @10.53.0.2 cyclic.example > dig.out.cyclic || ret=1
	match=0
	for j in 1 2 3 4
	do
		if $test_fixed; then
			cmp -s dig.out.cyclic dig.out.cyclic.fixed$j && {
				eval "match$j=1 match=1";
			}
		else
			cmp -s dig.out.cyclic dig.out.cyclic.good$j && {
				eval "match$j=1 match=1";
			}
		fi
		if [ $match -eq 1 ]; then break; fi
	done
	if [ $match -eq 0 ]; then ret=1; echo "I:unexpected order"; fi
done
match=0
for i in 1 2 3 4
do
	eval "match=\`expr \$match + \$match$i\`"
done
echo "I: Cyclic selection return $match of 4 possible orders in 8 samples"
if [ $match -ne 4 ]; then echo ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Checking order random (slave) ($n)"
ret=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
do
	eval match$i=0
done
for i in a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 9
do
$DIG +nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm +nostat +short \
	-p 5300 @10.53.0.2 random.example > dig.out.random || ret=1
	match=0
	for j in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
	do
		eval "cmp -s dig.out.random dig.out.random.good$j && match$j=1 match=1"
		if [ $match -eq 1 ]; then break; fi
	done
	if [ $match -eq 0 ]; then ret=1; fi
done
match=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
do
eval "match=\`expr \$match + \$match$i\`"
done
echo "I: Random selection return $match of 24 possible orders in 36 samples"
if [ $match -lt 8 ]; then echo ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: Shutting down slave"

(cd ..; sh stop.sh rrsetorder ns2 )

n=`expr $n + 1`
echo "I: Checking for slave's on disk copy of zone ($n)"

if [ ! -f ns2/root.bk ]
then
	echo "I:failed";
	status=`expr $status + 1`
fi

echo "I: Re-starting slave"

(cd ..; sh start.sh --noclean rrsetorder ns2 )

#
#
#
n=`expr $n + 1`
if $test_fixed; then
    echo "I: Checking order fixed (slave loaded from disk) ($n)"
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
    do
    ret=0
    $DIG +nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm +nostat +short \
	    -p 5300 @10.53.0.2 fixed.example > dig.out.test$n || ret=1
    cmp -s dig.out.test$n dig.out.fixed.good || ret=1
    [ $ret = 0 ] && break
    sleep 1
    done
    if [ $ret != 0 ]; then echo "I:failed"; fi
    status=`expr $status + $ret`
else
    echo "I: Skipped: Checking order fixed (slave loaded from disk) ($n)"

fi

#
#
#
n=`expr $n + 1`
echo "I: Checking order cyclic (slave loaded from disk) ($n)"
ret=0
for i in 1 2 3 4
do
	eval match$i=0
done
for i in a b c d e f g h
do
$DIG +nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm +nostat +short \
	-p 5300 @10.53.0.2 cyclic.example > dig.out.cyclic || ret=1
	match=0
	for j in 1 2 3 4
	do
		if $test_fixed; then
			cmp -s dig.out.cyclic dig.out.cyclic.fixed$j && {
				eval "match$j=1 match=1";
			}
		else
			cmp -s dig.out.cyclic dig.out.cyclic.good$j && {
				eval "match$j=1 match=1";
			}
		fi
		if [ $match -eq 1 ]; then break; fi
	done
	if [ $match -eq 0 ]; then ret=1; echo "I:unexpected order"; fi
done
match=0
for i in 1 2 3 4
do
	eval "match=\`expr \$match + \$match$i\`"
done
echo "I: Cyclic selection return $match of 4 possible orders in 8 samples"
if [ $match -ne 4 ]; then echo ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Checking order random (slave loaded from disk) ($n)"
ret=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
do
	eval match$i=0
done
for i in a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 9
do
$DIG +nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm +nostat +short \
	-p 5300 @10.53.0.2 random.example > dig.out.random || ret=1
	match=0
	for j in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
	do
		eval "cmp -s dig.out.random dig.out.random.good$j && match$j=1 match=1"
		if [ $match -eq 1 ]; then break; fi
	done
	if [ $match -eq 0 ]; then ret=1; fi
done
match=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
do
eval "match=\`expr \$match + \$match$i\`"
done
echo "I: Random selection return $match of 24 possible orders in 36 samples"
if [ $match -lt 8 ]; then echo ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

#
#
#
n=`expr $n + 1`
if $test_fixed; then
    echo "I: Checking order fixed (cache) ($n)"
    ret=0
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
    do
    $DIG +nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm +nostat +short \
	    -p 5300 @10.53.0.3 fixed.example > dig.out.test$n || ret=1
    cmp -s dig.out.test$n dig.out.fixed.good || ret=1
    done
    if [ $ret != 0 ]; then echo "I:failed"; fi
    status=`expr $status + $ret`
else
    echo "I: Skipped: Checking order fixed (cache) ($n)"
fi

#
#
#
n=`expr $n + 1`
echo "I: Checking order cyclic (cache) ($n)"
ret=0
for i in 1 2 3 4
do
	eval match$i=0
done
for i in a b c d e f g h
do
$DIG +nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm +nostat +short \
	-p 5300 @10.53.0.3 cyclic.example > dig.out.cyclic || ret=1
	match=0
	for j in 1 2 3 4
	do
		if $test_fixed; then
			cmp -s dig.out.cyclic dig.out.cyclic.fixed$j && {
				eval "match$j=1 match=1";
			}
		else
			cmp -s dig.out.cyclic dig.out.cyclic.good$j && {
				eval "match$j=1 match=1";
			}
		fi
		if [ $match -eq 1 ]; then break; fi
	done
	if [ $match -eq 0 ]; then ret=1; echo "I:unexpected order"; fi
done
match=0
for i in 1 2 3 4
do
	eval "match=\`expr \$match + \$match$i\`"
done
echo "I: Cyclic selection return $match of 4 possible orders in 8 samples"
if [ $match -ne 4 ]; then echo ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

n=`expr $n + 1`
echo "I: Checking order random (cache) ($n)"
ret=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
do
	eval match$i=0
done
for i in a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 9
do
$DIG +nosea +nocomm +nocmd +noquest +noadd +noauth +nocomm +nostat +short \
	-p 5300 @10.53.0.3 random.example > dig.out.random || ret=1
	match=0
	for j in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
	do
		eval "cmp -s dig.out.random dig.out.random.good$j && match$j=1 match=1"
		if [ $match -eq 1 ]; then break; fi
	done
	if [ $match -eq 0 ]; then ret=1; fi
done
match=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
do
eval "match=\`expr \$match + \$match$i\`"
done
echo "I: Random selection return $match of 24 possible orders in 36 samples"
if [ $match -lt 8 ]; then echo ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi

status=`expr $status + $ret`
echo "I:exit status: $status"
exit $status
