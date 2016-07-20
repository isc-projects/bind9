#!/bin/sh
#
# Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=1

matchall () {
    file=$1
    echo "$2" | while read matchline; do
        grep "$matchline" $file > /dev/null 2>&1 || {
            echo "FAIL"
            return
        }
    done
}

echo "I:checking for DNSSEC key coverage issues"
ret=0
for dir in [0-9][0-9]-*; do
        ret=0
        echo "I:$dir ($n)"
        kargs= cargs= kmatch= cmatch= kret= cret=0 warn= error= ok=
        . $dir/expect

        # use policy.conf if available
        policy=""
        [ -e "$dir/policy.conf" ] && policy="-c $dir/policy.conf"
        # run keymgr to update keys
        $KEYMGR $policy -K $dir -g $KEYGEN -r $RANDFILE -s $SETTIME $kargs > keymgr.$n 2>&1
        # check that return code matches expectations
        found=$?
        if [ $found -ne $kret ]; then
            echo "keymgr retcode was $found expected $kret"
            ret=1
        fi

        found=`matchall keymgr.$n "$kmatch"`
        if [ "$found" = "FAIL" ]; then
            echo "no match on '$kmatch'"
            ret=1
        fi

        # now check coverage
        $COVERAGE -K $dir $cargs > coverage.$n 2>&1
        # check that return code matches expectations
        found=$?
        if [ $found -ne $cret ]; then
            echo "coverage retcode was $found expected $cret"
            ret=1
        fi

        # check for correct number of errors
        found=`grep ERROR coverage.$n | wc -l`
        if [ $found -ne $error ]; then
            echo "error count was $found expected $error"
            ret=1
        fi

        # check for correct number of warnings
        found=`grep WARNING coverage.$n | wc -l`
        if [ $found -ne $warn ]; then
            echo "warning count was $found expected $warn"
            ret=1
        fi

        # check for correct number of OKs
        found=`grep "No errors found" coverage.$n | wc -l`
        if [ $found -ne $ok ]; then
            echo "good count was $found expected $ok"
            ret=1
        fi

        found=`matchall coverage.$n "$cmatch"`
        if [ "$found" = "FAIL" ]; then
            echo "no match on '$cmatch'"
            ret=1
        fi

        n=`expr $n + 1`
        if [ $ret != 0 ]; then echo "I:failed"; fi
        status=`expr $status + $ret`
done

echo "I:checking policy.conf parser ($n)"
ret=0
${PYTHON} testpolicy.py policy.sample > policy.out
cmp -s policy.good policy.out || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
