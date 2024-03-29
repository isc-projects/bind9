#!/bin/sh

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

set -e

. ../conf.sh

DIGOPTS="+nosea +stat +noquest +nocomm +nocmd -p ${PORT}"

status=0

echo_i "Getting message size with compression enabled"
$DIG $DIGOPTS -b 10.53.0.1 @10.53.0.1 mx example >dig.compen.test || ret=1
COMPEN=$(grep ';; MSG SIZE' dig.compen.test | sed -e "s/.*: //g")
cat dig.compen.test | grep -v ';;' | sort >dig.compen.sorted.test

echo_i "Getting message size with compression disabled"
$DIG $DIGOPTS -b 10.53.0.2 @10.53.0.1 mx example >dig.compdis.test || ret=1
COMPDIS=$(grep ';; MSG SIZE' dig.compdis.test | sed -e "s/.*: //g")
cat dig.compdis.test | grep -v ';;' | sort >dig.compdis.sorted.test

# the compression disabled message should be at least twice as large as with
# compression disabled, but the content should be the same
echo_i "Checking if responses are identical other than in message size"
{
  diff dig.compdis.sorted.test dig.compen.sorted.test >/dev/null
  ret=$?
} || true
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

echo_i "Checking if message with compression disabled is significantly larger"
echo_i "Disabled $COMPDIS vs enabled $COMPEN"
val=$(((COMPDIS * 3 / 2) / COMPEN))
if [ $val -le 1 ]; then
  echo_i "failed"
  status=$((status + 1))
fi

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
