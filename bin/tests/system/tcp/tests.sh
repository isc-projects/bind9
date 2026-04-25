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

# shellcheck source=../conf.sh
. ../conf.sh

dig_with_opts() {
  "${DIG}" -p "${PORT}" "$@"
}

rndccmd() {
  "${RNDC}" -p "${CONTROLPORT}" -c ../_common/rndc.conf -s "$@"
}

status=0
n=0

####################################################
# NOTE: The next test resets the debug level to 1. #
####################################################

n=$((n + 1))
echo_i "checking that BIND 9 doesn't crash on long TCP messages ($n)"
ret=0
# Avoid logging useless information.
rndccmd 10.53.0.1 trace 1 || ret=1
{ $PERL ../packet.pl -a "10.53.0.1" -p "${PORT}" -t tcp -r 300000 1996-alloc_dnsbuf-crash-test.pkt || ret=1; } | cat_i
dig_with_opts +tcp @10.53.0.1 txt.example >dig.out.test$n || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status + ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
