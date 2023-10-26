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

# Say on stdout whether to test DNSRPS
#	and creates dnsrps.conf
# Note that dnsrps.conf is included in named.conf
#	and differs from dnsrpz.conf which is used by dnsrpzd.

. ../conf.sh

DNSRPS_CMD=../rpz/dnsrps

AS_NS=
TEST_DNSRPS=
MCONF=dnsrps.conf
USAGE="$0: [-xAD] [-M dnsrps.conf]"
while getopts "xADM:S:" c; do
  case $c in
    x)
      set -x
      DEBUG=-x
      ;;
    A) AS_NS=yes ;;
    D) TEST_DNSRPS=yes ;;
    M) MCONF="$OPTARG" ;;
    *)
      echo "$USAGE" 1>&2
      exit 1
      ;;
  esac
done
shift $(expr $OPTIND - 1 || true)
if [ "$#" -ne 0 ]; then
  echo "$USAGE" 1>&2
  exit 1
fi

# erase any existing conf files
cat /dev/null >$MCONF

add_conf() {
  echo "$*" >>$MCONF
}

if ! $FEATURETEST --enable-dnsrps; then
  if [ -n "$TEST_DNSRPS" ]; then
    add_conf "## DNSRPS disabled at compile time"
  fi
  add_conf "#skip"
  exit 0
fi

if [ -z "$TEST_DNSRPS" ]; then
  add_conf "## testing with native RPZ"
  add_conf '#skip'
  exit 0
else
  add_conf "## testing with DNSRPS"
fi

if [ ! -x "$DNSRPS_CMD" ]; then
  add_conf "## make $DNSRPS_CMD to test DNSRPS"
  add_conf '#skip'
  exit 0
fi

if $DNSRPS_CMD -a >/dev/null; then
  :
else
  add_conf "## DNSRPS provider library is not available"
  add_conf '#skip'
  exit 0
fi

add_conf 'dnsrps-options { log-level 3 };'
add_conf 'dnsrps-enable yes;'
add_conf 'dnsrps-library "../../rpz/testlib/.libs/libdummyrpz.so";'
