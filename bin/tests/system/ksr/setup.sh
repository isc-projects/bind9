#!/bin/sh -e

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

# shellcheck source=conf.sh
. ../conf.sh

set -e

$SHELL clean.sh

mkdir keydir
mkdir offline

copy_setports named.conf.in named.conf

# Create KSK for the various policies.
create_ksk() {
  KSK=$($KEYGEN -l named.conf -fK -k $2 $1 2>keygen.out.$1)
  num=0
  for ksk in $KSK; do
    num=$(($num + 1))
    echo $ksk >"${1}.ksk${num}.id"
    cat "${ksk}.key" | grep -v ";.*" >"$1.ksk$num"
    cp "${ksk}.key" offline/
    cp "${ksk}.private" offline/
  done
}
create_ksk common.test common
create_ksk unlimited.test unlimited
create_ksk two-tone.test two-tone
