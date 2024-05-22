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
. ../../conf.sh

# Key directories
mkdir keydir
mkdir offline

# Zone files
cp template.db.in common.test.db
cp template.db.in past.test.db
cp template.db.in future.test.db
cp template.db.in last-bundle.test.db
cp template.db.in in-the-middle.test.db

# Create KSK for the various policies.
create_ksk() {
  KSK=$($KEYGEN -l named.conf -fK -k $2 $1 2>keygen.out.$1)
  num=0
  for ksk in $KSK; do
    num=$(($num + 1))
    echo $ksk >"../${1}.ksk${num}.id"
    cat "${ksk}.key" | grep -v ";.*" >"../$1.ksk$num"
    mv "${ksk}.key" offline/
    mv "${ksk}.private" offline/
    mv "${ksk}.state" offline/
  done
}
create_ksk common.test common
create_ksk past.test common
create_ksk future.test common
create_ksk last-bundle.test common
create_ksk in-the-middle.test common
create_ksk unlimited.test unlimited
create_ksk two-tone.test two-tone
