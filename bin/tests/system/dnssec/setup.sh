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

copy_setports ns1/named.conf.in ns1/named.conf
copy_setports ns2/named.conf.in ns2/named.conf
copy_setports ns3/named.conf.in ns3/named.conf

copy_setports ns4/named1.conf.in ns4/named.conf
copy_setports ns5/named1.conf.in ns5/named.conf

copy_setports ns6/named.conf.in ns6/named.conf
copy_setports ns7/named.conf.in ns7/named.conf
copy_setports ns8/named.conf.in ns8/named.conf

copy_setports ns9/named.conf.in ns9/named.conf

(
  cd ns1
  $SHELL sign.sh
  {
    echo "a.bogus.example.	A	10.0.0.22"
    echo "b.bogus.example.	A	10.0.0.23"
    echo "c.bogus.example.	A	10.0.0.23"
  } >>../ns3/bogus.example.db.signed
)

(
  cd ns3
  cp -f siginterval1.conf siginterval.conf
)

(
  cd ns5
  $SHELL sign.sh
)
