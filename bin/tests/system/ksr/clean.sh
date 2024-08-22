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

rm -f ./*.ksk*
rm -f ./*.zsk*
rm -f ./created.out
rm -f ./footer.*
rm -f ./now.out
rm -f ./ns1/*.db
rm -f ./ns1/*.db.jbk
rm -f ./ns1/*.db.signed
rm -f ./ns1/*.db.signed.jnl
rm -f ./ns1/K*
rm -f ./ns1/keygen.out.*
rm -f ./ns1/named.conf
rm -f ./ns1/named.memstats
rm -f ./ns1/named.run
rm -f ./python.out
rm -f ./settime.out.*
rm -f ./ksr.*.err.*
rm -f ./ksr.*.expect
rm -f ./ksr.*.expect.*
rm -f ./ksr.*.out.*

rm -rf ./ns1/keydir
rm -rf ./ns1/offline
