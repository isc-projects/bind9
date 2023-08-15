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
rm -f ./keygen.out.*
rm -f ./named.conf
rm -f ./now.out
rm -f ./python.out
rm -f ./settime.out.*
rm -f ./K*
rm -rf ./keydir
rm -f ./ksr.*.err.*
rm -f ./ksr.*.expect
rm -f ./ksr.*.expect.*
rm -f ./ksr.*.out.*
