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

rm -f *.created
rm -f cdnskey.ns*
rm -f cds.ns*
rm -f secondary.cdnskey.ns*
rm -f secondary.cds.ns*
rm -f created.key-*
rm -f dig.out.*
rm -f python.out.*
rm -f rndc.dnssec.status.out.*
rm -f unused.key-*
rm -f verify.out.*

rm -f ns*/*.jbk
rm -f ns*/*.jnl
rm -f ns*/*.journal.out.test*
rm -f ns*/*.signed
rm -f ns*/*.signed.jnl
rm -f ns*/*.zsk
rm -f ns*/db-*
rm -f ns*/K*
rm -f ns*/keygen.out.*
rm -f ns*/managed-keys*
rm -f ns*/model2.secondary.db
rm -f ns*/model2.secondary.db
rm -f ns*/named.conf
rm -f ns*/named.memstats
rm -f ns*/named.run
rm -f ns*/settime.out.*
