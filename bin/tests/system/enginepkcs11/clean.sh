#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=conf.sh
. ../conf.sh

set -e

rm -f dig.out.*
rm -f dsset-*
rm -f keyfromlabel.err.* keyfromlabel.out.*
rm -f pkcs11-tool.err.* pkcs11-tool.out.*
rm -f signer.out.*
rm -f ns*/*.kskid1 ns*/*.kskid2 ns*/*.zskid1 ns/*.zskid2
rm -f ns*/dig.out.*
rm -f ns*/K*
rm -f ns*/keygen.out.*
rm -f ns*/named.conf ns1/named.args ns1/named.run ns1/named.memstats
rm -f ns*/pin
rm -f ns*/update.cmd.*
rm -f ns*/update.log.*
rm -f ns*/verify.out.*
rm -f ns*/zone.*.jnl ns1/zone.*.jbk
rm -f ns1/*.example.db ns1/*.example.db.signed
rm -f ns1/*.kasp.db ns1/*.kasp.db.signed
rm -f ns1/*.split.db ns1/*.split.db.signed
rm -f ns2/*.views.db ns1/*.views.db.signed
rm -rf ./ns1/keys/
rm -rf ./ns2/keys/

OPENSSL_CONF= softhsm2-util --delete-token --token "softhsm2-enginepkcs11" >/dev/null 2>&1 || echo_i "softhsm2-enginepkcs11 token not found for cleaning"
