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

set -e

zone=example.
infile=example.db.in
zonefile=example.db

keyname1=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
keyname2=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname1.key" "$keyname2.key" >"$zonefile"

"$SIGNER" -P -g -o "$zone" -k "$keyname1" "$zonefile" "$keyname2" >/dev/null

# Override the DS key with a way lower TTL
"$DSFROMKEY" -T 2 "$keyname1.key" >"dsset-$zone"

# Override the DNSKEY with a way lower TTL
sed -E 's/.*300[[:space:]]+DNSKEY/ 2 DNSKEY/' "$zonefile.signed" >"$zonefile.signed.tmp"
mv "$zonefile.signed.tmp" "$zonefile.signed"
