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

zone=.
infile=root.db.in
zonefile=root.db

(cd ../ns2 && $SHELL sign.sh)

cp "../ns2/dsset-example." .

keyname=$($KEYGEN -q -a "${DEFAULT_ALGORITHM}" -b "${DEFAULT_BITS}" $zone)

cat "$infile" "$keyname.key" >"$zonefile"

$SIGNER -P -g -o $zone $zonefile >/dev/null

# Override the DS key with a way lower TTL (Also done from dsset-example. but
# this seems to be ignored when signing the zone.)
sed -E '/^example\./{
    n
    s/.*300[[:space:]]\+DS/ 2 DS/
}' "$zonefile.signed" >"$zonefile.signed.tmp"
mv "$zonefile.signed.tmp" "$zonefile.signed"

# Configure the resolving server with a static key.
keyfile_to_static_ds "$keyname" >trusted.conf
cp trusted.conf ../ns3/trusted.conf

# ...or with an initializing key.
keyfile_to_initial_ds "$keyname" >managed.conf
