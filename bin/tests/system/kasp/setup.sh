#!/bin/sh -e
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
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

$SHELL clean.sh

mkdir keys

copy_setports ns2/named.conf.in ns2/named.conf
copy_setports ns3/named.conf.in ns3/named.conf
copy_setports ns4/named.conf.in ns4/named.conf
copy_setports ns5/named.conf.in ns5/named.conf
copy_setports ns6/named.conf.in ns6/named.conf
copy_setports ns7/named.conf.in ns7/named.conf

if $SHELL ../testcrypto.sh ed25519; then
	echo "yes" > ed25519-supported.file
fi

if $SHELL ../testcrypto.sh ed448; then
	echo "yes" > ed448-supported.file
fi

# Setup zones
(
	cd ns2
	$SHELL setup.sh
)
(
	cd ns3
	$SHELL setup.sh
)
(
	cd ns4
	$SHELL setup.sh
)
(
	cd ns5
	$SHELL setup.sh
)
(
	cd ns6
	$SHELL setup.sh
)
(
	cd ns7
	$SHELL setup.sh
)
