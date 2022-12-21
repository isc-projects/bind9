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

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

symlink_alg=$(basename $(dirname $PWD) | awk -F- '{ print $2 }')
if [ "$symlink_alg" == "eddsa" ]; then
	echo_i "Setting algorithm to ED25519"
	DEFAULT_ALGORITHM=ED25519
fi

zone=.
zonefile=root.db

# a key for a trust island
islandkey=$($KEYGEN -a ${DEFAULT_ALGORITHM} -b $DEFAULT_BITS -r $RANDFILE -qfk island.)

# a key with unsupported algorithm
unsupportedkey=Kunknown.+255+00000
cp unsupported-managed.key "${unsupportedkey}.key"

# root key
rootkey=`cat ../ns1/managed.key`
cp "../ns1/${rootkey}.key" .

# Configure the resolving server with a managed trusted key.
keyfile_to_managed_keys $unsupportedkey $islandkey $rootkey > managed.conf
