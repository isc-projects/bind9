#!/bin/sh
#
# Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f */K* */*.signed */trusted.conf */*.jnl */*.bk
rm -f dsset-. ns1/dsset-.
rm -f ns*/named.lock
rm -f */managed-keys.bind* */named.secroots
rm -f */managed.conf ns1/managed.key ns1/managed.key.id
rm -f */named.memstats */named.run
rm -f dig.out* delv.out* rndc.out* signer.out*
rm -f ns1/named.secroots ns1/root.db.signed* ns1/root.db.tmp
rm -f ns1/named.conf
