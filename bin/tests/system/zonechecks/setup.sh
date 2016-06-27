#!/bin/sh
#
# Copyright (C) 2012-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL clean.sh

test -r $RANDFILE || $GENRANDOM 400 $RANDFILE

$SHELL ../genzone.sh 1 > ns1/master.db
$SHELL ../genzone.sh 1 > ns1/duplicate.db
cp bigserial.db ns1/
cd ns1
touch master.db.signed
echo '$INCLUDE "master.db.signed"' >> master.db
$KEYGEN -r $RANDFILE -3q master.example > /dev/null 2>&1
$KEYGEN -r $RANDFILE -3qfk master.example > /dev/null 2>&1
$SIGNER -SD -o master.example master.db > /dev/null 2>&1
echo '$INCLUDE "soa.db"' > reload.db
echo '@ 0 NS .' >> reload.db
echo '@ 0 SOA . . 1 0 0 0 0' > soa.db
