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

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

test -r $RANDFILE || $GENRANDOM $RANDOMSIZE $RANDFILE

pzone=parent.nil
czone=child.parent.nil

echo_i "generating keys"

# active zsk
zsk=`$KEYGEN -q -r $RANDFILE $czone`
echo $zsk > zsk.key

# not yet published or active
pending=`$KEYGEN -q -r $RANDFILE -P none -A none $czone`
echo $pending > pending.key

# published but not active
standby=`$KEYGEN -q -r $RANDFILE -A none $czone`
echo $standby > standby.key

# inactive
inact=`$KEYGEN -q -r $RANDFILE -P now-24h -A now-24h -I now $czone`
echo $inact > inact.key

# active ksk
ksk=`$KEYGEN -q -r $RANDFILE -fk $czone`
echo $ksk > ksk.key

# published but not YET active; will be active in 15 seconds
rolling=`$KEYGEN -q -r $RANDFILE -fk $czone`
$SETTIME -A now+15s $rolling > /dev/null
echo $rolling > rolling.key

# revoked
revoke1=`$KEYGEN -q -r $RANDFILE -fk $czone`
echo $revoke1 > prerev.key
revoke2=`$REVOKE $revoke1`
echo $revoke2 | sed -e 's#\./##' -e "s/\.key.*$//" > postrev.key

pzsk=`$KEYGEN -q -r $RANDFILE $pzone`
echo $pzsk > parent.zsk.key

pksk=`$KEYGEN -q -r $RANDFILE -fk $pzone`
echo $pksk > parent.ksk.key

oldstyle=`$KEYGEN -Cq -r $RANDFILE $pzone`
echo $oldstyle > oldstyle.key

