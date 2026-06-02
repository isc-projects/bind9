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

echo_i "ns2/setup.sh"

setup() {
  zone="$1"
  echo_i "setting up zone: $zone"
  infile="${zone}.db.in"
  zonefile="${zone}.db"

  cp ../ns3/dsset-ns3-model2.$zone. .
  cp ../ns4/dsset-ns4-model2.$zone. .

  KSK=$($KEYGEN -q -a $DEFAULT_ALGORITHM -L 3600 -f KSK $zone)
  ZSK=$($KEYGEN -q -a $DEFAULT_ALGORITHM -L 3600 $zone)
  $DSFROMKEY $KSK.key >dsset-ns2-${zone}.

  cat $infile $KSK.key $ZSK.key >$zonefile
  $SIGNER -g -o $zone $zonefile >/dev/null 2>&1
}

setup "multisigner"
setup "update-any"
setup "bad-dsync"
setup "secondary"
