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
. ../conf.sh

set -e

if $FEATURETEST --have-openssl-1.0.x; then
  cp dhparam3072.openssl_1.0.x.pem.in dhparam3072.pem
else
  cp dhparam3072.pem.in dhparam3072.pem
fi

# Setup zones
(
  cd ns9
  $SHELL setup.sh
)
(
  cd ns5
  $SHELL setup.sh
)
(
  cd ns2
  $SHELL setup.sh
)
(
  cd ns1
  $SHELL setup.sh
)
