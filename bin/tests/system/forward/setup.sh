#!/bin/sh

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

. ../conf.sh

if $FEATURETEST --have-openssl-1.0.x; then
  cp dhparam3072.openssl_1.0.x.pem.in dhparam3072.pem
else
  cp dhparam3072.pem.in dhparam3072.pem
fi

(
  cd ns1
  $SHELL sign.sh
)
