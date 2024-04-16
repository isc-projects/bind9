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

if [ -z "$BIND_SOURCE_ROOT" ] || [ -z "$BIND_BUILD_ROOT" ]; then
  echo "meson-system-test-init.sh must be run within meson!"
  exit 1
fi

cp $BIND_BUILD_ROOT/bin/tests/system/isctest/vars/.build_vars/TOP_BUILDDIR $BIND_SOURCE_ROOT/bin/tests/system/isctest/vars/.build_vars/TOP_BUILDDIR
cp $BIND_BUILD_ROOT/bin/tests/system/ifconfig.sh $BIND_SOURCE_ROOT/bin/tests/system/ifconfig.sh
