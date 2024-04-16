#!/usr/bin/env bash

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

git clone --branch "${BIND_BASELINE_VERSION}" --depth 1 https://gitlab.isc.org/isc-projects/bind9.git "bind-${BIND_BASELINE_VERSION}"

cd "bind-${BIND_BASELINE_VERSION}"

# if [ -f configure.ac ]; then
#   echo "cannot compare autoconf builds with meson builds, skipping..."
#   exit 0
# fi

# meson setup --libdir=lib -Dcmocka=enabled -Ddeveloper=enabled -Dleak-detection=enabled -Doptimization=1 build
# meson compile -C build

# The cross-version-config-tests job would fail when a system test is
# removed from the upcoming release. To avoid this, remove the system test
# also from the $BIND_BASELINE_VERSION.

# find bin/tests/system/ -mindepth 1 -maxdepth 1 -type d -exec sh -c 'test -e ../"$0" || rm -rfv -- "$0"' {} \;

for test in bin/tests/system/*/; do
  [ -d "../${test}" ] || rm -rfv ${test}
done

cd bin/tests/system

# System tests that employ binary drivers will fail on ABI change and
# should not be run.
rm -r dlzexternal
rm -r dyndb

cp ${CI_PROJECT_DIR}/build/bin/tests/system/isctest/vars/.build_vars/TOP_BUILDDIR isctest/vars/.build_vars/
