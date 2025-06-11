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

set -euo pipefail

extension=
dir=
while getopts d:e: opt; do
  case "$opt" in
    e) extension=$OPTARG ;;
    d) dir=$OPTARG ;;
    \?)
      echo "meson-glob.sh -d DIR -e EXTENSION"
      exit 1
      ;;
  esac
done

echo "files("

pushd ${dir:-.} >/dev/null
for file in ./*.${extension:-c}; do
  echo "    '${file:2}',"
done
popd >/dev/null

echo ")"
