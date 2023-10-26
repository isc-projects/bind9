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

ignored_yet_tracked="$(git ls-files --cached --ignored --exclude-standard | git check-ignore --verbose --stdin --no-index)"

if [ -n "${ignored_yet_tracked}" ]; then
  echo "The following .gitignore files contain patterns matching tracked files:"
  echo
  echo "${ignored_yet_tracked}"
  echo
  echo "Please adjust the contents of the above .gitignore files and/or the names of the tracked files."
  exit 1
fi
