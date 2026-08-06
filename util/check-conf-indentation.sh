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

# Ensure named configuration files in system tests are indented with tabs.
# The only leading space allowed is for a block comment continuation line.
space_indentation="$(git grep -nE '^ [^*]' -- 'bin/tests/system/*.conf' 'bin/tests/system/*.conf.*')"

if [ -n "${space_indentation}" ]; then
  echo "The following lines use spaces for indentation:"
  echo
  echo "${space_indentation}"
  echo
  echo "Please indent named configuration files with tabs."
  exit 1
fi
