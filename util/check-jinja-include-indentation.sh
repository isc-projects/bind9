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

# Ensure jinja2 templates in system tests use {% include_indented %} for
# indented includes: a plain {% include %} pastes the file at column zero
# and a {% filter indent %} wrapper repeats the depth by hand.
bad_includes="$(git grep -nE '^[[:blank:]]+[{]% include |[{]% filter indent' -- 'bin/tests/system/*.j2' 'bin/tests/system/*.j2.manual')"

if [ -n "${bad_includes}" ]; then
  echo "The following template lines indent an include by hand:"
  echo
  echo "${bad_includes}"
  echo
  echo "Please use {% include_indented \"...\" %} instead."
  exit 1
fi
