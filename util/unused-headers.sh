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

# Report tracked header files which no file in the repository includes.

# Gather every #include directive appearing in a C source or header file,
# or in a SWIG interface file.  Other file types (documentation, cocci
# patches, test data) do mention headers, but such a mention is not a use.
includes=$(git grep -hoE '#include [<"][^">]+[">]' -- '*.c' '*.h' '*.i' | sort -u)

# Reduce the quoted includes to the base name of the included file and the
# angle-bracketed ones to the path the header is included by.
quoted_includes=$(printf '%s\n' "${includes}" | sed -n 's|^#include "\(.*\)"$|\1|p' | sed 's|.*/||' | sort -u)
angled_includes=$(printf '%s\n' "${includes}" | sed -n 's|^#include <\(.*\)>$|\1|p' | sort -u)

if [ -z "${quoted_includes}" ] || [ -z "${angled_includes}" ]; then
  echo "No #include directives found, giving up"
  exit 1
fi

unused_headers=$(
  # Private headers are included by their base name; report those whose base
  # name is not part of any quoted include.
  git ls-files -- '*.h' ':!:*include*' ':!:*rdata*' \
    | sed 's|.*/\(.*\.h\)|\1|' \
    | grep -Fxv -e "${quoted_includes}"

  # Public headers are included by their path relative to the "include"
  # directory; report those whose path is not part of any angle-bracketed
  # include.
  git ls-files -- '*include/*.h' \
    | sed 's|.*/include\/\(.*\.h\)|\1|' \
    | grep -Fxv -e "${angled_includes}"
)

if [ -n "${unused_headers}" ]; then
  printf 'Following headers are unused:\n%s\n' "${unused_headers}"
  exit 1
fi
