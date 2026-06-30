#!/bin/bash

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

# Fail if an rdata source file under lib/dns/rdata is not registered as an
# input of the generated lib/dns/code.h header, i.e. missing from
# dns_header_depfiles in the relevant meson.build.  An unregistered file is
# still compiled into BIND 9 (gen.c scans the directories directly), but
# editing it does not trigger regeneration of code.h.
#
# Usage: check-rdata-registration.sh [BUILDDIR]   (BUILDDIR defaults to "build")

set -euo pipefail

builddir=${1:-build}

registered=$(mktemp)
ondisk=$(mktemp)
trap 'rm -f "$registered" "$ondisk"' EXIT

# Registered files: the inputs lib/dns/code.h is generated from, reduced to
# repo-relative lib/dns/rdata/<class>/<file> paths.
ninja -C "$builddir" -t inputs lib/dns/code.h \
  | sed -n 's@^.*\(lib/dns/rdata/[^/]*/[^/]*\)$@\1@p' \
  | sort -u >"$registered"

# rdata-type source files on disk (e.g. soa_6.c, nsap-ptr_23.h).  Skeleton
# files such as proforma.c are not type-named and are skipped, mirroring
# gen.c's filename filter.
printf '%s\n' lib/dns/rdata/*/*.c lib/dns/rdata/*/*.h \
  | grep -E '/[-0-9a-z]+_[0-9]+\.[ch]$' \
  | sort -u >"$ondisk"

unregistered=$(comm -23 "$ondisk" "$registered")

if [ -n "$unregistered" ]; then
  echo "$unregistered" | while read -r file; do
    echo "Rdata file $file is not registered for header" \
      "generation (add it to dns_header_depfiles in the" \
      "meson.build)" >&2
  done
  exit 1
fi

exit 0
