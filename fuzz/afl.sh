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

# The AFL main() reads a single input from stdin, so replay the corpus
# one file per process.

corpus="${1}/$(basename "${2}").in"
tested=0

for input in "${corpus}"/*; do
  [ -f "${input}" ] || continue
  if ! "${2}" <"${input}"; then
    echo "Failed on corpus input: ${input}" >&2
    exit 1
  fi
  tested=$((tested + 1))
done

if [ "${tested}" -eq 0 ]; then
  echo "No corpus inputs tested in ${corpus}" >&2
  exit 1
fi

echo "Tested ${tested} corpus inputs from ${corpus}"
