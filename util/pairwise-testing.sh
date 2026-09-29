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

set -e
set -o pipefail

NAMED_CONF="
options {
	port 5300;
	listen-on { 127.0.0.1; };
	listen-on-v6 { ::1; };
};

zone \".\" {
	type primary;
	file \"zone.db\";
};
"

ZONE_CONTENTS="
\$TTL 300
@		SOA	localhost. localhost.localhost. 1 30 10 3600000 300
@		NS	localhost.
localhost	A	127.0.0.1
		AAAA	::1
"

if ! command -v pict >/dev/null 2>&1; then
  echo "This script requires the 'pict' utility to be present in PATH." >&2
  exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "This script requires the 'timeout' utility to be present in PATH." >&2
  exit 1
fi

meson setup build-pairwise-default

meson introspect build-pairwise-default --buildoptions | ./util/pairwise-construct.jq >pairwise-model.txt

pict pairwise-model.txt | tr "\t" " " | sed "1d" >pairwise-commands.txt

rm -rf build-pairwise-default

runid=0
while read -r -a configure_switches; do
  runid=$((runid + 1))
  mkdir "pairwise-${runid}"
  cd "pairwise-${runid}"
  echo "Configuration:" "${configure_switches[@]}" | tee "../pairwise-output.${runid}.txt"
  meson setup build .. "${configure_switches[@]}" >>"../pairwise-output.${runid}.txt" 2>&1
  echo "Building..."
  ninja -C build >>"../pairwise-output.${runid}.txt" 2>&1
  echo "Running..."
  echo "${NAMED_CONF}" >named.conf
  echo "${ZONE_CONTENTS}" >zone.db
  # Let named run for a while, then ask it to shut down using SIGTERM
  # (which is what "timeout" sends once the time is up) and check that
  # it exited cleanly.  Thanks to --preserve-status, a crash or an
  # assertion failure at startup or during shutdown, as well as a
  # shutdown which does not complete before "timeout" resorts to
  # SIGKILL, all result in a non-zero exit code.
  ret=0
  timeout --preserve-status --kill-after=5s 5s build/named -c named.conf -g >>"../pairwise-output.${runid}.txt" 2>&1 || ret=$?
  if [ "${ret}" -ne 0 ]; then
    echo "named exited with a non-zero exit code (${ret})"
    exit 1
  fi
  cd ..
  rm -rf "pairwise-${runid}"
done <pairwise-commands.txt
