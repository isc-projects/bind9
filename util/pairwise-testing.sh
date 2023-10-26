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

grep -v -F "pairwise: skip" configure.ac | sed -n -E "s|.*# \[pairwise: (.*)\]|\1|p" \
  | while read -r SWITCH; do
    echo "${RANDOM}: ${SWITCH}"
  done >pairwise-model.txt

pict pairwise-model.txt | tr "\t" " " | sed "1d" >pairwise-commands.txt

while read -r -a configure_switches; do
  runid=${RANDOM}
  mkdir "pairwise-${runid}"
  cd "pairwise-${runid}"
  echo "Configuration:" "${configure_switches[@]}" | tee "../pairwise-output.${runid}.txt"
  ../configure --enable-option-checking=fatal "${configure_switches[@]}" >>"../pairwise-output.${runid}.txt" 2>&1
  echo "Building..."
  make "-j${BUILD_PARALLEL_JOBS:-1}" all >>"../pairwise-output.${runid}.txt" 2>&1
  echo "Running..."
  echo "${NAMED_CONF}" >named.conf
  echo "${ZONE_CONTENTS}" >zone.db
  ret=0
  timeout --kill-after=5s 5s bin/named/named -c named.conf -g >>"../pairwise-output.${runid}.txt" 2>&1 || ret=$?
  # "124" is the exit code "timeout" returns when it terminates
  # the command; in other words, the command-under-test times
  # out, i.e., was still running and didn't crash.
  if [ "${ret}" -ne 124 ]; then
    echo "Unexpected exit code from the 'timeout' utility (${ret})"
    exit 1
  fi
  # "timeout" is unable to report a crash on shutdown via its exit
  # code.
  cd ..
  rm -rf "pairwise-${runid}" "pairwise-output.${runid}.txt"
done <pairwise-commands.txt
