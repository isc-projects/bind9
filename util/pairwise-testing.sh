#!/bin/bash
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

set -e
set -o pipefail

grep -v -F "pairwise: skip" configure.ac | sed -n -E "s|.*# \[pairwise: (.*)\]|\1|p" | \
	while read -r SWITCH; do
	echo "${RANDOM}: ${SWITCH}"
done > pairwise-model.txt

pict pairwise-model.txt | tr "\t" " " | sed "1d" > pairwise-commands.txt

while read -r -a configure_switches; do
	runid=${RANDOM}
	mkdir "pairwise-${runid}"
	cd "pairwise-${runid}"
	echo "${configure_switches[@]}" | tee "../pairwise-output.${runid}.txt"
	../configure --enable-option-checking=fatal "${configure_switches[@]}" >> "../pairwise-output.${runid}.txt" 2>&1
	make "-j${BUILD_PARALLEL_JOBS:-1}" all >> "../pairwise-output.${runid}.txt" 2>&1
	cd ..
	rm -rf "pairwise-${runid}" "pairwise-output.${runid}.txt"
done < pairwise-commands.txt
