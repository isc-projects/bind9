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

unused_headers=$(
	git ls-files -- '*.h' ':!:*include*' ':!:*rdata*' ':!:*win32*' |
	sed 's|.*/\(.*\.h\)|\1|' |
	while read -r header; do
		git grep -q "#include \".*${header}\"" || echo "${header}"
	done

	git ls-files -- '*include/*.h' |
	sed 's|.*/include\/\(.*\.h\)|\1|' |
	while read -r header; do
		git grep -q "#include <${header}>" || echo "${header}"
	done
)

if [ -n "${unused_headers}" ]; then
	echo -e "Following headers are unused:\n${unused_headers}"
	exit 1
fi
