#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

status=0

for testscript in bin/tests/system/*/tests.sh; do
	testdir="$(dirname "${testscript}")"
	prereq="${testdir}/prereq.sh"
	if [ -e "${prereq}" ] || [ -e "${prereq}.in" ]; then
		continue
	fi
	if find "${testdir}" -type d -name "ans*" | grep -Eq "/ans[0-9]+$"; then
		echo "missing ${prereq}"
		status=1
	fi
done

exit ${status}
