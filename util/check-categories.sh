# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

list1=$(
	grep LOGCATEGORY lib/*/include/*/*.h bin/named/include/named/*.h |
	grep "#define.*(&" |
	sed -e 's/.*LOGCATEGORY_\([A-Z_]*\).*/\1/' -e 's/^RRL$/rate-limit/' |
	tr '[A-Z]' '[a-z]' |
	tr _ - |
	sed 's/^tat$/trust-anchor-telemetry/' |
	sort -u
)
list2=$(
	awk '$1 == "|" && $3 == "|" && $NF == "|" && $2 ~ /^``.*``$/ { print $2 }' doc/arm/logging-categories.rst |
	sed 's/``//g' |
	sort -u
)
status=0
for i in $list1
do
	ok=no
	for j in $list2
	do
		if test $i = $j
		then
			ok=yes
		fi
	done
	if test $ok = no
	then
		echo "$i missing from documentation."
		status=1
	fi
done
for i in $list2
do
	ok=no
	for j in $list1
	do
		if test $i = $j
		then
			ok=yes
		fi
	done
	if test $ok = no
	then
		echo "$i not in code."
		status=1
	fi
done
exit $status
