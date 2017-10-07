# Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

list1=`grep LOGCATEGORY lib/*/include/*/*.h bin/named/include/named/*.h |
grep "#define.*(&" |
sed -e 's/.*LOGCATEGORY_\([A-Z_]*\).*/\1/' -e 's/^RRL$/rate-limit/' |
tr '[A-Z]' '[a-z]' |
tr _ - | sed 's/^tat$/trust-anchor-telemetry/' | sort -u`
list2=`sed -n 's;.*<para><command>\(.*\)</command></para>;\1;p' doc/arm/logging-categories.xml | tr '[A-Z]' '[a-z]' | sort -u`
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
	fi
done
