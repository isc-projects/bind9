# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# $Id$

ps=`git log -1 --date=raw --pretty=format:%ad -- doc/arm/Bv9ARM.pdf | awk '{print $1;}'`
for f in doc/arm/*.html
do
	ts=`git log -1 --date=raw --pretty=format:%ad -- $f | awk '{print $1;}'`
	if test ${ts:-0} -gt ${ps:-0}
	then
		echo commit needed.
	fi
done
