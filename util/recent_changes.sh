#!/bin/sh
#
# Copyright (C) 2012, 2016, 2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Find the list of files that have been touched in the Git repository
# during the current calendar year.  This is done by walking backwards
# through the output of "git whatchanged" until a year other than the
# current one is seen.  Used by merge_copyrights.

thisyear=`date +%Y`
when="`expr $thisyear - 1`-12-31"
git whatchanged --since="$when" --pretty="" | awk '
    BEGIN { change=0 }
    NF == 0 { next; }
    $(NF-1) ~ /[AM]/ { print "./" $NF; change=1 }
    END { if (change) print "./COPYRIGHT" } ' | sort | uniq
