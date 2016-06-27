#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#
# Clean up after system tests.
#

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh


find . -type f \( \
    -name 'K*' -o -name '*~' -o -name 'core' -o -name '*.core' \
    -o -name '*.log' -o -name '*.pid' -o -name '*.keyset' \
    -o -name named.run -o -name lwresd.run -o -name ans.run \
    -o -name '*-valgrind-*.log' \) -print | xargs rm -f

status=0

for d in $SUBDIRS
do
   test ! -f $d/clean.sh || ( cd $d && $SHELL clean.sh )
   test -d $d && find $d -type d -exec rmdir '{}' \; 2> /dev/null
done
