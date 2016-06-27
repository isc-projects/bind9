#!/bin/sh
#
# Copyright (C) 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id$

# Given a file in the currently checked-out branch of the Git
# repository, find out in what year it was most recently committed.
# Used by merge_copyrights.

rev=`git rev-list HEAD -- "$1" | head -n 1`
git show --pretty=format:%ai $rev | head -n 1 | sed 's;-.*;;'
