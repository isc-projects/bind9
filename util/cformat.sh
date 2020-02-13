#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# use the main .clang-format for C files
find bin lib -name "*.c" |
    xargs clang-format --style=file --sort-includes -i

# set up a temporary .clang-format file for headers ONLY
cp -f .clang-format .clang-format.bak
sed -e 's/\(AlignConsecutiveDeclarations\).*/\1: true/' \
    -e 's/\(AlwaysBreakAfterReturnType\).*/\1: All/' \
    .clang-format.bak > .clang-format

# modify header files
find bin lib -name "*.h" |
    xargs clang-format --style=file --sort-includes -i

# restore the original .clang-format file
cp -f .clang-format.bak .clang-format
rm -f .clang-format.bak
