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

CLANG_FORMAT=clang-format
if [ -n "$1" ]; then
    CLANG_FORMAT="$1"
fi

CLANG_FORMAT_VERSION=$("$CLANG_FORMAT" --version | sed -e 's/clang-format version \([0-9]*\)\..*/\1/')

if [ "$CLANG_FORMAT_VERSION" -lt 11 ]; then
    echo "clang-format version 11 required"
    exit 1
fi

# use the main .clang-format for C files
"$CLANG_FORMAT" --style=file --sort-includes -i $(git ls-files '*.c')

# set up a temporary .clang-format file for headers ONLY
cp -f .clang-format .clang-format.bak
sed -e 's/\(AlignConsecutiveDeclarations\).*/\1: true/' \
    .clang-format.bak > .clang-format

"$CLANG_FORMAT" --style=file --sort-includes -i $(git ls-files '*.h')

# restore the original .clang-format file
cp -f .clang-format.bak .clang-format
rm -f .clang-format.bak
