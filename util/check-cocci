#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

ret=0
for spatch in cocci/*.spatch; do
  patch="$(dirname "$spatch")/$(basename "$spatch" .spatch).patch"
  : >"$patch"
  echo "Applying semantic patch $spatch..."
  spatch --jobs "${TEST_PARALLEL_JOBS:-1}" --sp-file "$spatch" --use-gitgrep --dir "." --very-quiet --include-headers "$@" >>"$patch" 2>cocci.stderr
  cat cocci.stderr
  if grep -q -e "parse error" cocci.stderr; then
    ret=1
  fi
  if [ "$(wc <"$patch" -l)" -gt "0" ]; then
    cat "$patch"
    ret=1
  else
    rm "$patch"
  fi
done

rm -f cocci.stderr

exit $ret
