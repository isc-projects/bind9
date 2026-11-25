#!/bin/sh -ex

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

exec "${2}" "${1}/$(basename "${2}").in" -runs=0 -error_exitcode=1 -print_pcs=1 -print_final_stats=1 -print_corpus_stats=1 -print_coverage=1
