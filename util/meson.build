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

configure_file(
    input: 'check-make-install.in',
    output: 'check-make-install',
    configuration: {
        'abs_builddir': meson.project_build_root(),
        'abs_top_srcdir': meson.project_source_root(),
        'prefix': prefix,
    },
)
