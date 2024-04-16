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

test_inc = include_directories(
    'include',
    '..' / 'lib' / 'isc',
    '..' / 'lib' / 'dns',
)

libtest = shared_library(
    'bindtest',
    files(
        'libtest/dns.c',
        'libtest/isc.c',
        'libtest/ns.c',
        'libtest/qp.c',
        'ns/netmgr_wrap.c',
    ),
    build_by_default: false,
    include_directories: test_inc,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
        libns_dep,
    ],
)

libtest_dep = declare_dependency(
    link_with: libtest,
    include_directories: test_inc,
)

if not cmocka_dep.found()
    subdir_done()
endif

subdir('bench')
subdir('dns')
subdir('isc')
subdir('isccfg')
subdir('ns')
