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

foreach unit : [
    'notify',
    'plugin',
    'query',
]
    test_bin = executable(
        unit,
        files(f'@unit@_test.c', 'netmgr_wrap.c'),
        build_by_default: false,
        export_dynamic: true,
        install: false,
        dependencies: [
            libisc_dep,
            libdns_dep,
            libns_dep,
            libtest_dep,

            openssl_dep,

            cmocka_dep,
            nghttp2_dep,
        ],
    )

    test(
        unit,
        test_bin,
        suite: 'ns',
        timeout: 300,
        workdir: meson.current_source_dir(),
    )
endforeach
