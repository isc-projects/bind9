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

foreach bench : [
    'ascii',
    'compress',
    'iterated_hash',
    'load-names',
    'qp-dump',
    'qplookups',
    'qpmulti',
    'siphash',
]
    executable(
        bench,
        files(fs.replace_suffix(bench, '.c')),
        export_dynamic: true,
        install: false,
        dependencies: [
            libisc_dep,
            libdns_dep,
            libns_dep,
            libtest_dep,
        ],
    )
endforeach

executable(
    'dns_name_fromwire',
    files(
        'dns_name_fromwire.c',
        meson.project_source_root() / 'fuzz' / 'old.c',
    ),
    export_dynamic: true,
    include_directories: '..' / '..' / 'fuzz',
    install: false,
    dependencies: [
        libisc_dep,
        libdns_dep,
        libns_dep,
        libtest_dep,
    ],
)
