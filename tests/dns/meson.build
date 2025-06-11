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

dns_tests = [
    'acl',
    'badcache',
    'db',
    'dbdiff',
    'dbiterator',
    'dbversion',
    'dispatch',
    'dns64',
    'dst',
    'ede',
    'keytable',
    'master',
    'name',
    'nametree',
    'nsec3',
    'nsec3param',
    'private',
    'qp',
    'qpdb',
    'qpmulti',
    'qpzone',
    'rdata',
    'rdataset',
    'rdatasetstats',
    'resconf',
    'resolver',
    'rsa',
    'sigs',
    'time',
    'transport',
    'tsig',
    'unreachcache',
    'update',
    'zonefile',
    'zonemgr',
    'zt',
]

if config.has('HAVE_GEOIP2')
    dns_tests += 'geoip'
endif

if config.has('HAVE_DNSTAP')
    dns_tests += 'dnstap'
endif

master_data = []
subdir('testdata/master')

foreach unit : dns_tests
    test_bin = executable(
        unit,
        files(f'@unit@_test.c'),
        build_by_default: false,
        export_dynamic: true,
        install: false,
        c_args: [
            '-DBUILDDIR="@0@"'.format(meson.current_build_dir()),
            '-DSRCDIR="@0@"'.format(meson.current_source_dir()),
            '-DTESTS_DIR="@0@"'.format(meson.current_source_dir()),
            '-DTEST_GEOIP_DATA="@0@"'.format(
                meson.project_source_root() / 'bin' / 'tests' / 'system' / 'geoip2' / 'data',
            ),
        ],
        dependencies: [
            libisc_dep,
            libdns_dep,
            libns_dep,
            libtest_dep,

            openssl_dep,

            cmocka_dep,
            dnstap_dep,
            maxminddb_dep,
        ],
    )

    test(
        unit,
        test_bin,
        depends: master_data,
        suite: 'dns',
        timeout: 300,
        workdir: meson.current_source_dir(),
    )
endforeach
