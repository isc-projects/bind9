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
    'byaddr',
    'db',
    'dbdiff',
    'dbiterator',
    'dbversion',
    'deleg',
    'diff',
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
    'skr',
    'time',
    'transport',
    'tsig',
    'unreachcache',
    'update',
    'vecheader',
    'zonefile',
    'zonemgr',
    'zt',
]

flaky_dns_tests = [
    'qpdb',
]

_all_dns_tests = dns_tests + ['geoip', 'dnstap']
run_command(
    check_test_registration,
    meson.current_source_dir(),
    _all_dns_tests,
    check: true,
)

if config.has('HAVE_GEOIP2')
    dns_tests += 'geoip'
endif

if config.has('HAVE_DNSTAP')
    dns_tests += 'dnstap'
endif

master_data = []
subdir('testdata/master')

deleg_probe_stub = custom_target(
    'deleg-test-probes-dns',
    input: files('../../lib/dns/probes-dns.d'),
    output: 'probes-dns.h',
    command: [
        files('../../util/dtrace.sh'),
        '-h',
        '-s', '@INPUT@',
        '-o', '@OUTPUT@',
    ],
)

foreach unit : dns_tests
    extra_sources = []
    if unit == 'deleg'
        extra_sources += deleg_probe_stub
    endif
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
        sources: [default_sanitize_options, extra_sources],
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

    suites = ['dns', 'cmocka']
    timeout = 300
    unit_env = test_env
    if unit in flaky_dns_tests
        suites += 'flaky'
        # Pass FLAKY and TIMEOUT to the test wrapper so it can retry
        # appropriately.  Build a fresh environment instead of mutating the
        # shared test_env, which meson stores by reference and would otherwise
        # leak these variables into every other test.
        unit_env = environment(
            test_env_vars + {'FLAKY': '1', 'TIMEOUT': timeout.to_string()},
        )
    endif
    test(
        unit,
        test_bin,
        depends: master_data,
        env: unit_env,
        suite: suites,
        timeout: timeout,
        workdir: meson.current_source_dir(),
    )
endforeach
