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

isc_test = [
    'ascii',
    'async',
    'buffer',
    'counter',
    'crypto',
    'dnsstream_utils',
    'errno',
    'file',
    'hash',
    'hashmap',
    'heap',
    'histo',
    'hmac',
    'ht',
    'job',
    'lex',
    'loop',
    'md',
    'mem',
    'mutex',
    'netaddr',
    'parse',
    'proxyheader',
    'proxystream',
    'proxyudp',
    'quota',
    'radix',
    'ratelimiter',
    'regex',
    'result',
    'rwlock',
    'safe',
    'siphash',
    'sockaddr',
    'spinlock',
    'stats',
    'symtab',
    'tcp',
    'tcpdns',
    'time',
    'timer',
    'tls',
    'tlsdns',
    'udp',
    'url',
    'utf8',
    'work',
]

flaky_isc_test = [
    'proxystream',
]

is_el8 = run_command('grep', '-q', '-F', 'platform:el8', '/etc/os-release', check: false).returncode() == 0

_all_isc_test = isc_test + ['doh']
run_command(
    check_test_registration,
    meson.current_source_dir(),
    _all_isc_test,
    check: true,
)

if config.has('HAVE_LIBNGHTTP2') and not is_el8
    isc_test += 'doh'
endif

foreach unit : isc_test
    test_bin = executable(
        unit,
        files(
            f'@unit@_test.c',
            'netmgr_common.c',
            'stream_shutdown.c',
        ),
        build_by_default: false,
        export_dynamic: true,
        install: false,
        sources: default_sanitize_options,
        dependencies: [
            libisc_dep,
            libtest_dep,

            m_dep,
            openssl_dep,

            cmocka_dep,
            nghttp2_dep,
        ],
    )

    suites = ['isc', 'cmocka']
    timeout = 300
    unit_env = test_env
    if unit in flaky_isc_test
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
        env: unit_env,
        suite: suites,
        timeout: timeout,
        workdir: meson.current_source_dir(),
    )
endforeach
