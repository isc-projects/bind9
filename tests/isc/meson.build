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
    'random',
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
    'work',
]

flaky_isc_test = [
    'proxystream',
    'random',
]

if config.has('HAVE_LIBNGHTTP2')
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
        dependencies: [
            libisc_dep,
            libtest_dep,

            m_dep,
            openssl_dep,

            cmocka_dep,
            nghttp2_dep,
        ],
    )

    suites = ['isc']
    if unit in flaky_isc_test
        suites += 'flaky'
    endif
    test(
        unit,
        test_bin,
        suite: suites,
        timeout: 300,
        workdir: meson.current_source_dir(),
    )
endforeach
