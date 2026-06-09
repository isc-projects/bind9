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

isccfg_tests = [
    'duration',
    'grammar',
    'parser',
]

run_command(
    check_test_registration,
    meson.current_source_dir(),
    isccfg_tests,
    check: true,
)

foreach unit : isccfg_tests
    test_bin = executable(
        unit,
        files(f'@unit@_test.c'),
        build_by_default: false,
        export_dynamic: true,
        install: false,
        sources: default_sanitize_options,
        dependencies: [
            libisc_dep,
            libisccfg_dep,
            libtest_dep,

            cmocka_dep,
        ],
    )

    test(
        unit,
        test_bin,
        env: test_env,
        suite: ['isccfg', 'cmocka'],
        timeout: 300,
        workdir: meson.current_source_dir(),
    )
endforeach
