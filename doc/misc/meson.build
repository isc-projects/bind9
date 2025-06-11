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

sort_options = files('sort-options.pl')

cfg_test = executable(
    'cfg_test',
    files('cfg_test.c'),
    install: false,
    dependencies: [
        libisc_dep,
        libisccfg_dep,
    ],
)

options_unsorted = custom_target(
    'options-unsorted',
    capture: true,
    install: false,
    output: 'options-unsorted',
    command: [
        cfg_test,
        '--named',
        '--grammar',
    ],
)

doc_misc_targets += custom_target(
    'options',
    capture: true,
    feed: true,
    input: options_unsorted,
    install: false,
    output: 'options',
    command: [
        perl,
        sort_options,
    ],
)

rndc_grammar_unsorted = custom_target(
    'rndc.grammar-unsorted',
    capture: true,
    install: false,
    output: 'rndc.grammar-unsorted',
    command: [
        cfg_test,
        '--rndc',
        '--grammar',
    ],
)

doc_misc_targets += custom_target(
    'rndc.grammar',
    capture: true,
    feed: true,
    input: rndc_grammar_unsorted,
    install: false,
    output: 'rndc.grammar',
    command: [
        perl,
        sort_options,
    ],
)

foreach zone : [
    'primary',
    'secondary',
    'mirror',
    'forward',
    'hint',
    'stub',
    'static-stub',
    'redirect',
    'in-view',
]
    doc_misc_targets += custom_target(
        f'@zone@.zoneopt',
        capture: true,
        install: false,
        output: f'@zone@.zoneopt',
        command: [
            cfg_test,
            '--zonegrammar', zone,
        ],
    )
endforeach
