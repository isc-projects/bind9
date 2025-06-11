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

dns_gen_headers += [
    custom_target(
        'dns-header-enumtype',
        output: 'enumtype.h',
        depend_files: dns_header_depfiles,
        capture: true,
        install: false,
        command: [dns_header_gen, '-s', '@CURRENT_SOURCE_DIR@' / '..' / '..', '-t'],
    ),

    custom_target(
        'dns-header-enumclass',
        output: 'enumclass.h',
        depend_files: dns_header_depfiles,
        capture: true,
        install: false,
        command: [dns_header_gen, '-s', '@CURRENT_SOURCE_DIR@' / '..' / '..', '-c'],
    ),

    custom_target(
        'dns-header-rdatastruct',
        output: 'rdatastruct.h',
        depend_files: dns_header_depfiles,
        capture: true,
        install: false,
        install_dir: get_option('includedir') / 'dns',
        command: [
            dns_header_gen,
            '-s', '@CURRENT_SOURCE_DIR@' / '..' / '..',
            '-i',
            '-P', '@CURRENT_SOURCE_DIR@' / '..' / '..' / 'rdata' / 'rdatastructpre.h',
            '-S', '@CURRENT_SOURCE_DIR@' / '..' / '..' / 'rdata' / 'rdatastructsuf.h',
        ],
    ),
]
