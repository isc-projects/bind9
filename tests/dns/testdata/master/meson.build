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

master_data += custom_target(
    'master-data-12',
    feed: true,
    capture: true,
    input: files('master12.data.in'),
    output: 'master12.data',
    command: [
        perl,
        '-e', 'use strict;',
        '-e', 'chomp(my $line = <STDIN>);',
        '-e', 'print pack("H*", $line);',
    ],
)

master_data += custom_target(
    'master-data-13',
    feed: true,
    capture: true,
    input: files('master13.data.in'),
    output: 'master13.data',
    command: [
        perl,
        '-e', 'use strict;',
        '-e', 'chomp(my $line = <STDIN>);',
        '-e', 'print pack("H*", $line);',
    ],
)

master_data += custom_target(
    'master-data-14',
    feed: true,
    capture: true,
    input: files('master14.data.in'),
    output: 'master14.data',
    command: [
        perl,
        '-e', 'use strict;',
        '-e', 'chomp(my $line = <STDIN>);',
        '-e', 'print pack("H*", $line);',
    ],
)

configure_file(
    input: 'master18.data.in',
    output: 'master18.data',
    configuration: {
        'TOP_SRCDIR': meson.project_source_root(),
    },
)
