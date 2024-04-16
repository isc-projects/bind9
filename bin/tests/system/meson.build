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

configure_file(
    input: 'ifconfig.sh.in',
    output: 'ifconfig.sh',
    configuration: {
        'SYSTEM': target_machine.system(),
    },
)

subdir('isctest' / 'vars' / '.build_vars')

system_test_binaries += {
    # 'bigkey': files('rsabigexponent' / 'bigkey.c'),
    'feature-test': files('feature-test.c'),
    'gencheck': files('rndc' / 'gencheck.c'),
    'makejournal': files('makejournal.c'),
    'pipequeries': files('pipelined' / 'pipequeries.c'),
    'wire-test': files('wire-test.c'),
}

system_test_libraries += {
    'driver-async': files('hooks' / 'driver' / 'test-async.c'),
    'driver-dlzexternal': files('dlzexternal' / 'driver' / 'driver.c'),
    'driver-sample': files(
        'dyndb' / 'driver' / 'db.c',
        'dyndb' / 'driver' / 'driver.c',
        'dyndb' / 'driver' / 'instance.c',
        'dyndb' / 'driver' / 'log.c',
        'dyndb' / 'driver' / 'syncptr.c',
        'dyndb' / 'driver' / 'zone.c',
    ),
}
