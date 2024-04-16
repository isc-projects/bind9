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

named_inc_p += include_directories('include')

named_srcset.add(when: maxminddb_dep, if_true: files('geoip.c'))

named_srcset.add(
    configure_file(
        input: 'xsl_c.in',
        output: 'xsl.c',
        configuration: {
            'XSL': '\\n'.join(fs.read('bind9.xsl').strip().replace('"', '\\"').split('\n')),
        },
    ),

    files(
        'builtin.c',
        'config.c',
        'control.c',
        'controlconf.c',
        'dlz_dlopen_driver.c',
        'fuzz.c',
        'log.c',
        'logconf.c',
        'main.c',
        'os.c',
        'server.c',
        'statschannel.c',
        'tkeyconf.c',
        'transportconf.c',
        'tsigconf.c',
        'zoneconf.c',
    ),
)

manrst_srcset.add(
    files(
        'named.conf.rst',
        'named.rst',
    ),
)
