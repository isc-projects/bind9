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

probe_src = [dtrace_header.process('probes.d'), files('query.c')]

if config.get('HAVE_DTRACE')
    ns_probe_objects += static_library(
        'ns-probe-target',
        probe_src,
        sources: dns_gen_headers,
        build_by_default: false,
        dependencies: [uv_dep, urcu_dep],
        implicit_include_directories: false,
        include_directories: [isc_inc, dns_inc, ns_inc],
    ).extract_all_objects(recursive: false)
endif

ns_srcset.add(
    when: 'HAVE_DTRACE',
    if_true: custom_target(
        'ns-probe',
        input: [files('probes.d'), ns_probe_objects],
        output: 'ns-probes.o',
        command: [
            dtrace,
            '-G',
            '-o', '@OUTPUT@',
            '-s', '@INPUT@',
        ],
    ),
    if_false: probe_src,
)

ns_srcset.add(
    files(
        'client.c',
        'hooks.c',
        'interfacemgr.c',
        'listenlist.c',
        'notify.c',
        'server.c',
        'stats.c',
        'update.c',
        'xfrout.c',
    ),
)
