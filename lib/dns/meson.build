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

probe_src = [dtrace_header.process('probes.d'), files('xfrin.c')]

# dns_inc += include_directories('include')
dns_inc_p += include_directories('.')

dns_header_depfiles = []
subdir('rdata')

dns_gen_headers = []

dns_header_gen = executable(
    'gen',
    files('gen.c'),
    install: false,
    native: true,
)

subdir('include')

dns_srcset.add(dns_gen_headers)
dns_srcset.add(when: dnstap_dep, if_true: files('dnstap.c'))
dns_srcset.add(when: maxminddb_dep, if_true: files('geoip2.c'))
dns_srcset.add(when: [gssapi_dep, krb5_dep], if_true: files('gssapi_link.c'))

dns_srcset.add(
    custom_target(
        'dns-code',
        output: 'code.h',
        depend_files: dns_header_depfiles,
        capture: true,
        command: [dns_header_gen, '-s', meson.current_source_dir()],
    ),
)

if config.get('HAVE_DTRACE')
    dns_probe_objects += static_library(
        'dns-probe-target',
        probe_src,
        build_by_default: false,
        dependencies: urcu_dep,
        implicit_include_directories: false,
        include_directories: [isc_inc, dns_inc, dns_inc_p],
        sources: dns_gen_headers,
    ).extract_all_objects(recursive: false)
endif

dns_srcset.add(
    when: 'HAVE_DTRACE',
    if_true: custom_target(
        'dns-probe',
        input: [files('probes.d'), dns_probe_objects],
        output: 'dns-probes.o',
        command: [
            dtrace,
            '-G',
            '-o', '@OUTPUT@',
            '-s', '@INPUT@',
        ],
    ),
    if_false: probe_src,
)

dns_srcset.add(
    files(
        'acl.c',
        'adb.c',
        'badcache.c',
        'byaddr.c',
        'cache.c',
        'callbacks.c',
        'catz.c',
        'client.c',
        'clientinfo.c',
        'compress.c',
        'db.c',
        'dbiterator.c',
        'diff.c',
        'dispatch.c',
        'dlz.c',
        'dns64.c',
        'dnssec.c',
        'ds.c',
        'dst_api.c',
        'dst_parse.c',
        'dyndb.c',
        'ecs.c',
        'ede.c',
        'fixedname.c',
        'forward.c',
        'gssapictx.c',
        'hmac_link.c',
        'ipkeylist.c',
        'iptable.c',
        'journal.c',
        'kasp.c',
        'key.c',
        'keydata.c',
        'keymgr.c',
        'keystore.c',
        'keytable.c',
        'lib.c',
        'master.c',
        'masterdump.c',
        'message.c',
        'name.c',
        'nametree.c',
        'ncache.c',
        'nsec.c',
        'nsec3.c',
        'nta.c',
        'openssl_link.c',
        'opensslecdsa_link.c',
        'openssleddsa_link.c',
        'opensslrsa_link.c',
        'order.c',
        'peer.c',
        'private.c',
        'qp.c',
        'qpcache.c',
        'qpzone.c',
        'rcode.c',
        'rdata.c',
        'rdatalist.c',
        'rdataset.c',
        'rdatasetiter.c',
        'rdataslab.c',
        'remote.c',
        'request.c',
        'resconf.c',
        'resolver.c',
        'result.c',
        'rootns.c',
        'rpz.c',
        'rriterator.c',
        'rrl.c',
        'sdlz.c',
        'skr.c',
        'soa.c',
        'ssu.c',
        'ssu_external.c',
        'stats.c',
        'time.c',
        'tkey.c',
        'transport.c',
        'tsig.c',
        'ttl.c',
        'unreachcache.c',
        'update.c',
        'validator.c',
        'view.c',
        'zone.c',
        'zoneverify.c',
        'zt.c',
    ),
)
