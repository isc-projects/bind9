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

probe_src = []

probe_src += [dtrace_header.process('probes.d'), files('job.c')]
if config.get('USE_PTHREAD_RWLOCK') != 1
    probe_src += files('rwlock.c')
endif

# isc_inc += include_directories('include')
isc_inc_p += include_directories('.')

subdir('netmgr')

isc_srcset.add(
    m_dep,
    openssl_dep,
    thread_dep,
    urcu_dep,
    uv_dep,
)

isc_srcset.add(when: 'HAVE_JEMALLOC', if_true: jemalloc_dep)
isc_srcset.add(when: 'HAVE_JSON_C', if_true: json_c_dep)
isc_srcset.add(when: 'HAVE_LIBXML2', if_true: xml2_dep)
isc_srcset.add(when: 'HAVE_ZLIB', if_true: zlib_dep)

if config.get('HAVE_DTRACE')
    isc_probe_objects += static_library(
        'isc-probe-target',
        probe_src,
        build_by_default: false,
        dependencies: [uv_dep, urcu_dep],
        implicit_include_directories: false,
        include_directories: [isc_inc, isc_inc_p],
    ).extract_all_objects(recursive: false)
endif

isc_srcset.add(
    when: 'HAVE_DTRACE',
    if_true: custom_target(
        'isc-probe',
        input: [files('probes.d'), isc_probe_objects],
        output: 'isc-probes.o',
        command: [
            dtrace,
            '-G',
            '-o', '@OUTPUT@',
            '-s', '@INPUT@',
        ],
    ),
    if_false: probe_src,
)

isc_srcset.add(
    files(
        'ascii.c',
        'assertions.c',
        'async.c',
        'backtrace.c',
        'base32.c',
        'base64.c',
        'commandline.c',
        'counter.c',
        'crypto.c',
        'dir.c',
        'entropy.c',
        'errno.c',
        'errno2result.c',
        'error.c',
        'file.c',
        'getaddresses.c',
        'hash.c',
        'hashmap.c',
        'heap.c',
        'helper.c',
        'hex.c',
        'histo.c',
        'hmac.c',
        'ht.c',
        'httpd.c',
        'interfaceiter.c',
        'iterated_hash.c',
        'lex.c',
        'lib.c',
        'log.c',
        'loop.c',
        'managers.c',
        'md.c',
        'mem.c',
        'meminfo.c',
        'mutex.c',
        'net.c',
        'netaddr.c',
        'netscope.c',
        'nonce.c',
        'openssl_shim.c',
        'os.c',
        'parseint.c',
        'picohttpparser.c',
        'portset.c',
        'proxy2.c',
        'quota.c',
        'radix.c',
        'random.c',
        'ratelimiter.c',
        'regex.c',
        'region.c',
        'result.c',
        'safe.c',
        'serial.c',
        'signal.c',
        'sockaddr.c',
        'stats.c',
        'stdio.c',
        'stdtime.c',
        'string.c',
        'symtab.c',
        'syslog.c',
        'thread.c',
        'tid.c',
        'time.c',
        'timer.c',
        'tls.c',
        'tm.c',
        'url.c',
        'utf8.c',
        'uv.c',
        'work.c',
        'xml.c',
    ),
)
