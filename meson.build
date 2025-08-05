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

project(
    'bind',
    ['c'],
    version: '9.21.11-dev',
    meson_version: '>=0.61',
    license: 'MPL-2.0',
    default_options: [
        'b_asneeded=true',
        'b_pch=false',
        'b_pie=true',
        'c_std=gnu11',
        'default_library=shared',
        'localstatedir=/var',
        'strip=false',
        'warning_level=2',
        'werror=false',
        'wrap_mode=nodownload',
    ],
)

fs = import('fs')
ss = import('sourceset')

cc = meson.get_compiler('c')

### Check if autoconf is mixed
if fs.exists(meson.project_source_root() / 'config.h')
    error('in-place autoconf detected! please run `make distclean`!')
endif

### Build Options
developer_mode = get_option('developer').enabled()

c_std = get_option('c_std')
optimization = get_option('optimization')
sanitizer = get_option('b_sanitize')

trace_logging = get_option('trace-logging')
rcu_flavor = get_option('rcu-flavor')

cap_opt = get_option('cap')
cmocka_opt = get_option('cmocka')
dnstap_opt = get_option('dnstap')
doc_opt = get_option('doc')
doh_opt = get_option('doh')
fips_opt = get_option('fips')
fuzz_opt = get_option('fuzzing')
geoip_opt = get_option('geoip')
gssapi_opt = get_option('gssapi')
idn_opt = get_option('idn')
jemalloc_opt = get_option('jemalloc').disable_auto_if(sanitizer != 'none')
leak_opt = get_option('leak-detection')
line_opt = get_option('line')
lmdb_opt = get_option('lmdb')
locktype_opt = get_option('locktype')
stats_json_opt = get_option('stats-json')
stats_xml_opt = get_option('stats-xml')
tracing_opt = get_option('tracing')
zlib_opt = get_option('zlib')

if meson.version().version_compare('>=1.1.0')
    build_options = meson.build_options()
    if build_options == ''
        build_options = 'default'
    endif
else
    build_options = 'unprobed'
endif

### External commands
dtrace_shim = meson.project_source_root() / 'util' / 'dtrace.sh'

if tracing_opt.disabled()
    meson.override_find_program('dtrace', find_program(dtrace_shim))
endif

## Required
perl = find_program(['perl', 'perl5'])
sh = find_program('sh')

## Feature gated
krb5_config = find_program('krb5-config', required: gssapi_opt)
protoc = find_program(['protoc-c', 'protoc'], required: dnstap_opt)
dtrace = find_program(['dtrace', dtrace_shim], required: false)

## Testing
curl = find_program('curl', required: false)
fstrm_capture = find_program('fstrm_capture', required: false)
git = find_program('git', required: false)
nc = find_program('nc', required: false)
python = find_program(['python3', 'python'], required: false)
xsltproc = find_program('xsltproc', required: false)
pytest = find_program(
    ['pytest-3', 'py.test-3', 'pytest', 'py.test', 'pytest-pypy'],
    required: false,
)

## Documentation
sphinx_build = find_program('sphinx-build', required: doc_opt)

### Install information
prefix = get_option('prefix')

bindir = prefix / get_option('bindir')
datadir = prefix / get_option('datadir')
libdir = prefix / get_option('libdir')
localstatedir = prefix / get_option('localstatedir')
mandir = prefix / get_option('mandir')
runstatedir = localstatedir / 'run'
sbindir = prefix / get_option('sbindir')
sysconfdir = prefix / get_option('sysconfdir')

src_id = ''
if fs.is_file('srcid')
    src_id = fs.read('srcid', encoding: 'utf-8').strip()
elif git.found()
    src_id = run_command(git, 'rev-parse', '--short', 'HEAD', check: true).stdout().substring(0, 7)
    meson.add_dist_script('util' / 'meson-dist-package.sh', 'srcid', src_id)
endif

### Compiler
add_project_arguments(
    cc.get_supported_arguments(
        '-Wformat',
        '-Wno-missing-field-initializers',
        '-Wpointer-arith',
        '-Wshadow',
        '-Wwrite-strings',

        '-Werror=alloca',
        '-Werror=cpp',
        '-Werror=flex-array-member-not-at-end',
        '-Werror=format-security',
        '-Werror=implicit',
        '-Werror=implicit-function-declaration',
        '-Werror=missing-prototypes',
        '-Werror=parentheses',
        '-Werror=strict-prototypes',
        '-Werror=vla',

        '-fdiagnostics-show-option',
        '-fno-delete-null-pointer-checks',
        '-fno-strict-aliasing',
        '-fstrict-flex-arrays=3',
    ),
    language: 'c',
)

if developer_mode
    add_project_arguments('-Werror', language: 'c')
endif

fortify_test = '''
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    void *x = malloc(10);
    printf("%p\n", x);
}
'''

if optimization != 'plain'
    if optimization != '0'
        if cc.compiles(
            fortify_test,
            args: ['-Werror=cpp', '-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3'],
            name: 'usage of _FORTIFY_SOURCE=3',
        )
            add_project_arguments('-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3', language: 'c')
        else
            add_project_arguments('-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=2', language: 'c')
        endif
    endif

    add_project_arguments(
        cc.get_supported_arguments(
            '-fcf-protection=full',
            '-fstack-clash-protection',
            '-fstack-protector-strong',

            '-mbranch-protection=standard',
        ),
        language: 'c',
    )

    add_project_link_arguments(
        cc.get_supported_link_arguments(
            '-Wl,-z,noexecstack',
            '-Wl,-z,now',
            '-Wl,-z,relro',
            '-Wl,-z,separate-code',
        ),
        language: 'c',
    )
endif

if host_machine.cpu_family() == 'x86'
    add_project_arguments(
        cc.get_supported_arguments(
            '-Wno-psabi',
        ),
        language: 'c',
    )
endif

isdarwin = host_machine.system() == 'darwin'
if isdarwin
    add_project_arguments(
        cc.get_supported_arguments(
            '-Wno-deprecated-declarations', # For GSS.Framework
            '-Wno-unknown-attributes', # For _Noreturn in urcu
        ),
        language: 'c',
    )

    add_project_link_arguments(
        cc.get_supported_link_arguments(
            '-Wl,-flat_namespace',
            '-Wl,-no_warn_duplicate_libraries', # for krb5
        ),
        language: 'c',
    )
endif

sys_defines = [
    '-D_BSD_SOURCE',
    '-D_DARWIN_C_SOURCE',
    '-D_DEFAULT_SOURCE',
    '-D_FILE_OFFSET_BITS=64',
    '-D_GNU_SOURCE',
    '-D_LARGE_FILES',
    '-D_TIME_BITS=64',
    '-D__APPLE_USE_RFC_3542=1',
]

add_project_arguments(sys_defines, language: 'c')

### Environment

env = environment(
    {
        'BIND_PROJECT_VERSION': meson.project_version(),
        'BIND_BUILD_ROOT': meson.project_build_root(),
        'BIND_SOURCE_ROOT': meson.project_source_root(),
    },
)

### Configuration
config = configuration_data()

config.set_quoted('PACKAGE_NAME', 'BIND')
config.set_quoted('PACKAGE_DESCRIPTION', 'Development Release')
config.set_quoted('PACKAGE_VERSION', meson.project_version())
config.set_quoted('PACKAGE_STRING', 'BIND ' + meson.project_version())
config.set_quoted('PACKAGE_BUILDER', 'meson')
config.set_quoted('PACKAGE_SRCID', src_id)
config.set_quoted('PACKAGE_CONFIGARGS', build_options)

if get_option('auto-validation').allowed()
    config.set_quoted('VALIDATION_DEFAULT', 'auto')
else
    config.set_quoted('VALIDATION_DEFAULT', 'no')
endif

config.set_quoted('SESSION_KEYFILE', localstatedir / 'run' / 'named' / 'session.key')

config.set_quoted('RNDC_CONFFILE', sysconfdir / 'rndc.conf')
config.set_quoted('RNDC_KEYFILE', sysconfdir / 'rndc.key')

config.set_quoted('NAMED_PLUGINDIR', libdir / 'bind')
if isdarwin
    # Plugin extensions - macOS is the only specific case
    config.set_quoted('NAMED_PLUGINEXT', '.dylib')
else
    config.set_quoted('NAMED_PLUGINEXT', '.so')
endif

config.set_quoted('NAMED_LOCALSTATEDIR', localstatedir)
config.set_quoted('NAMED_SYSCONFDIR', sysconfdir)
config.set_quoted('NAMED_CONFFILE', sysconfdir / 'named.conf')

config.set_quoted('CACHEDB_DEFAULT', get_option('cachedb'))
config.set_quoted('ZONEDB_DEFAULT', get_option('zonedb'))

# Shim constexpr for pre-C23
# "ne" => "none"
if c_std.substring(-2) in ['ne', '89', '99', '11', '17', '18']
    config.set('constexpr', 'static const')
endif

if developer_mode
    config.set('ISC_LIST_CHECKINIT', 1)
    config.set('ISC_MEM_DEFAULTFILL', 1)
    config.set('ISC_MEM_TRACKLINES', 1)
    config.set('ISC_MUTEX_ERROR_CHECK', 1)
    config.set('ISC_SOCKET_DETAILS', 1)
    config.set('ISC_STATS_CHECKUNDERFLOW', 1)
endif

foreach fn : [
    '__builtin_add_overflow',
    '__builtin_clz',
    '__builtin_mul_overflow',
    '__builtin_sub_overflow',
    '__builtin_unreachable',
]
    if cc.has_function(fn)
        config.set('HAVE_@0@'.format(fn.substring(2).to_upper()), 1)
    endif
endforeach

foreach attr : ['malloc', 'returns_nonnull']
    if cc.has_function_attribute(attr)
        config.set('HAVE_FUNC_ATTRIBUTE_@0@'.format(attr.to_upper()), 1)
    endif
endforeach

malloc_ext_test = '''
#include <stddef.h>
#include <stdlib.h>

__attribute__ ((malloc, malloc(free, 1))
void * xmalloc(size_t sz) {
    return malloc(sz);
}

void main(void) {
    return xmalloc(8) != NULL;
}
'''
if cc.compiles(malloc_ext_test, name: 'usage of extended malloc attribute')
    config.set('HAVE_MALLOC_EXT_ATTR', 1)
endif

## Fuzzing
config.set_quoted('FUZZDIR', meson.project_source_root() / 'fuzz')

fuzz_link_args = []
if fuzz_opt != 'none'
    if get_option('b_lundef') != false
        warning('fuzzing will fail to build properly without -Db_lundef=false')
    endif

    if fuzz_opt == 'afl'
    elif fuzz_opt == 'libfuzzer'
        config.set('FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION', 1)
        fuzz_link_args += '-fsanitize=fuzzer,address,undefined'
        add_project_link_arguments('-fsanitize=address,undefined', language: 'c')
        add_project_arguments('-fsanitize=fuzzer-no-link,address,undefined', language: 'c')
    endif
endif

## Architecture
if host_machine.endian() == 'big'
    config.set('WORDS_BIGENDIAN', 1)
endif

instruction_test = '''
int main(void) {
    __asm__ __volatile__ ("@0@");
    return 0;
}
'''

cpu_family = host_machine.cpu_family()
if cpu_family in ['arm', 'aarch64']
    if cc.compiles(
        instruction_test.format('yield'),
        name: 'usage of yield instruction',
    )
        config.set('HAVE_SPARC_PAUSE', 1)
    endif
elif cpu_family in ['sparc', 'sparc64']
    if cc.compiles(
        instruction_test.format('pause'),
        name: 'usage of pause instruction',
    )
        config.set('HAVE_SPARC_PAUSE', 1)
    endif
endif

atomic_test = '''
#include <stdatomic.h>
int main(void) {
    atomic_int_fast64_t val = 0;
    atomic_fetch_add_explicit(&val, 1, memory_order_relaxed);

    return 0;
}
'''

# meson_version (>=1.7.0) : new custom dependency for atomic
if not cc.links(atomic_test, name: 'usage of atomics without -latomic')
    atomic_dep = declare_dependency(link_args: '-latomic')
    if not cc.links(
        atomic_test,
        dependencies: atomic_dep,
        name: 'usage of atomics with -latomic',
    )
        error(
            'libatomic needed, but linking with -latomic failed, please fix your toolchain',
        )
    endif

    add_project_link_arguments('-latomic', language: 'c')
endif

## OS
config.set10('USE_PTHREAD_RWLOCK', locktype_opt == 'system')

if host_machine.system() == 'sunos' and cc.get_id() == 'gcc'
    add_project_link_arguments('-zrelax=transtls', language: 'c')
    warning(
        'When using GNU C Compiler on Solaris, -zrelax=transtls linker flag is used to fix bug in Thread Local Storage',
    )
endif

if cc.has_header_symbol('pthread.h', 'PTHREAD_MUTEX_ADAPTIVE_NP')
    config.set('HAVE_PTHREAD_MUTEX_ADAPTIVE_NP', 1)
endif

foreach fn, header : {
    # Better strings
    'strlcpy': '#include <string.h>',
    'strlcat': '#include <string.h>',
    'strnstr': '#include <string.h>',

    # Kernel information
    'uname': '#include <sys/utsname.h>',

    # Backtrace
    'backtrace_symbols': '#include <execinfo.h>',

    # Timezone
    'tzset': '#include <time.h>',

    # Check for if_nametoindex() for IPv6 scoped addresses support
    'if_nametoindex': '#include <net/if.h>',

    # FILE locking
    'flockfile': '#include <stdio.h>',
    'getc_unlocked': '#include <stdio.h>',

    # Processor control
    'cpuset_getaffinity': '#include <sys/cpuset.h>',
    'sched_getaffinity': '#include <sched.h>',
    'sched_yield': '#include <sched.h>',

    # Misc.
    'clock_gettime': '#include <time.h>',
    'sysctlbyname': '#include <sys/sysctl.h>',
}
    if cc.has_function(fn, prefix: header, args: sys_defines)
        config.set('HAVE_@0@'.format(fn.to_upper()), 1)
    endif
endforeach

# Check for nanoseconds in file stats
if cc.has_member('struct stat', 'st_mtim.tv_nsec', prefix: '#include <sys/stat.h>')
    config.set('HAVE_STAT_NSEC', 1)
endif

foreach h : [
    'fcntl.h',
    'linux/netlink.h',
    'linux/rtnetlink.h',
    'malloc_np.h',
    'net/if6.h',
    'net/route.h',
    'regex.h',
    'sys/mman.h',
    'sys/select.h',
    'sys/sockio.h',
    'sys/sysctl.h',
    'sys/time.h',
    'unistd.h',
]
    if cc.has_header(h)
        config.set('HAVE_@0@'.format(h.underscorify().to_upper()), 1)
    endif
endforeach

## Leak detection in external libraries
config.set10('ENABLE_LEAK_DETECTION', leak_opt.enabled())

## Query Tracing

# meson_version (>=1.1.0) : enable_if in feature object
query_trace_opt = 'query' in trace_logging
single_trace_opt = 'single' in trace_logging
if query_trace_opt or developer_mode
    config.set('WANT_QUERYTRACE', 1)
    if single_trace_opt
        config.set('WANT_SINGLETRACE', 1)
    endif
elif single_trace_opt
    error('single trace logging requires query trace logging')
endif

###
### Dependencies
###
null_dep = dependency('', required: false)

m_dep = cc.find_library('m', required: false)

## Threads
thread_dep = dependency('threads')

foreach fn : [
    'pthread_attr_getstacksize',
    'pthread_attr_setstacksize',
    'pthread_barrier_init',
    'pthread_set_name_np',
    'pthread_setname_np',
    'pthread_spin_init',
    'pthread_yield',
    'pthread_yield_np',
]
    if cc.has_function(
        fn,
        prefix: '#include <pthread.h>',
        args: sys_defines,
        dependencies: thread_dep,
    )
        config.set('HAVE_@0@'.format(fn.to_upper()), 1)
    endif
endforeach

## OpenSSL
openssl_dep = [
    dependency('libcrypto', version: '>=1.1.1'),
    dependency('libssl', version: '>=1.1.1'),
]

foreach fn, header : {
    'EVP_default_properties_enable_fips': '#include <openssl/evp.h>',
    'FIPS_mode': '#include <openssl/crypto.h>',
}
    if cc.has_function(fn, prefix: header, dependencies: openssl_dep)
        config.set('HAVE_OPENSSL_FIPS_TOGGLE', 1)
        config.set('HAVE_@0@'.format(fn.to_upper()), 1)
    endif
endforeach

fips_opt.require(
    config.has('HAVE_OPENSSL_FIPS_TOGGLE'),
    error_message: 'OpenSSL FIPS mode requested but not available',
)

# Hash and curve probe
if cc.has_header_symbol('openssl/evp.h', 'NID_ED448', dependencies: openssl_dep)
    config.set('HAVE_OPENSSL_ED448', 1)
endif

foreach fn, header : {
    'ERR_get_error_all': '#include <openssl/err.h>',
    'BIO_read_ex': '#include <openssl/bio.h>',
    'BIO_write_ex': '#include <openssl/bio.h>',
    'EVP_MD_CTX_get0_md': '#include <openssl/evp.h>',
    'EVP_PKEY_eq': '#include <openssl/evp.h>',
    'SSL_CTX_set1_cert_store': '#include <openssl/ssl.h>',
}
    config.set10(
        'HAVE_@0@'.format(fn.to_upper()),
        cc.has_function(fn, dependencies: openssl_dep, prefix: header),
    )
endforeach

## libuv
uv_dep = dependency('libuv', version: '>=1.34.0')
if uv_dep.version().version_compare('<1.40.0')
    warning('libuv version 1.40.0 or greater is highly recommended')
endif

foreach sym : ['UV_UDP_LINUX_RECVERR', 'UV_UDP_MMSG_CHUNK', 'UV_UDP_MMSG_FREE']
    if cc.has_header_symbol('uv.h', sym, dependencies: uv_dep)
        config.set('HAVE_DECL_@0@'.format(sym), 1)
    endif
endforeach

if not cc.has_members('struct msghdr', '__pad1', '__pad2', prefix: '#include <sys/socket.h>')
    if cc.has_header_symbol('uv.h', 'UV_UDP_RECVMMSG', dependencies: uv_dep)
        config.set('HAVE_DECL_UV_UDP_RECVMMSG', 1)
    endif
else
    message('likely non-glibc on linux, disabling recvmmsg')
endif

## userspace-rcu
urcu_dep = [dependency('liburcu-cds', version: '>=0.10.0')]
if rcu_flavor == 'membarrier'
    config.set('RCU_MEMBARRIER', true)
    urcu_dep += dependency('liburcu', version: '>=0.10.0')
elif not developer_mode
    error('Changing Userspace-RCU flavor is allowed only in development mode')
elif rcu_flavor == 'bp'
    config.set('RCU_BP', true)
    urcu_dep += dependency('liburcu-bp', version: '>=0.10.0')
elif rcu_flavor == 'mb'
    config.set('RCU_MB', true)
    urcu_dep += dependency('liburcu-mb', version: '>=0.10.0')
elif rcu_flavor == 'qsbr'
    config.set('RCU_QSBR', true)
    urcu_dep += dependency('liburcu-qsbr', version: '>=0.10.0')
endif

# liburcu << v0.13.0 didn't add -lurcu-common and some toolchains would
# not add it automatically - we need to add it explicitly in such case.

if urcu_dep[1].version().version_compare('<0.13.0')
    urcu_dep += cc.find_library('liburcu-common')
endif

config.set_quoted('RCU_FLAVOR', f'liburcu-@rcu_flavor@')
config.set_quoted('RCU_VERSION', urcu_dep[0].version())

urcu_inline_test = '''
#define URCU_INLINE_SMALL_FUNCTIONS 1
#include <urcu.h>
int main(void) {
    struct opaque *a = malloc(1);
    struct opaque *b = rcu_dereference(a);

    return b != NULL;
}
'''
if cc.compiles(
    urcu_inline_test,
    dependencies: urcu_dep,
    name: 'usage of opaque urcu inlining',
)
    config.set('URCU_INLINE_SMALL_FUNCTIONS', 1)
endif

## jemalloc
jemalloc_dep = null_dep
if jemalloc_opt.allowed()
    jemalloc_dep = dependency('jemalloc', required: jemalloc_opt)
    if jemalloc_dep.found()
        config.set('HAVE_JEMALLOC', 1)
    endif
endif

## dnstap
dnstap_dep = null_dep # Will be filled later

fstrm_dep = null_dep
proto_dep = null_dep
if dnstap_opt.allowed()
    fstrm_dep = dependency('libfstrm', required: dnstap_opt)
    proto_dep = dependency('libprotobuf-c', required: dnstap_opt)
    if protoc.found() and fstrm_dep.found() and proto_dep.found()
        config.set('HAVE_DNSTAP', 1)
    endif
endif

## JSON
json_c_dep = null_dep
if stats_json_opt.allowed()
    json_c_dep = dependency('json-c', version: '>=0.11', required: stats_json_opt)
    if json_c_dep.found()
        config.set('HAVE_JSON_C', 1)
    endif
endif

## XML
xml2_dep = null_dep
if stats_xml_opt.allowed()
    xml2_dep = dependency('libxml-2.0', version: '>=2.6.0', required: stats_xml_opt)
    if xml2_dep.found()
        config.set('HAVE_LIBXML2', 1)
    endif
endif

## DNS-over-HTTP (DoH)
nghttp2_dep = null_dep
if doh_opt.allowed()
    nghttp2_dep = dependency('libnghttp2', version: '>=1.6.0', required: doh_opt)
    if nghttp2_dep.found()
        config.set('HAVE_LIBNGHTTP2', 1)
    endif
endif

## GeoIP
maxminddb_dep = null_dep
if geoip_opt.allowed()
    maxminddb_dep = dependency('libmaxminddb', required: geoip_opt)
    if maxminddb_dep.found()
        config.set('HAVE_GEOIP2', 1)
        config.set_quoted('MAXMINDDB_PREFIX', maxminddb_dep.get_variable('prefix'))
    endif
endif

## GSSAPI
gssapi_dep = null_dep
krb5_dep = null_dep
if gssapi_opt.allowed() and krb5_config.found()
    krb5_dep = declare_dependency(
        compile_args: run_command(krb5_config, ['krb5', '--cflags'], check: true).stdout().strip().split(),
        link_args: run_command(krb5_config, ['krb5', '--libs'], check: true).stdout().strip().split(),
        version: run_command(krb5_config, ['--version'], check: true).stdout().strip(),
    )

    if cc.has_header('krb5/krb5.h', dependencies: krb5_dep)
        config.set('HAVE_KRB5_KRB5_H', 1)
    elif cc.has_header('krb5.h', dependencies: krb5_dep)
        config.set('HAVE_KRB5_H', 1)
    elif krb5_dep.found()
        error('neither krb5/krb5.h nor krb5 found')
    endif

    if krb5_dep.found() and not cc.has_function('krb5_init_context', dependencies: krb5_dep)
        error('KRB5 does not work')
    endif

    gssapi_dep = declare_dependency(
        compile_args: run_command(krb5_config, ['gssapi', '--cflags'], check: true).stdout().strip().split(),
        link_args: run_command(krb5_config, ['gssapi', '--libs'], check: true).stdout().strip().split(),
        version: krb5_dep.version(),
    )

    if cc.has_header('gssapi/gssapi.h', dependencies: gssapi_dep)
        config.set('HAVE_GSSAPI_GSSAPI_H', 1)
    elif cc.has_header('gssapi.h', dependencies: gssapi_dep)
        config.set('HAVE_GSSAPI_H', 1)
    elif gssapi_dep.found()
        error('neither gssapi/gssapi.h nor gssapi.h found')
    endif

    if cc.has_header('gssapi/gssapi_krb5.h', dependencies: gssapi_dep)
        config.set('HAVE_GSSAPI_GSSAPI_KRB5_H', 1)
    elif cc.has_header('gssapi_krb5.h', dependencies: gssapi_dep)
        config.set('HAVE_GSSAPI_KRB5_H', 1)
    elif gssapi_dep.found()
        error('neither gssapi/gssapi_krb5.h nor gssapi_krb5.h found')
    endif

    if krb5_dep.found() and gssapi_dep.found()
        config.set('HAVE_GSSAPI', 1)
    endif
endif

## libcap
cap_dep = null_dep
if cap_opt.allowed()
    cap_dep = dependency('libcap', required: cap_opt)
    if cap_dep.found()
        config.set('HAVE_LIBCAP', 1)
    endif
endif

## IDN
idn2_dep = null_dep
if idn_opt.allowed()
    idn2_dep = dependency('libidn2', required: idn_opt)
    if idn2_dep.found()
        config.set('HAVE_LIBIDN2', 1)
    endif
endif

## LMDB
lmdb_dep = null_dep
if lmdb_opt.allowed()
    lmdb_dep = dependency('lmdb', required: lmdb_opt)
    if lmdb_dep.found()
        config.set('HAVE_LMDB', 1)
    endif
endif

## zlib

# meson_version (>=1.1.0) : enable_if in feature object
zlib_dep = null_dep
if zlib_opt.allowed() or developer_mode
    zlib_dep = dependency('zlib', required: zlib_opt.enabled() or developer_mode)
    if zlib_dep.found()
        config.set('HAVE_ZLIB', 1)
    endif
endif

## libedit
edit_dep = null_dep
if line_opt.allowed()
    edit_dep = dependency('libedit', required: line_opt)
    if edit_dep.found()
        config.set('HAVE_LIBEDIT', 1)
    endif
endif

## cmocka
cmocka_dep = null_dep

# meson_version (>=1.1.0) : enable_if in feature object
if cmocka_opt.allowed() or developer_mode
    cmocka_dep = dependency(
        'cmocka',
        version: '>=1.1.3',
        required: cmocka_opt.enabled() or developer_mode,
    )

    if cmocka_dep.found()
        config.set('HAVE_CMOCKA', 1)
    endif
endif

## DTrace
dtrace_header = generator(
    dtrace,
    output: '@BASENAME@.h',
    arguments: ['-s', '@INPUT@', '-h', '-o', '@OUTPUT@'],
)

# Acutally, dtrace probes are still built with macOS.
# macOS flavored dtrace doesn't recognize the -G option and
# only uses headers.
#
# Since the binary is in the base system, there isn't much reason
# to be able to disable it. You can just not use the probes.
config.set(
    'HAVE_DTRACE',
    dtrace.full_path() != dtrace_shim
    and build_machine.system() != 'darwin',
)
cc.has_header('sys/sdt.h', required: tracing_opt)
assert(
    dtrace.full_path() != dtrace_shim or not tracing_opt.enabled(),
    'tracing is requested but dtrace is not found',
)

### Finalize configuration
configure_file(output: 'config.h', configuration: config)
add_project_arguments('-include', meson.project_build_root() / 'config.h', language: 'c')

### Build dnstap if necessary, needs configuration
if config.has('HAVE_DNSTAP')
    dnstap_schema_src = custom_target(
        'dnstap-protobuf',
        input: ['dnstap.proto'],
        output: ['dnstap.pb-c.c', 'dnstap.pb-c.h'],
        command: [
            protoc,
            '--proto_path=@CURRENT_SOURCE_DIR@',
            '--c_out=@OUTDIR@',
            '@INPUT@',
        ],
    )

    dnstap = static_library(
        'dnstap',
        dnstap_schema_src,
        implicit_include_directories: false,
        dependencies: proto_dep,
    )

    dnstap_dep = declare_dependency(
        link_with: dnstap,
        sources: dnstap_schema_src[1],
        dependencies: [
            fstrm_dep,
            proto_dep,
        ],
    )
endif

###
### Compile Targets
###
bind_keys = custom_target(
    'bind-keys',
    output: 'bind.keys.h',
    depend_files: files('bind.keys', 'util' / 'bindkeys.pl'),
    capture: true,
    command: [
        perl,
        meson.project_source_root() / 'util' / 'bindkeys.pl',
        meson.project_source_root() / 'bind.keys',
    ],
)

# Headers
dns_inc = include_directories('lib' / 'dns' / 'include')
isc_inc = include_directories('lib' / 'isc' / 'include')
isccc_inc = include_directories('lib' / 'isccc' / 'include')
isccfg_inc = include_directories('lib' / 'isccfg' / 'include')
ns_inc = include_directories('lib' / 'ns' / 'include')

dns_inc_p = []
isc_inc_p = []

named_inc_p = []
confgen_inc_p = []

# USDT Probes
dns_probe_objects = []
isc_probe_objects = []
ns_probe_objects = []

# Use sourceset to add conditional files
# https://mesonbuild.com/SourceSet-module.html
dns_srcset = ss.source_set()
isc_srcset = ss.source_set()
isccc_srcset = ss.source_set()
isccfg_srcset = ss.source_set()
ns_srcset = ss.source_set()

named_srcset = ss.source_set()

arm_srcset = ss.source_set()
man_srcset = ss.source_set()
manrst_srcset = ss.source_set()
doc_misc_targets = []

man_pages = []

arpaname_src = []
delv_src = []
dig_src = []
dnssec_cds_src = []
dnssec_dsfromkey_src = []
dnssec_importkey_src = []
dnssec_keyfromlabel_src = []
dnssec_keygen_src = []
dnssec_ksr_src = []
dnssec_revoke_src = []
dnssec_settime_src = []
dnssec_signzone_src = []
dnssec_verify_src = []
dnstap_read_src = []
host_src = []
mdig_src = []
named_checkconf_src = []
named_checkzone_src = []
named_journalprint_src = []
named_makejournal_src = []
named_nzd2nzf_src = []
named_rrchecker_src = []
nsec3hash_src = []
nslookup_src = []
nsupdate_src = []
rndc_confgen_src = []
rndc_src = []
tsig_keygen_src = []

filter_a_src = []
filter_aaaa_src = []

fuzz_binaries = {}
system_test_binaries = {}
system_test_libraries = {}

system_test_targets = []

subdir('bin')
subdir('fuzz')
subdir('lib')
subdir('util')

###
### Libraries & Binaries
###

# libisc

isc_srcconf = isc_srcset.apply(config, strict: false)

libisc = library(
    'isc',
    isc_srcconf.sources(),
    objects: isc_probe_objects,
    install: true,
    install_rpath: libdir,
    implicit_include_directories: false,
    include_directories: [isc_inc, isc_inc_p],
    dependencies: isc_srcconf.dependencies(),
)

libisc_dep = declare_dependency(
    link_with: libisc,
    include_directories: isc_inc,
    dependencies: [
        openssl_dep,
        thread_dep,
        urcu_dep,
        uv_dep,

        jemalloc_dep,
    ],
)

# libdns
dns_srcconf = dns_srcset.apply(config, strict: false)

libdns = library(
    'dns',
    dns_srcconf.sources(),
    include_directories: dns_inc,
    install: true,
    install_rpath: libdir,
    objects: dns_probe_objects,
    dependencies: [
        libisc_dep,

        openssl_dep,
        urcu_dep,

        json_c_dep,
        lmdb_dep,
        xml2_dep,

        dns_srcconf.dependencies(),
    ],
)

libdns_dep = declare_dependency(
    link_with: libdns,
    include_directories: dns_inc,
    sources: dns_gen_headers,
    dependencies: [
        libisc_dep,
    ],
)

# libns

ns_srcconf = ns_srcset.apply(config, strict: false)

libns = library(
    'ns',
    ns_srcconf.sources(),
    objects: ns_probe_objects,
    install: true,
    install_rpath: libdir,
    implicit_include_directories: false,
    include_directories: ns_inc,
    dependencies: [
        libisc_dep,
        libdns_dep,
    ],
)

libns_dep = declare_dependency(
    link_with: libns,
    include_directories: ns_inc,
    dependencies: [
        libisc_dep,
        libdns_dep,
    ],
)

# libisccc
isccc_srcconf = isccc_srcset.apply(config, strict: false)

libisccc = library(
    'isccc',
    isccc_srcconf.sources(),
    implicit_include_directories: false,
    include_directories: isccc_inc,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

libisccc_dep = declare_dependency(
    link_with: libisccc,
    include_directories: isccc_inc,
)

# libisccfg
isccfg_srcconf = isccfg_srcset.apply(config, strict: false)

libisccfg = library(
    'isccfg',
    isccfg_srcconf.sources(),
    implicit_include_directories: false,
    include_directories: isccfg_inc,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libns_dep,

        dnstap_dep,
    ],
)

libisccfg_dep = declare_dependency(
    link_with: libisccfg,
    include_directories: isccfg_inc,
)

named_srcconf = named_srcset.apply(config, strict: false)

executable(
    'arpaname',
    arpaname_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libisc_dep,
    ],
)

executable(
    'delv',
    delv_src,
    export_dynamic: true,
    implicit_include_directories: true,
    install: true,
    install_rpath: libdir,
    sources: bind_keys,
    dependencies: [
        libisc_dep,
        libisccfg_dep,
        libns_dep,
    ],
)

executable(
    'dig',
    dig_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        idn2_dep,
    ],
)

executable(
    'dnssec-cds',
    dnssec_cds_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
    ],
)

executable(
    'dnssec-dsfromkey',
    dnssec_dsfromkey_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
    ],
)

executable(
    'dnssec-importkey',
    dnssec_importkey_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
    ],
)

executable(
    'dnssec-keyfromlabel',
    dnssec_keyfromlabel_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
    ],
)

executable(
    'dnssec-keygen',
    dnssec_keygen_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
    ],
)

executable(
    'dnssec-ksr',
    dnssec_ksr_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
    ],
)

executable(
    'dnssec-revoke',
    dnssec_revoke_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
    ],
)

executable(
    'dnssec-settime',
    dnssec_settime_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
    ],
)

executable(
    'dnssec-signzone',
    dnssec_signzone_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
    ],
)

executable(
    'dnssec-verify',
    dnssec_verify_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
    ],
)

if config.has('HAVE_DNSTAP')
    executable(
        'dnstap-read',
        dnstap_read_src,
        export_dynamic: true,
        implicit_include_directories: true,
        install: true,
        install_rpath: libdir,
        dependencies: [
            libdns_dep,
            libisc_dep,

            dnstap_dep,
        ],
    )
endif

executable(
    'host',
    host_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        idn2_dep,
    ],
)

executable(
    'mdig',
    mdig_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'named-checkconf',
    named_checkconf_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libisc_dep,
        libdns_dep,
        libisccfg_dep,
    ],
)

executable(
    'named-checkzone',
    named_checkzone_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libisc_dep,
        libdns_dep,
        libisccfg_dep,
        libns_dep,
    ],
)

install_symlink(
    'named-compilezone',
    pointing_to: 'named-checkzone',
    install_dir: bindir,
)

executable(
    'named-journalprint',
    named_journalprint_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'named-makejournal',
    named_makejournal_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

if config.has('HAVE_LMDB')
    executable(
        'named-nzd2nzf',
        named_nzd2nzf_src,
        export_dynamic: true,
        implicit_include_directories: false,
        install: true,
        install_rpath: libdir,
        dependencies: [
            libdns_dep,
            libisc_dep,

            lmdb_dep,
        ],
    )
endif

executable(
    'named-rrchecker',
    named_rrchecker_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],

)

executable(
    'named',
    named_srcconf.sources(),
    export_dynamic: true,
    implicit_include_directories: true,
    include_directories: named_inc_p,
    install: true,
    install_dir: sbindir,
    install_rpath: libdir,
    sources: bind_keys,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccc_dep,
        libisccfg_dep,
        libns_dep,

        openssl_dep,

        cap_dep,
        dnstap_dep,
        json_c_dep,
        lmdb_dep,
        nghttp2_dep,
        xml2_dep,
        zlib_dep,

        named_srcconf.dependencies(),
    ],
)

executable(
    'nsec3hash',
    nsec3hash_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'nslookup',
    nslookup_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        idn2_dep,
        edit_dep,
    ],
)

executable(
    'nsupdate',
    nsupdate_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        gssapi_dep,
        krb5_dep,
        edit_dep,
    ],
)

executable(
    'rndc-confgen',
    rndc_confgen_src,
    export_dynamic: true,
    implicit_include_directories: false,
    include_directories: confgen_inc_p,
    install: true,
    install_rpath: libdir,
    install_dir: sbindir,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'rndc',
    rndc_src,
    export_dynamic: true,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    install_dir: sbindir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccc_dep,
        libisccfg_dep,
    ],
)

executable(
    'tsig-keygen',
    tsig_keygen_src,
    export_dynamic: true,
    implicit_include_directories: false,
    include_directories: confgen_inc_p,
    install: true,
    install_rpath: libdir,
    install_dir: sbindir,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccc_dep,
        libisccfg_dep,
    ],
)

install_symlink(
    'ddns-confgen',
    pointing_to: 'tsig-keygen',
    install_dir: sbindir,
)

shared_library(
    'filter-a',
    filter_a_src,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    install_dir: libdir / 'bind',
    name_prefix: '',
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
        libns_dep,
    ],
)

shared_library(
    'filter-aaaa',
    filter_aaaa_src,
    implicit_include_directories: false,
    install: true,
    install_rpath: libdir,
    install_dir: libdir / 'bind',
    name_prefix: '',
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
        libns_dep,
    ],
)

subdir('doc')
subdir('tests')

foreach name, sources : fuzz_binaries
    executable(
        name,
        sources,
        export_dynamic: true,
        implicit_include_directories: true,
        install: false,
        c_args: ['-Wno-vla'],
        link_args: fuzz_link_args,
        dependencies: [
            libdns_dep,
            libisc_dep,
            libtest_dep,
        ],
    )
endforeach

foreach name, sources : system_test_binaries
    system_test_targets += executable(
        name,
        sources,
        build_by_default: developer_mode,
        export_dynamic: true,
        implicit_include_directories: false,
        install: false,
        dependencies: [
            libdns_dep,
            libisc_dep,

            openssl_dep,
        ],
    )
endforeach

foreach name, sources : system_test_libraries
    system_test_targets += shared_library(
        name,
        sources,
        build_by_default: developer_mode,
        implicit_include_directories: false,
        install: false,
        name_prefix: 'testlib-',
        dependencies: [
            libdns_dep,
            libisc_dep,
            libns_dep,
        ],
    )
endforeach

alias_target('system-test-dependencies', system_test_targets)

### Documentation

get_release_date = '''
import os
import datetime

changelog_mtime = os.path.getmtime("doc/arm/changelog.rst")
release_date = datetime.date.fromtimestamp(changelog_mtime)
print(release_date, end="")
'''

if doc_opt.allowed()
    release_date = ''
    if python.found()
        release_date = run_command(python, ['-c', get_release_date], check: true).stdout()
    endif

    man_srcconf = man_srcset.apply(config, strict: false)
    foreach man : man_srcconf.sources()
        man_pages += configure_file(
            input: man,
            output: fs.stem(man),
            configuration: {
                'RELEASE_DATE': release_date,
                'RUNSTATEDIR': runstatedir,
                'SYSCONFDIR': sysconfdir,
            },
        )
    endforeach

    install_man(man_pages)

    if sphinx_build.found()
        alias_target('doc-misc', doc_misc_targets)

        meson.add_dist_script(
            'util' / 'meson-dist-package.sh',
            'manual',
            meson.project_version(),
            sphinx_build.full_path(),
        )

        # meson_version (>=0.63) : multiline f-string
        rst_epilog_tmpl = '''.. |rndc_conf| replace:: ``@0@/rndc.conf``
.. |rndc_key| replace:: ``@0@/rndc.key``
.. |named_conf| replace:: ``@0@/named.key``
.. |named_pid| replace:: ``@1@/named.key``
.. |session_key| replace:: ``@1@/session.key``
'''

        rst_epilog = rst_epilog_tmpl.format(sysconfdir, runstatedir)

        sphinx_common_options = [
            '-W',
            '-a',
            '-n',
            '-q',
            '-D', 'version=' + meson.project_version(),
            '-D', 'release=' + meson.project_version(),
            '-D', 'rst_epilog=' + rst_epilog,
            '-D', 'today_fmt=%Y-%m-%d',
        ]

        ## Manual pages
        manrst_srcconf = manrst_srcset.apply(config, strict: false)

        custom_target(
            'man',
            build_always_stale: true,
            depend_files: manrst_srcconf.sources(),
            depends: doc_misc_targets,
            install: man_srcconf.sources().length() == 0,
            install_dir: fs.parent(mandir),
            output: fs.name(mandir),
            env: env,
            command: [
                sphinx_build,
                sphinx_common_options,
                '-b', 'man',
                '-d', '@PRIVATE_DIR@',
                '-c', '@CURRENT_SOURCE_DIR@' / 'doc' / 'man',
                '@CURRENT_SOURCE_DIR@' / 'doc' / 'man',
                '@OUTPUT@',
            ],
        )

        ## ARM
        arm_srcset.add_all(manrst_srcset)
        arm_srcconf = arm_srcset.apply(config, strict: false)

        custom_target(
            'arm',
            build_by_default: false,
            depend_files: arm_srcconf.sources(),
            depends: doc_misc_targets,
            output: 'arm',
            env: env,
            command: [
                sphinx_build,
                sphinx_common_options,
                '-b', 'html',
                '-d', '@PRIVATE_DIR@',
                '-c', '@CURRENT_SOURCE_DIR@' / 'doc' / 'arm',
                '@CURRENT_SOURCE_DIR@' / 'doc' / 'arm',
                '@OUTPUT@',
            ],
        )

        custom_target(
            'arm-singlehtml',
            build_by_default: false,
            depend_files: arm_srcconf.sources(),
            depends: doc_misc_targets,
            output: 'arm-singlehtml',
            env: env,
            command: [
                sphinx_build,
                sphinx_common_options,
                '-b', 'singlehtml',
                '-d', '@PRIVATE_DIR@',
                '-c', '@CURRENT_SOURCE_DIR@' / 'doc' / 'arm',
                '@CURRENT_SOURCE_DIR@' / 'doc' / 'arm',
                '@OUTPUT@',
            ],
        )

        custom_target(
            'arm-pdf',
            build_by_default: false,
            depend_files: arm_srcconf.sources(),
            depends: doc_misc_targets,
            output: 'arm-pdf',
            env: env,
            command: [
                sphinx_build,
                '-M', 'latexpdf',
                '@CURRENT_SOURCE_DIR@' / 'doc' / 'arm',
                '@OUTPUT@',
                sphinx_common_options,
                '-d', '@PRIVATE_DIR@',
                '-c', '@CURRENT_SOURCE_DIR@' / 'doc' / 'arm',
            ],
        )

        custom_target(
            'arm-epub',
            build_by_default: false,
            depend_files: arm_srcconf.sources(),
            depends: doc_misc_targets,
            output: 'arm-epub',
            env: env,
            command: [
                sphinx_build,
                sphinx_common_options,
                '-b', 'epub',
                '-d', '@PRIVATE_DIR@',
                '-c', '@CURRENT_SOURCE_DIR@' / 'doc' / 'arm',
                '@CURRENT_SOURCE_DIR@' / 'doc' / 'arm',
                '@OUTPUT@',
            ],
        )
    endif
endif

###
### Summary
###

summary(
    {
        'Compiler': cc.get_id(),
        'Linker': cc.get_linker_id(),
    },
    section: 'Toolchain',
)

summary(
    {
        'libuv': uv_dep.version(),
        'OpenSSL': openssl_dep[0].version(),
        'Userspace RCU': urcu_dep[0].version(),
        'RCU Flavor': rcu_flavor,
    },
    section: 'Required Dependencies',
)

summary(
    {
        'cmocka': cmocka_dep.version(),
        'fstrm': fstrm_dep.version(),
        'GSSAPI': gssapi_dep.version(),
        'jemalloc': jemalloc_dep.version(),
        'json-c': json_c_dep.version(),
        'krb5': krb5_dep.version(),
        'libcap': cap_dep.version(),
        'libedit': edit_dep.version(),
        'libidn2': idn2_dep.version(),
        'libxml2': xml2_dep.version(),
        'LMDB': lmdb_dep.version(),
        'MaxMindDB': maxminddb_dep.version(),
        'nghttp2': nghttp2_dep.version(),
        'protobuf-c': proto_dep.version(),
        'zlib': zlib_dep.version(),
    },
    section: 'Optional Dependencies',
)

### Warn about fragmentation
if not (config.has('HAVE_JEMALLOC') or config.has('HAVE_MALLOC_NP_H'))
    message()
    warning(
        '''
    +------------------------------------------+
    |             ==== WARNING ====            |
    |                                          |
    | This is NOT a recommended configuration. |
    | Using the system memory allocator causes |
    | reduced performance and increased memory |
    | fragmentation. Installing the jemalloc   |
    | memory allocator (version >= 4.0.0) is   |
    | strongly recommended.                    |
    +------------------------------------------+
        ''',
    )
    message()
endif
