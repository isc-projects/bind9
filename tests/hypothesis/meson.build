# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
# SPDX-License-Identifier: MPL-2.0

# Keep these dependencies independent of dnstap and cmocka.
hypothesis_protoc = find_program('protoc', required: false)
hypothesis_protoc_c = find_program('protoc-c', required: false)
hypothesis_proto_dep = dependency('libprotobuf-c', required: false)
if not python.found() or not hypothesis_protoc.found() or not hypothesis_protoc_c.found() or not hypothesis_proto_dep.found()
    subdir_done()
endif

accumulator_proto_c = custom_target(
    'accumulator-protobuf-c',
    input: 'accumulator.proto',
    output: ['accumulator.pb-c.c', 'accumulator.pb-c.h'],
    command: [
        hypothesis_protoc_c,
        '--proto_path=@CURRENT_SOURCE_DIR@',
        '--c_out=@OUTDIR@',
        '@INPUT@',
    ],
)
accumulator_proto_py = custom_target(
    'accumulator-protobuf-python',
    input: 'accumulator.proto',
    output: 'accumulator_pb2.py',
    command: [
        hypothesis_protoc,
        '--proto_path=@CURRENT_SOURCE_DIR@',
        '--python_out=@OUTDIR@',
        '@INPUT@',
    ],
)
accumulator_server = executable(
    'accumulator_server',
    'accumulator_server.c',
    accumulator_proto_c,
    default_sanitize_options,
    include_directories: test_inc,
    dependencies: [libisc_dep, hypothesis_proto_dep],
    build_by_default: false,
    install: false,
)
accumulator_env = environment(test_env_vars)
accumulator_env.set('ACCUMULATOR_SERVER', accumulator_server.full_path())
accumulator_env.set('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')
accumulator_env.prepend('PYTHONPATH', meson.current_build_dir())
test(
    'accumulator-hypothesis',
    python,
    args: files('accumulator.py'),
    depends: [accumulator_server, accumulator_proto_py],
    env: accumulator_env,
    suite: ['hypothesis'],
    timeout: 300,
    workdir: meson.current_build_dir(),
)

vec_proto_c = custom_target(
    'vecheader-protobuf-c',
    input: 'vecheader.proto',
    output: ['vecheader.pb-c.c', 'vecheader.pb-c.h'],
    command: [
        hypothesis_protoc_c,
        '--proto_path=@CURRENT_SOURCE_DIR@',
        '--c_out=@OUTDIR@',
        '@INPUT@',
    ],
)
vec_proto_py = custom_target(
    'vecheader-protobuf-python',
    input: 'vecheader.proto',
    output: 'vecheader_pb2.py',
    command: [
        hypothesis_protoc,
        '--proto_path=@CURRENT_SOURCE_DIR@',
        '--python_out=@OUTDIR@',
        '@INPUT@',
    ],
)
vec_server = executable(
    'vecheader_server',
    'vecheader_server.c',
    vec_proto_c,
    default_sanitize_options,
    include_directories: test_inc,
    dependencies: [libdns_dep, libisc_dep, hypothesis_proto_dep],
    build_by_default: false,
    install: false,
)
vec_env = environment(test_env_vars)
vec_env.set('VECHEADER_SERVER', vec_server.full_path())
vec_env.set('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')
vec_env.prepend('PYTHONPATH', meson.current_build_dir())
vec_env.append('PYTHONPATH', meson.project_source_root() / 'bin/tests/system')
test(
    'vecheader-hypothesis',
    python,
    args: files('vecheader.py'),
    depends: [vec_server, vec_proto_py],
    env: vec_env,
    suite: ['dns', 'hypothesis'],
    timeout: 300,
    workdir: meson.current_build_dir(),
)
