<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

# Fuzzing

Building the fuzzers is controlled by two meson options:

* `-Dfuzzing` (feature, `auto` by default) decides whether the fuzzing
  binaries are built at all.
* `-Dfuzzing-backend` (`none`, `afl`, `libfuzzer` or `oss-fuzz`, default
  `none`) selects which backend the binaries are wired up against.  The
  `none` backend still builds the binaries (so that breaking a fuzzer is
  caught at build time), but they only run in the non-fuzzing mode below.

The build targets are named `fuzz_<test_name>` (see `fuzz_binaries` in
`fuzz/meson.build`), while the test cases of a fuzzer live in
`fuzz/<test_name>.in/`.

The tests in this directory can be operated in the following modes:

* non-fuzzing (`-Dfuzzing-backend=none`) - the test just runs over all input
  located in the `<test_name>.in/` directory by compiling with the mock
  main.c that walks through the directory and runs
  `LLVMFuzzerTestOneInput()` over the input files.  Individual test cases
  can be passed on the command line instead, and `-d` as the first argument
  turns on the `debug` flag.  The binary fails if an input could not be read
  or no test case ran, so that an incomplete or misnamed corpus cannot
  silently pass.
* AFL (`-Dfuzzing-backend=afl`) - `main.c` will either feed the stdin to
  `LLVMFuzzerTestOneInput()` or run the `__AFL_LOOP(10000)` if compiled with
  `afl-clang-fast`.  You have to compile using an AFL wrapper; the bundled
  cross file selects `afl-cc`, and meson refuses to configure the backend
  with a compiler that is not one:

      meson setup --cross-file fuzz/afl.ini build-afl
      ninja -C build-afl
      afl-fuzz -i fuzz/<test_name>.in -o findings -- ./build-afl/fuzz_<test_name>

* LibFuzzer (`-Dfuzzing-backend=libfuzzer`) - `main.c` is disabled completely
  and the standard LibFuzzer mechanism feeds `LLVMFuzzerTestOneInput` with the
  fuzzer.  Requires clang; use the bundled cross file:

      meson setup --cross-file fuzz/libfuzzer.ini build-libfuzzer
      ninja -C build-libfuzzer
      ./build-libfuzzer/fuzz_<test_name> fuzz/<test_name>.in

* OSS-Fuzz (`-Dfuzzing-backend=oss-fuzz`) - like LibFuzzer, but the
  instrumentation flags are supplied externally through `$CFLAGS` and
  the engine linking arguments through `-Doss-fuzz-args=$LIB_FUZZING_ENGINE`.
  The build recipe lives in `projects/bind9/` of the
  https://github.com/google/oss-fuzz repository.

`meson test --suite fuzz` replays the repository corpora with every backend.
LibFuzzer uses `-runs=0`; AFL and OSS-Fuzz use separate standalone replay
binaries. These tests terminate after replay rather than starting an
unbounded fuzzing session.

Note: with clang-based backends meson must be configured with
`-Db_lundef=false` (the cross files above already set this).  Configuring
any backend also disables link time optimization of `named`, because LTO
discards the sanitizer coverage sections the backends need.

## Test Cases

Each test case should be called descriptively.  `fuzz/<test_name>.c` must
define `LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` and
`LLVMFuzzerInitialize()`; both are declared in `fuzz.h`.  Add the file,
together with `main.c`, as a new `fuzz_<test_name>` entry of the
`fuzz_binaries` dictionary in `fuzz/meson.build`, and put the sample inputs
into `fuzz/<test_name>.in/`.

The fuzz binaries link only `libisc` and `libdns`; they deliberately avoid the
`libbindtest` test library (`fuzz_dns_qp` pulls in just the QP test helpers via
`libtest_qp_dep`), so that a static build stays self-contained.

## Adding more fuzzers

To add a different fuzzer, add its name to the `fuzzing-backend` choices in
`meson.options`, handle it in the fuzzing section of the top-level
`meson.build`, and add the `main()` function for that fuzzer to `main.c` (or
no function, as is the case with LibFuzzer).
