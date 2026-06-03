<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

= Fuzzing

Building the fuzzers is controlled by two meson options:

* `-Dfuzzing` (feature, `auto` by default) decides whether the fuzzing
  binaries are built at all.
* `-Dfuzzing-backend` (`none`, `afl`, `libfuzzer` or `oss-fuzz`, default
  `none`) selects which backend the binaries are wired up against.  The
  `none` backend still builds the binaries (so that breaking a fuzzer is
  caught at build time), but they only run in the non-fuzzing mode below.

The tests in this directory can be operated in the following modes:

* non-fuzzing (`-Dfuzzing-backend=none`) - the test just runs over all input
  located in the `<test_name>.in/` directory by compiling with the mock
  main.c that walks through the directory and runs
  `LLVMFuzzerTestOneInput()` over the input files.  This is what
  `meson test --suite fuzz` exercises.
* AFL (`-Dfuzzing-backend=afl`) - `main.c` will either feed the stdin to
  `LLVMFuzzerTestOneInput()` or run the `__AFL_LOOP(10000)` if compiled with
  `afl-clang-fast`.  You have to compile using an AFL wrapper, e.g.
  `CC=afl-clang-fast`.  The simplest way is the bundled cross file:

      CC=afl-clang-fast meson setup --cross-file fuzz/afl.ini build-afl
      ninja -C build-afl
      afl-fuzz -i fuzz/<test_name>.in -o findings -- ./build-afl/<test_name>

* LibFuzzer (`-Dfuzzing-backend=libfuzzer`) - `main.c` is disabled completely
  and the standard LibFuzzer mechanism feeds `LLVMFuzzerTestOneInput` with the
  fuzzer.  Requires clang; use the bundled cross file:

      meson setup --cross-file fuzz/libfuzzer.ini build-libfuzzer
      ninja -C build-libfuzzer
      ./build-libfuzzer/<test_name> fuzz/<test_name>.in

* OSS-Fuzz (`-Dfuzzing-backend=oss-fuzz`) - like LibFuzzer, but the
  instrumentation and linking flags are supplied externally via
  `-Doss-fuzz-args=...` (set from the OSS-Fuzz `$CFLAGS`/`$LIB_FUZZING_ENGINE`
  environment).

Note: with clang-based backends meson must be configured with
`-Db_lundef=false` (the cross files above already set this).

== Test Cases

Each test case should be called descriptively and the executable target must
link `testcase.o` and `main.o` and the `test_case.c` must have a function
`LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)`.

== Adding more fuzzers

To add a different fuzzer, `main.c` must be modified to include `main()` function
for a specific fuzzer (or no function as is case with LibFuzzer).
