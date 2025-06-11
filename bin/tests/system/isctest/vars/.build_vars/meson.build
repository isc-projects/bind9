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

if not pytest.found()
    subdir_done()
endif

configure_file(
    configuration: {'TOP_BUILDDIR': meson.project_build_root()},
    input: 'TOP_BUILDDIR.in',
    output: 'TOP_BUILDDIR',
)

configure_file(
    configuration: {'TOP_SRCDIR': meson.project_source_root()},
    input: 'TOP_SRCDIR.in',
    output: 'TOP_SRCDIR',
)

foreach name, prog : {
    'CURL': curl,
    'FSTRM_CAPTURE': fstrm_capture,
    'NC': nc,
    'PERL': perl,
    'PYTEST': pytest,
    'PYTHON': python,
    'SHELL': sh,
    'XSLTPROC': xsltproc,
}
    if prog.found()
        configure_file(
            configuration: {name: prog.full_path()},
            input: fs.replace_suffix(name, '.in'),
            output: name,
        )
    endif
endforeach

# Run a script to copy required files to the source directory in order to make
# pytest work and find the compiled files. This is executed on every incovation
# of the compile command, so the latest build is always used for system tests.
custom_target(
    'system-test-init',
    build_always_stale: true,
    build_by_default: true,
    command: meson.project_source_root() / 'util' / 'meson-system-test-init.sh',
    output: 'system-test-init', # not an actual file, but it's mandatory...
    env: env,
)
