# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

from pathlib import Path

import sys

SYSTEM_TEST_DIR_GIT_PATH = "bin/tests/system"


def load_vars_from_build_files() -> dict[str, str]:
    # TOP_BUILDDIR is special, it is always read from the source directory
    top_builddir_file = Path(__file__).resolve().parent / ".build_vars" / "TOP_BUILDDIR"
    if not top_builddir_file.exists():
        raise RuntimeError(
            'Uninitialized build variable: "TOP_BUILDDIR". Did you run `meson compile`?'
        )

    top_builddir = top_builddir_file.read_text(encoding="utf-8").strip()

    build_vars = {
        "TOP_BUILDDIR": top_builddir,
    }

    var_dir = (
        Path(top_builddir)
        / SYSTEM_TEST_DIR_GIT_PATH
        / "isctest"
        / "vars"
        / ".build_vars"
    )

    for var in [
        "CURL",
        "FSTRM_CAPTURE",
        "JQ",
        "NC",
        "PERL",
        "PYTEST",
        "PYTHON",
        "SHELL",
        "TOP_SRCDIR",
        "XMLLINT",
        "XSLTPROC",
    ]:
        var_file = var_dir / var
        if var_file.exists():
            build_vars[var] = var_file.read_text(encoding="utf-8").strip()

    # When running inside a virtualenv, prefer the virtualenv's interpreter
    # over the path baked in by meson.
    # This is needed because meson is configured to prefer specific versions
    # (e.g. python3.12 and python3.11) by default to properly detect the
    # right python interpreter in CI - this is undesirable when running
    # in a virtualenv as it can lead to the system tests using the system
    # versions of Python dependencies defeating the purpose of the virtual
    # environment.
    if sys.prefix != sys.base_prefix:
        build_vars["PYTHON"] = sys.executable

    return build_vars


BUILD_VARS = load_vars_from_build_files()
