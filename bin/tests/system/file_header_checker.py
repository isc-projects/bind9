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

import os
import stat

from astroid import nodes
from pylint.checkers import BaseRawFileChecker
from pylint.lint import PyLinter

# The same text as in the C sources, as a block of comments so that a module
# docstring can follow it.  The markers keep reuse from reading the quoted
# SPDX line as a second, malformed license tag of this file.
# REUSE-IgnoreStart
LICENSE_HEADER = [
    '# Copyright (C) Internet Systems Consortium, Inc. ("ISC")',
    "#",
    "# SPDX-License-Identifier: MPL-2.0",
    "#",
    "# This Source Code Form is subject to the terms of the Mozilla Public",
    "# License, v. 2.0. If a copy of the MPL was not distributed with this",
    "# file, you can obtain one at https://mozilla.org/MPL/2.0/.",
    "#",
    "# See the COPYRIGHT file distributed with this work for additional",
    "# information regarding copyright ownership.",
]
# REUSE-IgnoreEnd


class FileHeaderChecker(BaseRawFileChecker):
    """
    Require every module to start with the license header above, followed by
    an empty line, and to not be executable.

    The CI and the test runners have to control which Python interpreter runs
    a script, so every script is started through an explicit interpreter
    ($PYTHON, python -m, pytest) rather than by itself.  An executable bit and
    the shebang it calls for would only offer a second way to run the script,
    with whatever python is first in PATH.
    """

    name = "file-header"
    msgs = {
        "C9005": (
            "License header missing or not in the canonical form",
            "license-header",
            "Emitted when a module does not start with the ISC license header "
            "as a block of comments; a shebang line is not allowed either, since "
            "scripts are always run through an explicitly chosen interpreter.",
        ),
        "C9006": (
            "Python file must not be executable",
            "executable-python-file",
            "Emitted when a Python file has an executable bit set.  Scripts are "
            "run through an interpreter chosen by the caller (the CI, the test "
            "runner), never by themselves, so the bit only offers a way to run "
            "them with whatever python comes first in PATH.",
        ),
    }
    options = ()

    def process_module(self, node: nodes.Module) -> None:
        with node.stream() as stream:
            lines = [
                line.decode("utf-8", errors="replace").rstrip("\r\n") for line in stream
            ]

        end = len(LICENSE_HEADER)
        if lines[:end] != LICENSE_HEADER or (len(lines) > end and lines[end] != ""):
            self.add_message("license-header", line=1)

        if node.file and stat.S_IMODE(os.stat(node.file).st_mode) & 0o111:
            self.add_message("executable-python-file", line=1)


def register(linter: PyLinter) -> None:
    linter.register_checker(FileHeaderChecker(linter))
