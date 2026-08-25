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
    Require every module to start with the license header above, optionally
    preceded by a shebang line and followed by an empty line.
    """

    name = "file-header"
    msgs = {
        "C9005": (
            "License header missing or not in the canonical form",
            "license-header",
            "Emitted when a module does not start with the ISC license header "
            "as a block of comments, optionally preceded by a shebang line.",
        ),
    }
    options = ()

    def process_module(self, node: nodes.Module) -> None:
        with node.stream() as stream:
            lines = [
                line.decode("utf-8", errors="replace").rstrip("\r\n") for line in stream
            ]

        start = 0
        if lines and lines[0].startswith("#!"):
            start = 1
            if len(lines) > 1 and lines[1] == "":
                start = 2

        end = start + len(LICENSE_HEADER)
        if lines[start:end] != LICENSE_HEADER or (
            len(lines) > end and lines[end] != ""
        ):
            self.add_message("license-header", line=1)


def register(linter: PyLinter) -> None:
    linter.register_checker(FileHeaderChecker(linter))
