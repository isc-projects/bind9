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

from astroid import nodes
from pylint.checkers import BaseChecker
from pylint.lint import PyLinter

QUOTES = b'"""'
PREFIX_CHARS = b"rRuUbBfF"


class DocstringFormatChecker(BaseChecker):
    """
    Require every docstring to keep its quotes on lines of their own:

        \"\"\"
        text
        \"\"\"

    rather than a one-liner or text sharing a line with either set of quotes.
    """

    name = "docstring-format"
    msgs = {
        "C9004": (
            "Docstring quotes must be on their own lines",
            "docstring-quotes-not-alone",
            "Emitted when a docstring starts or ends on the same line as its "
            "opening or closing triple quotes.",
        ),
    }

    def __init__(self, linter: PyLinter) -> None:
        super().__init__(linter)
        self._lines: list[bytes] = []

    def visit_module(self, node: nodes.Module) -> None:
        # astroid column offsets count bytes, so keep the lines as bytes
        with node.stream() as stream:
            self._lines = [line.rstrip(b"\r\n") for line in stream]
        self._check(node)

    def visit_classdef(self, node: nodes.ClassDef) -> None:
        self._check(node)

    def visit_functiondef(self, node: nodes.FunctionDef) -> None:
        self._check(node)

    visit_asyncfunctiondef = visit_functiondef

    def _check(self, node: nodes.NodeNG) -> None:
        doc = node.doc_node
        if doc is None or doc.lineno is None or doc.end_lineno is None:
            return

        opening = self._lines[doc.lineno - 1][doc.col_offset :].lstrip(PREFIX_CHARS)
        closing = self._lines[doc.end_lineno - 1][: doc.end_col_offset]
        if not opening.startswith(QUOTES) or not closing.endswith(QUOTES):
            return

        if (
            doc.lineno == doc.end_lineno
            or opening[len(QUOTES) :].strip()
            or closing[: -len(QUOTES)].strip()
        ):
            self.add_message("docstring-quotes-not-alone", node=doc)


def register(linter: PyLinter) -> None:
    linter.register_checker(DocstringFormatChecker(linter))
