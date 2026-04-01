#!/usr/bin/python3

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

from dataclasses import dataclass
import os
from pathlib import Path
import re
from re import compile as Re
from typing import Any, Dict, Optional, Union

import pytest

from .log import debug

NS_DIR_RE = Re(r"^(a?ns([0-9]+))/")


class TemplateEngine:
    """
    Engine for rendering jinja2 templates in system test directories.
    """

    def __init__(self, directory: Union[str, Path], env_vars=None):
        """
        Initialize the template engine for `directory`, optionally overriding
        the `env_vars` that will be used when rendering the templates (defaults
        to the environment variables set by the pytest runner).
        """
        self.directory = Path(directory)
        self._j2env = None
        if env_vars is None:
            self.env_vars = dict(os.environ)
        else:
            self.env_vars = dict(env_vars)

    @property
    def j2env(self):
        """
        Jinja2 engine that is initialized when first requested. In case the
        jinja2 package in unavailable, the current test will be skipped.
        """
        if self._j2env is None:
            try:
                import jinja2  # pylint: disable=import-outside-toplevel
            except ImportError:
                pytest.skip("jinja2 not found")

            loader = jinja2.FileSystemLoader(str(self.directory))
            return jinja2.Environment(
                loader=loader,
                undefined=jinja2.StrictUndefined,
                variable_start_string="@",
                variable_end_string="@",
            )
        return self._j2env

    def render(
        self,
        output: str,
        data: Optional[Dict[str, Any]] = None,
        template: Optional[str] = None,
    ) -> None:
        """
        Render `output` file from jinja `template` and fill in the `data`. The
        `template` defaults to *.j2.manual or *.j2 file. The environment
        variables which the engine was initialized with are also filled in. In
        case of a variable name clash, `data` has precedence.
        """
        if template is None:
            template = f"{output}.j2.manual"
            if not Path(template).is_file():
                template = f"{output}.j2"
        if not Path(template).is_file():
            raise RuntimeError('No jinja2 template found for "{output}"')

        if data is None:
            data = {**self.env_vars}
        else:
            data = {**self.env_vars, **data}

        # directory-specific "ns" var
        assert "ns" not in data, '"ns" variable is reserved for nameserver data'
        match = NS_DIR_RE.search(output)
        if match:
            data["ns"] = Nameserver(match.group(1))

        debug("rendering template `%s` to file `%s`", template, output)
        stream = self.j2env.get_template(template).stream(data)
        stream.dump(output, encoding="utf-8")

    def render_auto(self, data: Optional[Dict[str, Any]] = None):
        """
        Render all *.j2 templates with default (and optionally the provided)
        values and write the output to files without the .j2 extensions.
        """
        templates = [
            str(filepath.relative_to(self.directory))
            for filepath in self.directory.rglob("*.j2")
        ]
        for template in templates:
            self.render(template[:-3], data)


@dataclass
class Nameserver:

    name: str
    num: int | None = None
    ip: str | None = None
    ip6: str | None = None

    def __post_init__(self):
        if self.num is None:
            match = re.search(r"\d+", self.name)
            assert match
            self.num = int(match.group(0))
        if self.ip is None:
            self.ip = f"10.53.0.{self.num}"
        if self.ip6 is None:
            self.ip6 = f"fd92:7065:b8e:ffff::{self.num}"


NS1 = Nameserver("ns1")
NS2 = Nameserver("ns2")
NS3 = Nameserver("ns3")
NS4 = Nameserver("ns4")
NS5 = Nameserver("ns5")
NS6 = Nameserver("ns6")
NS7 = Nameserver("ns7")
NS8 = Nameserver("ns8")
NS9 = Nameserver("ns9")
NS10 = Nameserver("ns10")
NS11 = Nameserver("ns11")


@dataclass
class Zone:

    name: str
    ns: Nameserver
    type: str = "primary"
    filename: str | None = None

    def __post_init__(self):
        if self.filename is None:
            self.filename = f"{self.name}.db"


@dataclass
class TrustAnchor:
    domain: str
    type: str
    contents: str
