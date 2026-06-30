#!/usr/bin/env python

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


from pathlib import Path

import argparse
import json
import subprocess
import sys

ASAN = False
UBSAN = False
TSAN = False

args = argparse.ArgumentParser()
args.add_argument("build")
args = args.parse_args()

build = Path(args.build)

# https://mesonbuild.com/IDE-integration.html#build-options
#
# e.g. { "name": "b_sanitize", "value": ["address", "undefined"], ... }
#
with (build / "meson-info" / "intro-buildoptions.json").open() as f:
    options = json.load(f)

    for opt in options:
        if opt["name"] == "b_sanitize":
            ASAN = "address" in opt["value"]
            UBSAN = "undefined" in opt["value"]
            TSAN = "thread" in opt["value"]
            break

if not (ASAN or UBSAN or TSAN):
    print("no sanitizer check necessary")
    sys.exit(0)

with (build / "meson-info" / "intro-targets.json").open() as f:
    targets = json.load(f)

    for target in targets:
        if target["type"] == "executable" and Path(target["filename"][0]).exists():
            nm = subprocess.run(
                ["nm", target["filename"][0]],
                stdin=None,
                stdout=subprocess.PIPE,
                timeout=60,
                check=True,
                shell=False,
            )

            if ASAN and b"__asan_default_options" not in nm.stdout:
                print(f"Default ASAN options missing for executable '{target['name']}'")
                sys.exit(1)

            if UBSAN and b"__ubsan_default_options" not in nm.stdout:
                print(
                    f"Default UBSAN options missing for executable '{target['name']}'"
                )
                sys.exit(1)

            if TSAN and b"__tsan_default_options" not in nm.stdout:
                print(f"Default TSAN options missing for executable '{target['name']}'")
                sys.exit(1)

print("all relevant sanitizer defaults are set")
