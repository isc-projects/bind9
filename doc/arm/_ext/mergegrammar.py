############################################################################
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
############################################################################

# Depends on CWD - Sphinx plugin

import json
from pathlib import Path

from . import parsegrammar


def read_zone():
    zone_grammars = {}
    for file in Path("../misc/").glob("*.zoneopt"):
        zone_type = f"type {file.stem}"

        with file.open(encoding="ascii") as fp:
            zonegrammar = parsegrammar.parse_mapbody(fp)
            assert len(zonegrammar) == 1
            assert "zone" in zonegrammar
            zone_grammars[zone_type] = zonegrammar["zone"]

    return {"zone": {"_mapbody": zone_grammars}}


def read_main():
    with Path("../misc/options").open(encoding="ascii") as fp:
        optgrammar = parsegrammar.parse_mapbody(fp)
    return optgrammar


def combine():
    zones = read_zone()
    assert zones
    rest = read_main()
    assert rest
    rest.update(zones)

    return rest


if __name__ == "__main__":
    full_grammar = combine()
    print(json.dumps(full_grammar))
