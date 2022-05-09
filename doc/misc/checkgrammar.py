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

"""
Utility to check ISC config grammar consistency. It detects statement names
which use different grammar depending on position in the configuration file.
E.g. "max-zone-ttl" in dnssec-policy uses '<duration>'
vs. '( unlimited | <duration> ) used in options.
"""

from collections import namedtuple
from itertools import groupby
from pprint import pformat
import fileinput

import parsegrammar


def statement2block(grammar, path):
    """Return mapping statement name to "path" where it is allowed.
    _top is placeholder name for the namesless topmost context.

    E.g. {
        'options: [('_top',)],
        'server': [('_top', 'view'), ('_top',)],
        'rate-limit': [('_top', 'options'), ('_top', 'view')],
        'slip': [('_top', 'options', 'rate-limit'), ('_top', 'view', 'rate-limit')]
    }
    """
    key2place = {}

    for key in grammar:
        assert not key.startswith("_")
        key2place.setdefault(key, []).append(tuple(path))
        if "_mapbody" in grammar[key]:
            nested2block = statement2block(grammar[key]["_mapbody"], path + [key])
            # merge to uppermost output dictionary
            for nested_key, nested_path in nested2block.items():
                key2place.setdefault(nested_key, []).extend(nested_path)
    return key2place


def get_statement_grammar(grammar, path, name):
    """Descend into grammar dict using provided path
    and return final dict found there.

    Intermediate steps into "_mapbody" subkeys are done automatically.
    """
    assert path[0] == "_top"
    path = list(path) + [name]
    for step in path[1:]:
        if "_mapbody" in grammar:
            grammar = grammar["_mapbody"]
        grammar = grammar[step]
    return grammar


Statement = namedtuple("Statement", ["path", "name", "subgrammar"])


def groupby_grammar(statements):
    """
    Return groups of Statement tuples with identical grammars and flags.
    See itertools.groupby.
    """

    def keyfunc(statement):
        return sorted(statement.subgrammar.items())

    groups = []
    statements = sorted(statements, key=keyfunc)
    for _key, group in groupby(statements, keyfunc):
        groups.append(list(group))  # Store group iterator as a list
    return groups


def diff_statements(whole_grammar, places):
    """
    Return map {statement name: [groups of [Statement]s with identical grammar].
    """
    out = {}
    for statement_name, paths in places.items():
        grammars = []
        for path in paths:
            statement_grammar = get_statement_grammar(
                whole_grammar, path, statement_name
            )
            grammars.append(Statement(path, statement_name, statement_grammar))
        groups = groupby_grammar(grammars)
        out[statement_name] = groups
    return out


def main():
    """
    Ingest output from cfg_test --grammar and print out statements which use
    different grammar in different contexts.
    """
    with fileinput.input() as filein:
        grammar = parsegrammar.parse_mapbody(filein)
    places = statement2block(grammar, ["_top"])

    for statementname, groups in diff_statements(grammar, places).items():
        if len(groups) > 1:
            print(f'statement "{statementname}" is inconsistent across blocks')
            for group in groups:
                print(
                    "- path:", ", ".join(" -> ".join(variant.path) for variant in group)
                )
                print(" ", pformat(group[0].subgrammar))
            print()


if __name__ == "__main__":
    main()
