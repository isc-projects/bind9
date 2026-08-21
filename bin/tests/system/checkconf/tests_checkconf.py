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

import os

import isctest


def test_checkconf_effective():
    cmd = isctest.run.cmd([os.environ["CHECKCONF"], "-e", "effective.conf"])
    assert b"listen-on port 5353 {\n\t\t127.1.2.3/32;\n\t};" in cmd.proc.stdout
    assert 'view "_bind" chaos {' in cmd.out
    assert 'remote-servers "_default_iana_root_zone_primaries" {' in cmd.out
    assert b'view "foo" {\n}' in cmd.proc.stdout

    # builtin-trust-anchors is non documented and internal clause only, it must
    # not be visible.
    assert "builtin-trust-anchors" not in cmd.out


def test_checkconf_builtin():
    cmd = isctest.run.cmd([os.environ["CHECKCONF"], "-b"])
    assert b'listen-on  {\n\t\t"any";\n\t};' in cmd.proc.stdout
    assert 'view "_bind" chaos {' in cmd.out
    assert 'remote-servers "_default_iana_root_zone_primaries" {' in cmd.out

    # builtin-trust-anchors is non documented and internal clause only, it must
    # not be visible.
    assert "builtin-trust-anchors" not in cmd.out


# Because this is specifically testing an issue occuring in an included file,
# the `bad-` pattern can't be used here.
def test_checkconf_included_unexpectedeof():
    cmd = isctest.run.cmd(
        [os.environ["CHECKCONF"], "truncated-with-include.conf"],
        raise_on_exception=False,
    )

    assert (
        b"included-truncated.conf:1: unknown option 'b'\nincluded-truncated.conf:1: unexpected end of input \nincluded-truncated.conf:1: isc_symtab_define() failed \n"
        == cmd.proc.stdout
    )
    assert cmd.proc.returncode != 0
