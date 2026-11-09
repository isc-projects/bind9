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

import os

import pytest

import isctest
import isctest.mark


def dnstap_confs(pattern):
    # Collection happens before the test directory becomes the working
    # directory, so look next to this file.
    return sorted(path.name for path in Path(__file__).parent.glob(pattern))


# The dnstap-*.conf files are kept out of the bad-*/good-* loops in tests.sh
# because they only make sense when dnstap support is compiled in.
@isctest.mark.with_dnstap
@pytest.mark.parametrize("conf", dnstap_confs("dnstap-bad-*.conf"))
def test_checkconf_dnstap_bad(conf):
    cmd = isctest.run.cmd([os.environ["CHECKCONF"], conf], raise_on_exception=False)
    assert cmd.proc.returncode == 1


@isctest.mark.with_dnstap
@pytest.mark.parametrize("conf", dnstap_confs("dnstap-good-*.conf"))
def test_checkconf_dnstap_good(conf):
    isctest.run.cmd([os.environ["CHECKCONF"], conf])
