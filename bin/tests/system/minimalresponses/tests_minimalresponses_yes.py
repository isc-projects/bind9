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

import pytest

from minimalresponses.common import INPUTPARAMS, INPUTS_YES_NOAUTH, check, reconfig


@pytest.fixture(scope="module", autouse=True)
def authsection_init(servers, templates):
    reconfig(servers, templates, "yes")


@pytest.mark.parametrize(INPUTPARAMS, INPUTS_YES_NOAUTH)
def test_minimalresponses_yes(
    ns, qname, qtype, rd, cached, rcode, answer, authority, additional
):
    check(ns, qname, qtype, rd, cached, rcode, answer, authority, additional)
