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

from nsec_synthesis.common import ARTIFACTS, check_nsec, get_nsec, has_a

import isctest
import isctest.template
import isctest.zone

PARENT = "f007.test."
CHILD = "!.f007.test."
PROBE = f"probe.{CHILD}"
VICTIM = f"victim.{PARENT}"
VICTIM_A = "203.0.113.7"

pytestmark = ARTIFACTS


def bootstrap():
    child = isctest.zone.Zone(CHILD, isctest.template.NS3, signed=True)
    child.configure(csk=True)
    parent = isctest.zone.Zone(PARENT, isctest.template.NS3, signed=True)
    parent.delegations = [child]
    parent.configure(csk=True)
    return {
        "trust_anchors": parent.trust_anchors(),
        "zones": isctest.template.zones([parent, child]),
    }


def test_direct_child_self_loop_nsec_fixture(ns3):
    response = isctest.query.tcp(isctest.query.create(PROBE, "A"), ns3.ip)
    isctest.check.nxdomain(response)
    isctest.check.aaflag(response)
    check_nsec(response, response.authority, CHILD, CHILD, CHILD)


def test_resolver_does_not_synth_parent_nxdomain_from_child_nsec(ns2):
    poison = isctest.query.tcp(isctest.query.create(PROBE, "A"), ns2.ip)
    isctest.check.nxdomain(poison)
    isctest.check.adflag(poison)
    check_nsec(poison, poison.authority, CHILD, CHILD, CHILD)

    response = isctest.query.tcp(isctest.query.create(VICTIM, "A"), ns2.ip)
    isctest.check.noerror(response)
    assert has_a(response, VICTIM, VICTIM_A), response.to_text()
    isctest.check.adflag(response)
    assert not get_nsec(response, response.authority, CHILD)
