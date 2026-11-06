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

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.update
import pytest

import isctest

# what setup.sh and the servers leave behind
pytestmark = pytest.mark.extra_artifacts(
    [
        "ns*/*.bk",
        "ns*/*.db*",
        "ns*/*.key",
        "ns1/tls.conf",
        "ns3/K*",
        "ns3/dsset-*",
        "verylarge",
    ]
)


@pytest.mark.parametrize(
    "section",
    [dns.update.UpdateSection.UPDATE, dns.update.UpdateSection.ADDITIONAL],
    ids=["update", "additional"],
)
def test_type0_record_in_update(section, ns1):
    msg = dns.update.UpdateMessage(".")
    rrset = dns.rrset.RRset(dns.name.root, dns.rdataclass.NONE, dns.rdatatype.TYPE0)
    msg.section_from_number(section).append(rrset)

    with ns1.watch_log_from_here() as watcher:
        res = isctest.query.tcp(msg, ns1.ip)
        isctest.check.formerr(res)
        watcher.wait_for_line("message parsing failed: FORMERR")
