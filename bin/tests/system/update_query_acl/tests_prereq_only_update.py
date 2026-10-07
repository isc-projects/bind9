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

"""
Regression test for GL#6216: prerequisite-only UPDATEs honour the query ACLs.

An UPDATE carrying only prerequisites is answered with NXDOMAIN, YXDOMAIN,
NXRRSET, or YXRRSET, revealing whether a name, RRset, or RDATA exists.  It
must therefore be refused wherever an ordinary query would be, by
allow-query and by allow-query-on alike.  This must hold for an
inline-signed zone too, although named processes its UPDATEs on the raw
zone loaded from the file rather than on the signed zone it serves and
configures the ACLs on.

With update-policy, an unsigned UPDATE over TCP gets as far as the
prerequisite checks, as its empty update section gives the policy
nothing to reject, so that is the request used to probe: ns1 refuses
queries by client and ns2 by local address, each with an inline-signed
and a plain zone.
"""

import dns.rcode
import dns.update
import pytest

from isctest.template import NS1, NS2
from isctest.zone import Zone

import isctest

pytestmark = pytest.mark.extra_artifacts(["ns*/K*"])

ZONES = ["inline", "plain"]

# The ACL that refuses ordinary queries for the zones of each server.
SERVERS = {
    "allow-query": "ns1",
    "allow-query-on": "ns2",
}

# None of these prerequisites is satisfied by the zone content, so that a
# response which did evaluate them names the check that failed rather than
# being a plain NOERROR.
PREREQUISITES = [
    pytest.param(
        lambda update, zone: update.present(f"missing.{zone}."),
        id="name-in-use",
    ),
    pytest.param(
        lambda update, zone: update.absent(f"a.{zone}."),
        id="name-not-in-use",
    ),
    pytest.param(
        lambda update, zone: update.present(f"a.{zone}.", "AAAA"),
        id="rrset-exists",
    ),
    pytest.param(
        lambda update, zone: update.absent(f"a.{zone}.", "A"),
        id="rrset-does-not-exist",
    ),
    pytest.param(
        lambda update, zone: update.present(f"a.{zone}.", "A", "10.0.0.2"),
        id="rrset-exists-value",
    ),
]


def bootstrap():
    for ns in (NS1, NS2):
        for name in ZONES:
            Zone(name, ns).configure()


@pytest.fixture(name="server", params=SERVERS.keys())
def server_fixture(request, servers):
    return servers[SERVERS[request.param]]


@pytest.mark.parametrize("zone", ZONES)
def test_query_refused(server, zone):
    """
    Sanity check: an ordinary query for the zone content is refused.

    The signed zone is set up asynchronously after startup, so keep asking
    until the query ACL answers rather than a not-yet-loaded database.
    """
    msg = isctest.query.create(f"a.{zone}.", "A")
    response = isctest.query.tcp(msg, server.ip, expected_rcode=dns.rcode.REFUSED)
    isctest.check.refused(response)


@pytest.mark.parametrize("zone", ZONES)
def test_query_answered_on_loopback(ns2, zone):
    """
    Sanity check: ns2 does answer the same query on the local address that
    its allow-query-on permits.
    """
    msg = isctest.query.create(f"a.{zone}.", "A")
    response = isctest.query.tcp(
        msg, "127.0.0.1", ns2.ports.dns, expected_rcode=dns.rcode.NOERROR
    )
    isctest.check.noerror(response)
    isctest.check.has_answer(response)


@pytest.mark.parametrize("prerequisite", PREREQUISITES)
@pytest.mark.parametrize("zone", ZONES)
def test_prerequisite_only_update_refused(server, zone, prerequisite):
    """
    An unsigned prerequisite-only UPDATE must reveal no more than a query.
    """
    update = dns.update.UpdateMessage(zone)
    prerequisite(update, zone)
    response = isctest.query.tcp(update, server.ip)
    isctest.check.refused(response)
