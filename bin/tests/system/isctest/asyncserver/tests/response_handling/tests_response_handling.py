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

import asyncio

import dns.message
import dns.rcode
import dns.rrset
import dns.tsig
import pytest

from isctest.asyncserver import _make_asyncserver_response
from isctest.asyncserver.actions import DnsResponseSend
from isctest.template import ANS1

import isctest


def query(qname: str) -> dns.message.Message:
    msg = isctest.query.create(qname, "A", dnssec=False, rd=False)
    return isctest.query.tcp(msg, ANS1.ip, timeout=3, attempts=1)


def test_rollback_restores_the_response_from_zone_data():
    res = query("rollback.response.test.")
    isctest.check.noerror(res)
    isctest.check.aaflag(res)
    isctest.check.section_equal(
        res.answer,
        [dns.rrset.from_text("rollback.response.test.", 300, "IN", "A", "192.0.2.1")],
    )


def test_fresh_response_keeps_the_server_defaults():
    res = query("fresh.response.test.")
    isctest.check.rcode(res, dns.rcode.NOTIMP)
    isctest.check.aaflag(res)
    isctest.check.empty_answer(res)
    isctest.check.empty_authority(res)


def test_changes_after_rendering_reach_the_wire():
    res = query("rendered.response.test.")
    isctest.check.noerror(res)
    isctest.check.noaaflag(res)
    isctest.check.section_equal(
        res.answer,
        [
            dns.rrset.from_text("rendered.response.test.", 300, "IN", "A", "192.0.2.2"),
            dns.rrset.from_text(
                "rendered.response.test.", 300, "IN", "TXT", '"added after rendering"'
            ),
        ],
    )


QUERY = dns.message.make_query("unit.test.", "A")


def perform(action: DnsResponseSend) -> dns.message.Message | bytes | None:
    return asyncio.run(action.perform())


def test_hand_rolled_response_is_refused():
    response = dns.message.make_response(QUERY)
    action = DnsResponseSend(response)
    with pytest.raises(RuntimeError, match="prepare_new_response"):
        perform(action)
    action = DnsResponseSend(response, acknowledge_hand_rolled_response=True)
    assert perform(action) is response


def test_aa_change_on_a_signed_response_is_refused():
    response = _make_asyncserver_response(QUERY)
    response.use_tsig(dns.tsig.Key("key.", "c2VjcmV0"))
    response.to_wire()
    assert response.tsig is not None
    with pytest.raises(RuntimeError, match="TSIG"):
        perform(DnsResponseSend(response, authoritative=True))
    assert perform(DnsResponseSend(response)) is response
