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

import shutil
from typing import Optional

import dns.flags
import dns.rcode
import dns.message
import dns.zone

import isctest.log
from isctest.compat import dns_rcode


def rcode(message: dns.message.Message, expected_rcode) -> None:
    assert message.rcode() == expected_rcode, str(message)


def noerror(message: dns.message.Message) -> None:
    rcode(message, dns_rcode.NOERROR)


def notimp(message: dns.message.Message) -> None:
    rcode(message, dns_rcode.NOTIMP)


def refused(message: dns.message.Message) -> None:
    rcode(message, dns_rcode.REFUSED)


def servfail(message: dns.message.Message) -> None:
    rcode(message, dns_rcode.SERVFAIL)


def adflag(message: dns.message.Message) -> None:
    assert (message.flags & dns.flags.AD) != 0, str(message)


def noadflag(message: dns.message.Message) -> None:
    assert (message.flags & dns.flags.AD) == 0, str(message)


def rdflag(message: dns.message.Message) -> None:
    assert (message.flags & dns.flags.RD) != 0, str(message)


def nordflag(message: dns.message.Message) -> None:
    assert (message.flags & dns.flags.RD) == 0, str(message)


def section_equal(sec1: list, sec2: list) -> None:
    # convert an RRset to a normalized string (lower case, TTL=0)
    # so it can be used as a set member.
    def normalized(rrset):
        ttl = rrset.ttl
        rrset.ttl = 0
        s = str(rrset).lower()
        rrset.ttl = ttl
        return s

    # convert the section contents to sets before comparison,
    # in case they aren't in the same sort order.
    set1 = {normalized(item) for item in sec1}
    set2 = {normalized(item) for item in sec2}
    assert set1 == set2


def same_data(res1: dns.message.Message, res2: dns.message.Message):
    assert res1.question == res2.question
    section_equal(res1.answer, res2.answer)
    section_equal(res1.authority, res2.authority)
    section_equal(res1.additional, res2.additional)
    assert res1.rcode() == res2.rcode()


def same_answer(res1: dns.message.Message, res2: dns.message.Message):
    assert res1.question == res2.question
    section_equal(res1.answer, res2.answer)
    assert res1.rcode() == res2.rcode()


def rrsets_equal(
    first_rrset: dns.rrset.RRset,
    second_rrset: dns.rrset.RRset,
    compare_ttl: Optional[bool] = False,
) -> None:
    """Compare two RRset (optionally including TTL)"""

    def compare_rrs(rr1, rrset):
        rr2 = next((other_rr for other_rr in rrset if rr1 == other_rr), None)
        assert rr2 is not None, f"No corresponding RR found for: {rr1}"
        if compare_ttl:
            assert rr1.ttl == rr2.ttl

    isctest.log.debug(
        "%s() first RRset:\n%s",
        rrsets_equal.__name__,
        "\n".join([str(rr) for rr in first_rrset]),
    )
    isctest.log.debug(
        "%s() second RRset:\n%s",
        rrsets_equal.__name__,
        "\n".join([str(rr) for rr in second_rrset]),
    )
    for rr in first_rrset:
        compare_rrs(rr, second_rrset)
    for rr in second_rrset:
        compare_rrs(rr, first_rrset)


def zones_equal(
    first_zone: dns.zone.Zone,
    second_zone: dns.zone.Zone,
    compare_ttl: Optional[bool] = False,
) -> None:
    """Compare two zones (optionally including TTL)"""

    isctest.log.debug(
        "%s() first zone:\n%s",
        zones_equal.__name__,
        first_zone.to_text(relativize=False),
    )
    isctest.log.debug(
        "%s() second zone:\n%s",
        zones_equal.__name__,
        second_zone.to_text(relativize=False),
    )
    assert first_zone == second_zone
    if compare_ttl:
        for name, node in first_zone.nodes.items():
            for rdataset in node:
                found_rdataset = second_zone.find_rdataset(
                    name=name, rdtype=rdataset.rdtype
                )
                assert found_rdataset
                assert found_rdataset.ttl == rdataset.ttl


def is_executable(cmd: str, errmsg: str) -> None:
    executable = shutil.which(cmd)
    assert executable is not None, errmsg


def nxdomain(message: dns.message.Message) -> None:
    rcode(message, dns.rcode.NXDOMAIN)


def single_question(message: dns.message.Message) -> None:
    assert len(message.question) == 1, str(message)


def empty_answer(message: dns.message.Message) -> None:
    assert not message.answer, str(message)


def answer_count_eq(m: dns.message.Message, expected: int):
    count = sum(max(1, len(rrs)) for rrs in m.answer)
    assert count == expected, str(m)


def authority_count_eq(m: dns.message.Message, expected: int):
    count = sum(max(1, len(rrs)) for rrs in m.authority)
    assert count == expected, str(m)


def additional_count_eq(m: dns.message.Message, expected: int):
    count = sum(max(1, len(rrs)) for rrs in m.additional)

    # add one for the OPT?
    opt = bool(m.opt) if hasattr(m, "opt") else bool(m.edns >= 0)
    count += 1 if opt else 0

    # add one for the TSIG?
    tsig = bool(m.tsig) if hasattr(m, "tsig") else m.had_tsig
    count += 1 if tsig else 0

    assert count == expected, str(m)


def is_response_to(response: dns.message.Message, query: dns.message.Message) -> None:
    single_question(response)
    single_question(query)
    assert query.is_response(response), str(response)
