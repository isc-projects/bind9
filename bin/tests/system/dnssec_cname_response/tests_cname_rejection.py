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

from re import compile as Re

import base64
import time

from cryptography.hazmat.primitives.asymmetric import ec
from dns.rdtypes.dnskeybase import Flag

import dns.dnssec
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.zone
import pytest

from isctest.template import ANS2

import isctest


def _sign_zone(db_in, signed_out, origin):
    """
    Sign 'db_in' with a fresh KSK; write 'signed_out'; return the KSK
    public key (base64) for use as a static trust anchor.
    """
    ksk_private_key = ec.generate_private_key(ec.SECP384R1())
    ksk_dnskey = dns.dnssec.make_dnskey(
        public_key=ksk_private_key.public_key(),
        algorithm=dns.dnssec.Algorithm.ECDSAP384SHA384,
        flags=Flag.ZONE | Flag.SEP,
    )

    zone = dns.zone.from_file(db_in, origin=origin)
    with zone.writer() as txn:
        dns.dnssec.sign_zone(
            zone=zone,
            txn=txn,
            keys=[(ksk_private_key, ksk_dnskey)],
            lifetime=300,
            add_dnskey=True,
            deterministic=False,  # for OpenSSL<3.2.0 compat
        )
    zone.to_file(signed_out)

    return base64.b64encode(ksk_dnskey.key).decode()


def _sign_nsec3_zone(db_in, signed_out, origin) -> isctest.template.TrustAnchor:
    """
    Sign 'db_in' with NSEC3 using dnssec-signzone; write 'signed_out';
    return the KSK as a static-key trust anchor.
    """
    zone = isctest.zone.Zone(
        origin,
        ANS2,
        signed=True,
        filepath_unsigned=db_in,
        filepath_signed=signed_out,
    )
    zone.add_keys()
    zone.sign("-3 - -H 0")
    return zone.trust_anchors("static-key")[0]


def bootstrap():
    try:
        result = {
            "ksk_public_key": _sign_zone(
                "ans2/example.db.in", "ans2/example.signed.db", "example."
            ),
            "secure_ksk_public_key": _sign_zone(
                "ans2/secure.db.in", "ans2/secure.signed.db", "secure."
            ),
            "parent_ksk_public_key": _sign_zone(
                "ans2/parent.db.in",
                "ans2/zones/parent.db.signed",
                "parent.",
            ),
            "stuffed_ta": _sign_nsec3_zone(
                "stuffed.db.in", "stuffed.signed.zone", "stuffed."
            ),
        }
    except ImportError as exc:
        pytest.skip(f"{exc}")
    return result


def _assert_alive(ip):
    liveness = isctest.query.create("version.bind.", "TXT", dns.rdataclass.CH, rd=False)
    res = isctest.query.tcp(liveness, ip, timeout=5)
    assert (
        res is not None
    ), f"{ip} did not answer a liveness query -- it may have crashed"


# With QNAME minimization (ns3), validator and client fetch options differ,
# testing a sibling DS fetch; ns4 tests a direct join of the client fetch.
RESOLVERS = ["ns3", "ns4"]

EXPECTED_CNAME = dns.rrset.from_text(
    "insecure.parent.",
    300,
    dns.rdataclass.IN,
    dns.rdatatype.CNAME,
    "cname-target.insecure.parent.",
)
EXPECTED_A = dns.rrset.from_text(
    "cname-target.insecure.parent.",
    300,
    dns.rdataclass.IN,
    dns.rdatatype.A,
    "192.0.2.1",
)


def _query_insecure_parent(ns, qtype):
    return isctest.query.tcp(isctest.query.create("insecure.parent.", qtype), ns.ip)


def _check_insecure_cname_chain(res):
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    answers = {rrset.rdtype: rrset for rrset in res.answer}
    assert set(answers) == {dns.rdatatype.CNAME, dns.rdatatype.A}, res
    assert answers[dns.rdatatype.CNAME] == EXPECTED_CNAME, res
    assert answers[dns.rdatatype.A] == EXPECTED_A, res


@pytest.mark.parametrize("qtype", ["DNSKEY", "NSEC", "NSEC3", "RRSIG"])
def test_direct_metatype_query_does_not_crash_resolver(qtype):
    """
    A direct recursive client query for a DNSSEC meta-type, answered by a
    malicious authoritative server with a CNAME, must not crash the
    resolver. This probes the client-facing consumers of the resolver
    fetch (ns_query/query_cname), not the validator's internal fetch.

    A resolver fetch that completes with DNS_R_CNAME goes through the
    normal answer path, which binds the answer name and rdataset. An
    earlier resolver-side shortcut returned DNS_R_CNAME without binding
    them, so query_cname() handed an empty (non-absolute) name to
    dns_message_addname() and named aborted on REQUIRE(dns_name_isabsolute).
    """
    msg = isctest.query.create("sub.example.", qtype)

    start_time = time.time()
    res = isctest.query.tcp(msg, "10.53.0.3", timeout=8)
    elapsed_time = time.time() - start_time

    # The resolver must answer promptly. An RRSIG query is handled as a
    # subset of ANY, and a CNAME answer to it used to be dropped without
    # caching or validation, leaving the fetch waiting ~12s for a
    # validator that was never started.
    assert elapsed_time < 5.0, f"{qtype} query took too long: {elapsed_time}s"

    # We do not assert a particular rcode here -- SERVFAIL or a chased
    # answer are both acceptable. The point is that named survives.
    assert res is not None, f"no response to direct {qtype} query"
    _assert_alive("10.53.0.3")


def test_rrsig_lone_record_does_not_stall_resolver():
    """
    A direct recursive RRSIG query answered with an unrelated record
    (here a lone A, with no RRSIG and no alias) must not stall the
    resolver. An RRSIG query is handled as a subset of ANY; every record
    of the wrong type is filtered out, and when nothing is left the
    answer used to be accepted as success with no answer bound, leaving
    the fetch waiting ~12s for a validator that was never started.
    """
    msg = isctest.query.create("lone-a.example.", "RRSIG")

    start_time = time.time()
    res = isctest.query.tcp(msg, "10.53.0.3", timeout=8)
    elapsed_time = time.time() - start_time

    assert elapsed_time < 5.0, f"RRSIG query took too long: {elapsed_time}s"
    assert res is not None, "no response to lone-record RRSIG query"
    _assert_alive("10.53.0.3")


def test_cname_for_validator_dnskey_fetch(ns3):
    """
    A malicious authoritative server returning a CNAME for the
    validator's DNSKEY fetch must not stall validation. The DNSKEY
    fetch completes with DNS_R_CNAME, which the validator treats as a
    broken trust chain, so the client query terminates with SERVFAIL
    rather than hanging. No resolver-side special case is needed: the
    validator already rejects a CNAME answer to its meta-fetch.
    """
    log_brokenchain = Re(r"broken trust chain resolving 'www\.example/A/IN'")

    msg = isctest.query.create("www.example.", "A")

    start_time = time.time()
    with ns3.watch_log_from_here(timeout=5) as watcher:
        res = isctest.query.tcp(msg, "10.53.0.3")
        watcher.wait_for_line(log_brokenchain)
    elapsed_time = time.time() - start_time

    assert elapsed_time < 5.0, f"Query took too long: {elapsed_time}s"
    isctest.check.servfail(res)


@pytest.mark.parametrize("resolver", RESOLVERS)
def test_ds_cname_does_not_deadlock(servers, resolver):
    """
    An unsigned CNAME answer to a DS query makes validation fetch the same DS.
    Reject the fetch loop promptly instead of waiting for a timeout (GL#5878).
    """
    ns = servers[resolver]
    log_loop = Re(r"fetch loop detected resolving 'insecure\.secure/DS")
    msg = isctest.query.create("insecure.secure.", "DS")

    start_time = time.time()
    with ns.watch_log_from_here(timeout=5) as watcher:
        res = isctest.query.tcp(msg, ns.ip, timeout=8)
        watcher.wait_for_line(log_loop)
    elapsed_time = time.time() - start_time

    assert (
        elapsed_time < 5.0
    ), f"DS query took too long: {elapsed_time}s (possible deadlock)"
    isctest.check.servfail(res)
    _assert_alive(ns.ip)


@pytest.mark.parametrize("resolver", RESOLVERS)
def test_cname_at_insecure_delegation_is_accepted(servers, resolver):
    """
    An insecure apex CNAME must allow fetching the parent's DS denial and
    remain usable from cache (GL#6435).
    """
    ns = servers[resolver]

    res = _query_insecure_parent(ns, "A")
    _check_insecure_cname_chain(res)

    res = _query_insecure_parent(ns, "DS")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    res = _query_insecure_parent(ns, "NS")
    isctest.check.noerror(res)
    answers = {rrset.rdtype: rrset for rrset in res.answer}
    assert answers.get(dns.rdatatype.CNAME) == EXPECTED_CNAME, res

    # Repeat with a warm cache.
    res = _query_insecure_parent(ns, "A")
    _check_insecure_cname_chain(res)

    assert not ns.log.grep(Re(r"deadlock found resolving 'insecure\.parent"))
    assert not ns.log.grep(Re(r"fetch loop detected resolving 'insecure\.parent"))


def test_apex_cname_coexists_with_other_types(ns3):
    """
    Caching an apex CNAME must preserve an existing MX RRset.
    """
    expected_mx = dns.rrset.from_text(
        "insecure.parent.",
        300,
        dns.rdataclass.IN,
        dns.rdatatype.MX,
        "10 mail.insecure.parent.",
    )

    def check_mx(res):
        isctest.check.noerror(res)
        assert len(res.answer) == 1
        isctest.check.rrsets_equal(res.answer[0], expected_mx)

    # Cache MX first; a cached CNAME would answer the MX query via the alias.
    ns3.rndc("flushtree insecure.parent")

    res = _query_insecure_parent(ns3, "MX")
    check_mx(res)

    res = _query_insecure_parent(ns3, "A")
    _check_insecure_cname_chain(res)

    res = _query_insecure_parent(ns3, "MX")
    check_mx(res)

    with ns3.watch_log_from_here() as watcher:
        ns3.rndc("dumpdb -cache")
        watcher.wait_for_line("dumpdb complete")
    dump = isctest.text.TextFile(f"{ns3.identifier}/named_dump.db")
    # Match unique RDATA because the dump omits repeated owner names.
    assert len(dump.grep(Re(r"\tMX\t10 mail\.insecure\.parent\.$"))) == 1
    assert len(dump.grep(Re(r"\tCNAME\tcname-target\.insecure\.parent\.$"))) == 1


def test_unsolicited_nsec3_proofs_are_rejected(ns3):
    """
    A malicious authoritative server can place every NSEC3 RRset and its
    RRSIGs in an NXDOMAIN authority section. The resolver must reject the
    response before validating all those unsolicited proof RRsets.
    """
    log_max_validations = Re(r"maximum number of validations exceeded")
    msg = isctest.query.create("absent.stuffed.", "A")

    start_time = time.time()
    with ns3.watch_log_from_here(timeout=5) as watcher:
        res = isctest.query.tcp(msg, "10.53.0.3", timeout=8)
        watcher.wait_for_line(log_max_validations)
    elapsed_time = time.time() - start_time

    assert elapsed_time < 5.0, f"Query took too long: {elapsed_time}s"
    isctest.check.servfail(res)
    _assert_alive("10.53.0.3")
