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

"""Regression tests for GL#5818: legacy DNSSEC types on the dynamic-update path.

SIG (24) and NXT (30) are obsolete DNSSEC record types, superseded by RRSIG
and NSEC in RFC 3755.  Allowing a client to inject them via dynamic update
exposed two bugs in sequence:

  * dns__db_findrdataset() asserted `covers == 0 || type == RRSIG`, which
    crashed named when a SIG update reached the prescan foreach_rr() call.
  * diff.c rdata_covers() dropped the covered type for SIG rdatas, so the
    zone DB stored every SIG rdataset under typepair (SIG, 0) instead of
    (SIG, covered_type); a second SIG add with a different covers and
    different TTL then tripped DNS_DBADD_EXACTTTL in qpzone and came back
    as SERVFAIL.

The adopted defence is to treat the legacy SIG and NXT records as normal RR
records without any special processing.

"""

from re import compile as Re

import re
import time

import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.tsigkeyring
import dns.update
import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ans*/ans.run",
        "ns*/*.bk",
        "ns*/*.conf",
        "ns*/*.db",
        "ns*/*.db.jnl",
        "ns*/*.db.signed",
        "ns*/*.jnl",
        "ns*/*.key",
        "ns*/K*.key",
        "ns*/K*.private",
        "ns*/K*.state",
        "ns*/dsset-*.",
        "ns6/sigaxfr.bk",
        "verylarge",
    ]
)


def _make_sig_rdata(text):
    """Create a SIG rdata from text.

    dnspython has no native text parser for the legacy SIG type (24),
    but the wire format is identical to RRSIG (46).  Parse as RRSIG,
    then re-wrap as SIG via the wire representation.
    """
    rrsig = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.RRSIG, text)
    wire = rrsig.to_digestable()
    return dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.SIG, wire, 0, len(wire))


def _make_nxt_rdata():
    """Create a minimal NXT rdata.

    NXT wire format (RFC 2535) is: next-name + type-bitmap.  The exact
    content does not matter for the refusal test; we just need a
    syntactically valid NXT rdata.
    """
    # next-name = root (\x00), type bitmap covering type A only.
    wire = b"\x00\x00\x00\x00\x40"
    return dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.NXT, wire, 0, len(wire))


def test_tcp_self_sig_record(ns6):
    """SIG (type 24) updates are accepted and stored as opaque rdata.

    Per RFC 3755 SIG is obsolete (superseded by RRSIG).  BIND treats
    incoming SIG records as a generic unknown type with no covered-type
    semantics: dynamic updates carrying SIG are accepted and the record
    becomes queryable.  A PTR add first ensures the node exists.
    """
    owner = "1.0.53.10.in-addr.arpa."

    ptr_update = dns.update.UpdateMessage("in-addr.arpa.")
    ptr_update.add(owner, 600, "PTR", "localhost.")
    response = isctest.query.tcp(
        ptr_update, ns6.ip, port=ns6.ports.dns, source="10.53.0.1"
    )
    assert response.rcode() == dns.rcode.NOERROR

    sig = _make_sig_rdata("A 6 0 86400 20260331170000 20260318160000 21831 . 0000")
    rds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.SIG)
    rds.update_ttl(600)
    rds.add(sig)
    sig_update = dns.update.UpdateMessage("in-addr.arpa.")
    sig_update.add(owner, rds)

    response = isctest.query.tcp(
        sig_update, ns6.ip, port=ns6.ports.dns, source="10.53.0.1"
    )
    assert response.rcode() == dns.rcode.NOERROR

    # Confirm the SIG record was stored.
    msg = isctest.query.create(owner, "SIG")
    res = isctest.query.tcp(msg, ns6.ip, port=ns6.ports.dns)
    stored = any(rrset.rdtype == dns.rdatatype.SIG for rrset in res.answer)
    assert stored, "SIG record was not stored despite NOERROR response"


def test_tcp_self_nxt_record(ns6):
    """NXT (type 30) updates are accepted and stored as opaque rdata.

    NXT is the legacy DNSSEC denial-of-existence type, obsolete since
    RFC 3755 replaced it with NSEC.  BIND treats it as a generic
    unknown rdata type.
    """
    source = "10.53.0.2"
    owner = "2.0.53.10.in-addr.arpa."

    ptr_update = dns.update.UpdateMessage("in-addr.arpa.")
    ptr_update.add(owner, 600, "PTR", "localhost.")
    response = isctest.query.tcp(ptr_update, ns6.ip, port=ns6.ports.dns, source=source)
    assert response.rcode() == dns.rcode.NOERROR

    nxt = _make_nxt_rdata()
    rds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.NXT)
    rds.update_ttl(600)
    rds.add(nxt)
    nxt_update = dns.update.UpdateMessage("in-addr.arpa.")
    nxt_update.add(owner, rds)

    response = isctest.query.tcp(nxt_update, ns6.ip, port=ns6.ports.dns, source=source)
    assert response.rcode() == dns.rcode.NOERROR

    # Confirm the NXT record was stored.
    msg = isctest.query.create(owner, "NXT")
    res = isctest.query.tcp(msg, ns6.ip, port=ns6.ports.dns)
    stored = any(rrset.rdtype == dns.rdatatype.NXT for rrset in res.answer)
    assert stored, "NXT record was not stored despite NOERROR response"


def test_sig_axfr_stored_opaque(ns6):
    """SIG records received via AXFR are stored as opaque rdata.

    ans11 serves an AXFR for sigaxfr.nil. containing two SIG rdatas at
    the same owner with different "covered type" body fields (A, MX).
    Per RFC 3755 SIG has no covered-type semantics; both rdatas land in
    a single opaque rdataset and both survive in the zone DB.

    rndc dumpdb is used to inspect the secondary's stored state
    directly; the wire-level response can merge same-(owner,type,class)
    RRs and mask the difference.
    """
    zone = "sigaxfr.nil"
    owner = f"host.{zone}."
    dump_path = ns6.directory / "named_dump.db"

    # ns6 may have tried to SOA-poll ans11 before it was listening; force
    # a fresh refresh attempt and wait for the transfer to complete.
    with ns6.watch_log_from_here() as watcher:
        ns6.rndc(f"refresh {zone}")
        watcher.wait_for_line(f"zone {zone}/IN: transferred serial 1")

    # Remove any stale dump and ask named for a fresh one.
    if dump_path.exists():
        dump_path.unlink()
    ns6.rndc("dumpdb -zones")

    # rndc dumpdb is asynchronous; wait for the file and for its
    # trailing "Dump complete" marker.
    deadline_marker = "; Dump complete"
    for _ in range(50):
        if dump_path.exists():
            text = dump_path.read_text()
            if deadline_marker in text:
                break
        time.sleep(0.1)
    else:
        raise AssertionError(f"{dump_path} never contained {deadline_marker!r}")

    # Collect every SIG line for the owner from the dump.
    sig_lines = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        if not fields[0].lower().startswith("host.sigaxfr.nil"):
            continue
        if fields[2] != "IN" or fields[3] != "SIG":
            continue
        sig_lines.append(fields)

    assert (
        len(sig_lines) == 2
    ), f"expected 2 SIG rdatas at {owner}, got {len(sig_lines)}: {sig_lines}"

    ttls = {int(fields[1]) for fields in sig_lines}
    assert ttls == {600}, f"SIG rdataset should share a single TTL, got {ttls}"


def parse_named_conf_keys(conf_text):
    """
    Extract TSIG keys from a BIND named.conf-style string.
    Returns a dict suitable for dns.tsigkeyring.from_text().
    """
    key_re = Re(
        r'key\s+"(?P<name>[^"]+)"\s*\{(?P<body>.*?)\};', re.DOTALL | re.IGNORECASE
    )
    field_re = Re(r"(?P<field>algorithm|secret)\s+(?P<value>[^;]+);", re.IGNORECASE)

    keys = {}

    for match in key_re.finditer(conf_text):
        name = match.group("name")
        body = match.group("body")

        fields = {}
        for fmatch in field_re.finditer(body):
            field = fmatch.group("field").lower()
            value = fmatch.group("value").strip().strip('"')
            fields[field] = value

        if "secret" not in fields:
            continue  # skip incomplete entries

        algorithm = fields.get("algorithm", "hmac-sha256")

        # Ensure FQDN key name
        key_name = name if name.endswith(".") else name + "."

        keys[key_name] = (algorithm.lower(), fields["secret"])

    return keys


def keyring_from_file(keyfile):
    with open(keyfile, "r", encoding="utf-8") as file:
        data = file.read()

    keys = parse_named_conf_keys(data)
    return dns.tsigkeyring.from_text(keys)


def test_prereq_sig_record(ns1):
    keyring = keyring_from_file("ns1/ddns.key")

    # First, create the node.
    node_update = dns.update.UpdateMessage("example.nil.", keyring=keyring)
    node_update.add("sig.example.nil.", 600, "A", "10.53.0.11")
    response = isctest.query.tcp(
        node_update, ns1.ip, port=ns1.ports.dns, source="10.53.0.1"
    )
    assert response.rcode() == dns.rcode.NOERROR

    # Now require a SIG record at the same node — this triggers the
    # dns_db_findrdataset() call with type=SIG and covers=A.
    sig = _make_sig_rdata("A 6 0 86400 20260331170000 20260318160000 21831 . 0000")
    rds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.SIG)
    rds.update_ttl(0)
    rds.add(sig)

    # First attempt with no matching credentials.
    sig_update = dns.update.UpdateMessage("example.nil.")  # no key
    sig_update.present("sig.example.nil.", rds)
    sig_update.add("sig.example.nil.", 600, "TXT", "I require SIG")

    with ns1.watch_log_from_here() as watcher:
        response = isctest.query.tcp(
            sig_update, ns1.ip, port=ns1.ports.dns, source="10.53.0.1"
        )
        assert response.rcode() == dns.rcode.REFUSED

        watcher.wait_for_sequence(
            [
                "update-policy: using: signer= name=sig.example.nil addr=10.53.0.1 tcp=1 type=TXT target=",
                "update-policy: trying: grant zonesub-key.example.nil zonesub TXT",
                "update-policy: trying: grant ddns-key.example.nil subdomain example.nil ANY",
                "update-policy: no match found",
                "updating zone 'example.nil/IN': update failed: rejected by secure update (REFUSED)",
            ]
        )

    # Second attempt with the right key.
    sig_update = dns.update.UpdateMessage("example.nil.", keyring=keyring)
    sig_update.present("sig.example.nil.", rds)
    sig_update.add("sig.example.nil.", 600, "TXT", "I require SIG")

    with ns1.watch_log_from_here() as watcher:
        response = isctest.query.tcp(
            sig_update, ns1.ip, port=ns1.ports.dns, source="10.53.0.1"
        )
        assert response.rcode() == dns.rcode.NXRRSET

        watcher.wait_for_sequence(
            [
                "update-policy: using: signer=ddns-key.example.nil name=sig.example.nil addr=10.53.0.1 tcp=1 type=TXT target=",
                "update-policy: trying: grant zonesub-key.example.nil zonesub TXT",
                "update-policy: trying: grant ddns-key.example.nil subdomain example.nil ANY",
                "update-policy: matched: grant ddns-key.example.nil subdomain example.nil ANY",
                "updating zone 'example.nil/IN': update section prescan OK",
                "updating zone 'example.nil/IN': update unsuccessful: sig.example.nil/SIG: 'RRset exists (value dependent)' prerequisite not satisfied (NXRRSET)",
                "updating zone 'example.nil/IN': rolling back",
            ]
        )
