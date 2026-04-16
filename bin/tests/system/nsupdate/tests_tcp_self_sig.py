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

"""
Regression tests for GL#5818: SIG (type 24) records on the dynamic-update path.

1. test_tcp_self_sig_record:
   The dns_db_findrdataset() REQUIRE check only accepted
   dns_rdatatype_rrsig for the covers parameter, causing named to abort
   when processing a SIG record via dynamic update with tcp-self policy.

2. test_sig_covers_preserved_in_diff:
   The rdata_covers() helper in lib/dns/diff.c only recognised RRSIG (46),
   so it dropped the covered-type field for legacy SIG (24) records.  The
   zone DB then filed every SIG rdataset under typepair (SIG, 0) instead
   of (SIG, covered_type).  A second SIG add with a different covers and
   a different TTL collided at that bucket, tripped DNS_DBADD_EXACTTTL
   in qpzone, and came back as SERVFAIL.
"""

import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.update

import isctest


def _make_sig_rdata(text):
    """Create a SIG rdata from text.

    dnspython has no native text parser for the legacy SIG type (24),
    but the wire format is identical to RRSIG (46).  Parse as RRSIG,
    then re-wrap as SIG via the wire representation.
    """
    rrsig = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.RRSIG, text)
    wire = rrsig.to_digestable()
    return dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.SIG, wire, 0, len(wire))


def test_tcp_self_sig_record(ns6):
    """Verify that update-policy tcp-self accepts a SIG record via TCP.

    The node must already exist (have at least one RR) so that
    dns_db_findrdataset() is called during the update — that is the
    function whose REQUIRE was too strict.  We therefore add a PTR
    record first.
    """
    # First, create the node by adding a PTR record (allowed by tcp-self).
    ptr_update = dns.update.UpdateMessage("in-addr.arpa.")
    ptr_update.add("1.0.0.127.in-addr.arpa.", 600, "PTR", "localhost.")
    response = isctest.query.tcp(
        ptr_update, ns6.ip, port=ns6.ports.dns, source="127.0.0.1"
    )
    assert response.rcode() == dns.rcode.NOERROR

    # Now add a SIG record at the same node — this triggers the
    # dns_db_findrdataset() call with type=SIG and covers=A.
    sig = _make_sig_rdata("A 6 0 86400 20260331170000 20260318160000 21831 . 0000")
    rds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.SIG)
    rds.update_ttl(600)
    rds.add(sig)

    sig_update = dns.update.UpdateMessage("in-addr.arpa.")
    sig_update.add("1.0.0.127.in-addr.arpa.", rds)

    with ns6.watch_log_from_here() as watcher:
        response = isctest.query.tcp(
            sig_update, ns6.ip, port=ns6.ports.dns, source="127.0.0.1"
        )
        assert response.rcode() == dns.rcode.NOERROR

        watcher.wait_for_sequence(
            [
                "update-policy: using: signer= name=1.0.0.127.in-addr.arpa"
                " addr=127.0.0.1 tcp=1 type=SIG target=",
                "update-policy: trying: grant * tcp-self . PTR(1) ANY(2) A",
                "update-policy: tcp-self=1.0.0.127.IN-ADDR.ARPA",
                "update-policy: matched: grant * tcp-self . PTR(1) ANY(2) A",
            ]
        )

    # Verify the SIG record was actually stored
    msg = isctest.query.create("1.0.0.127.in-addr.arpa.", "SIG")
    res = isctest.query.tcp(msg, ns6.ip, port=ns6.ports.dns)
    found = any(rrset.rdtype == dns.rdatatype.SIG for rrset in res.answer)
    assert found, "SIG record not found in answer section"


def test_sig_covers_preserved_in_diff(ns6):
    """Regression test for GL#5818 Finding 1.

    lib/dns/diff.c rdata_covers() only recognised RRSIG and returned 0
    for SIG (24), so the zone DB stored every SIG rdataset under
    typepair (SIG, 0) instead of (SIG, covered_type).  The second add
    at the same name with a different covers field but a different TTL
    then targeted the same bucket, hit DNS_DBADD_EXACTTTL in qpzone's
    add(), and returned DNS_R_NOTEXACT -- which dns_diff_apply
    propagates as SERVFAIL.

    With the fix (rdata_covers using dns_rdatatype_issig), the two
    records land in separate typepairs and both updates succeed.
    """
    # tcp-self requires the client IP in reverse form to equal the
    # update's owner name.  Use a distinct (source, owner) pair so
    # this test does not interact with test_tcp_self_sig_record.
    source = "127.0.0.5"
    owner = "5.0.0.127.in-addr.arpa."

    # Create the node with a PTR (allowed by tcp-self).
    ptr = dns.update.UpdateMessage("in-addr.arpa.")
    ptr.add(owner, 600, "PTR", "localhost.")
    response = isctest.query.tcp(ptr, ns6.ip, port=ns6.ports.dns, source=source)
    assert response.rcode() == dns.rcode.NOERROR

    # First SIG: covers=A, TTL=600.
    sig_a = _make_sig_rdata("A 6 0 600 20260331170000 20260318160000 21831 . 0000")
    rds_a = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.SIG)
    rds_a.update_ttl(600)
    rds_a.add(sig_a)
    upd_a = dns.update.UpdateMessage("in-addr.arpa.")
    upd_a.add(owner, rds_a)
    response = isctest.query.tcp(upd_a, ns6.ip, port=ns6.ports.dns, source=source)
    assert response.rcode() == dns.rcode.NOERROR

    # Second SIG: different covers (MX) and different TTL (1200).  With
    # the fix this lands in typepair (SIG, MX) and succeeds.  Without
    # the fix it collides with the first record at typepair (SIG, 0),
    # the TTL mismatch trips DNS_DBADD_EXACTTTL in qpzone, and
    # dns_diff_apply returns DNS_R_NOTEXACT -> SERVFAIL.
    sig_mx = _make_sig_rdata("MX 6 0 1200 20260331170000 20260318160000 21831 . 0000")
    rds_mx = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.SIG)
    rds_mx.update_ttl(1200)
    rds_mx.add(sig_mx)
    upd_mx = dns.update.UpdateMessage("in-addr.arpa.")
    upd_mx.add(owner, rds_mx)
    response = isctest.query.tcp(upd_mx, ns6.ip, port=ns6.ports.dns, source=source)
    assert response.rcode() == dns.rcode.NOERROR, (
        f"second SIG add returned {dns.rcode.to_text(response.rcode())}; Finding 1 (rdata_covers dropping "
        "covers for SIG) is likely still present"
    )

    # Both SIG rdatas must be retrievable.
    q = isctest.query.create(owner, "SIG")
    res = isctest.query.tcp(q, ns6.ip, port=ns6.ports.dns)
    sig_count = sum(
        1 for rrset in res.answer if rrset.rdtype == dns.rdatatype.SIG for _ in rrset
    )
    assert sig_count == 2, f"expected 2 SIG rdatas, got {sig_count}"
