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
Regression test for GL#5818: update-policy tcp-self must handle SIG records.

The dns_db_findrdataset() REQUIRE check only accepted dns_rdatatype_rrsig
for the covers parameter, causing named to abort when processing a SIG
record (type 24) via dynamic update with tcp-self policy.
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
