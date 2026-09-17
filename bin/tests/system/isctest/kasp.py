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

from functools import total_ordering
from pathlib import Path

import dns.dnssec
import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.tsig
import dns.zone
import dns.zonefile

from isctest.template import TrustAnchor

DEFAULT_TTL = 300


@total_ordering
class Key:
    """
    Represent a key from a keyfile.

    This object keeps track of its origin (keydir + name), can be used to
    retrieve metadata from the underlying files and supports convenience
    operations for KASP tests.
    """

    def __init__(self, name: str, keydir: str | Path | None = None):
        self.name = name
        if keydir is None:
            self.keydir = Path()
        else:
            self.keydir = Path(keydir)
        self.path = str(self.keydir / name)
        self.privatefile = f"{self.path}.private"
        self.keyfile = f"{self.path}.key"
        self.statefile = f"{self.path}.state"
        self.tag = int(self.name[-5:])
        self.external = False

    @property
    def dnskey(self) -> dns.rrset.RRset:
        with open(self.keyfile, "r", encoding="utf-8") as file:
            rrsets = dns.zonefile.read_rrsets(
                file.read(),
                rdclass=None,  # read rdclass from the file
                default_ttl=DEFAULT_TTL,  # use this TTL if not present
            )
        assert len(rrsets) == 1, f"{self.keyfile} has multiple RRsets"
        dnskey_rr = rrsets[0]
        assert len(dnskey_rr) == 1, f"{self.keyfile} has multiple RRs"
        assert (
            dnskey_rr.rdtype == dns.rdatatype.DNSKEY
        ), f"DNSKEY not found in {self.keyfile}"
        return dnskey_rr

    def into_ta(self, ta_type: str, dsdigest=dns.dnssec.DSDigest.SHA256) -> TrustAnchor:
        dnskey = self.dnskey
        if ta_type in ["static-ds", "initial-ds"]:
            ds = dns.dnssec.make_ds(dnskey.name, dnskey[0], dsdigest)
            parts = str(ds).split()
            contents = " ".join(parts[:3]) + f' "{parts[3]}"'
        elif ta_type in ["static-key", "initial-key"]:
            parts = str(dnskey).split()
            contents = " ".join(parts[4:7]) + f' "{"".join(parts[7:])}"'
        else:
            raise ValueError(f"invalid trust anchor type: {ta_type}")
        return TrustAnchor(str(dnskey.name), ta_type, contents)

    def __lt__(self, other: "Key"):
        return self.name < other.name

    def __eq__(self, other: object):
        return isinstance(other, Key) and self.path == other.path

    def __repr__(self):
        return self.path
