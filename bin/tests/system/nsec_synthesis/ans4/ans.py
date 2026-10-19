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


import dns.rcode
import dns.rdatatype

from isctest.asyncserver import AsyncDnsServer
from isctest.asyncserver.matchers import Qname, Qtype

from ..nsec_synthesis_ans import AttackNsecHandler


class AttackChildNsecHandler(AttackNsecHandler):
    """
    An NSEC for a name in the insecure child zone evil.f023.test whose next
    name reaches past target.f023.test in the signed parent.
    """

    matcher = Qname("0.evil.f023.test.") & Qtype(dns.rdatatype.NSEC)
    nsec = "zzz.f023.test. A RRSIG NSEC"
    key_tag = 12345


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(AttackChildNsecHandler())
    server.run()


if __name__ == "__main__":
    main()
