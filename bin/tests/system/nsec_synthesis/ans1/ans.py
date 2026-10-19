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


import dns.flags
import dns.rcode
import dns.rdatatype

from isctest.asyncserver import AsyncDnsServer
from isctest.asyncserver.matchers import Flags, Qname, Qtype

from ..nsec_synthesis_ans import AttackNsecHandler


class AttackCoveringNsecHandler(AttackNsecHandler):
    """
    An NSEC whose next name reaches past victim.f004.test, covering it.
    """

    matcher = (
        Qname("attacker.f004.test.") & Qtype(dns.rdatatype.NSEC) & Flags(dns.flags.CD)
    )
    nsec = "b.victim.f004.test. A RRSIG NSEC"


class AttackNodataNsecHandler(AttackNsecHandler):
    """
    An NSEC owned by victim.f004.test itself, whose type bitmap omits A but
    includes the NSEC and RRSIG types query_coveringnsec() requires; if
    trusted, it would prove a NODATA for victim/A and hide the real A record.
    """

    matcher = (
        Qname("victim.f004.test.") & Qtype(dns.rdatatype.NSEC) & Flags(dns.flags.CD)
    )
    nsec = "z.f004.test. TXT RRSIG NSEC"


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR, default_aa=True)
    server.install_response_handlers(
        AttackCoveringNsecHandler(),
        AttackNodataNsecHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
