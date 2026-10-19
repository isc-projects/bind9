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
from isctest.asyncserver.handlers import SingleResponseHandler
from isctest.asyncserver.matchers import Qname, Qtype

from ..rpzrecurse_ans import AHandler, rrset


class ReplyA(AHandler):
    matcher = Qname("trigger.cve-2026-97313.test.") & Qtype(dns.rdatatype.A)
    address = "10.53.0.99"


class ReplyDefault(SingleResponseHandler):
    authority = [
        rrset(
            ".",
            dns.rdatatype.SOA,
            "a.root-servers.test. root.test. 1 3600 1200 604800 1",
            ttl=1,  # Important: this should be 1 so it expires early
        )
    ]


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(ReplyA())
    server.install_response_handlers(ReplyDefault())
    server.run()


if __name__ == "__main__":
    main()
