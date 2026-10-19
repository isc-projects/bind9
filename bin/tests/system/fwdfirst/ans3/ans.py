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

from ..fwdfirst_ans import a

VICTIM = "victim.sibling.hack."
POISON_ADDRESS = "6.6.6.6"


class PoisonedAHandler(SingleResponseHandler):
    matcher = Qname(VICTIM) & Qtype(dns.rdatatype.A)
    answer = [a(VICTIM, POISON_ADDRESS)]


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(PoisonedAHandler())
    server.run()


if __name__ == "__main__":
    main()
