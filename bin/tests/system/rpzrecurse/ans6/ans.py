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

from isctest.asyncserver import AsyncDnsServer
from isctest.template import ANS6

from ..rpzrecurse_ans import AHandler, DelayedNsHandler


class WwwBarDelegationHandler(DelayedNsHandler):
    owner = "www.bar."
    nameserver = "ns6.foo."
    delay = 1


class Ns6FooAHandler(AHandler):
    address = ANS6.ip


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        WwwBarDelegationHandler(),
        Ns6FooAHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
