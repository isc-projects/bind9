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
from isctest.template import ANS5

from ..rpzrecurse_ans import AHandler, DelayedNsHandler


class FooChildDelegationHandler(DelayedNsHandler):
    owner = "foo.child.example.tld."
    nameserver = "ns5.foo."
    delay = 3


class Ns5FooAHandler(AHandler):
    address = ANS5.ip


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        FooChildDelegationHandler(),
        Ns5FooAHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
