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
from isctest.asyncserver.handlers import SingleResponseHandler
from isctest.asyncserver.matchers import Domain
from isctest.template import ANS3

from ..fwdfirst_ans import a, ns


class PoisonReferralForwarder(SingleResponseHandler):
    matcher = Domain("fwd.hack.")
    authority = [ns(matcher.domain.parent(), f"ns.{matcher.domain}")]
    additional = [a(f"ns.{matcher.domain}", ANS3.ip)]
    rcode = dns.rcode.NOERROR
    authoritative = False


def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handlers(PoisonReferralForwarder())
    server.run()


if __name__ == "__main__":
    main()
