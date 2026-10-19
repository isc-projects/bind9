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

from isctest.asyncserver import ControllableAsyncDnsServer

from ..reclimit_ans import (
    CountAndResetHandler,
    DirectExampleHandler,
    FallbackNxdomainHandler,
    IndirectExampleOrgHandler,
    LimitControlCommand,
    Ns1ExampleOrgHandler,
    ReclimitState,
)


def main() -> None:
    server = ControllableAsyncDnsServer(
        default_aa=True, default_rcode=dns.rcode.NOERROR
    )
    state = ReclimitState()
    server.install_response_handlers(
        CountAndResetHandler(state),
        DirectExampleHandler(state, 4),
        IndirectExampleOrgHandler(state, 4),
        Ns1ExampleOrgHandler(state),
        FallbackNxdomainHandler(state),
    )
    server.install_control_command(LimitControlCommand(state))
    server.run()


if __name__ == "__main__":
    main()
