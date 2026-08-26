# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import isctest


def test_trust_anchor():
    with isctest.log.WatchLogFromStart("ns9/named.run") as watcher:
        watcher.wait_for_all(
            [
                "ignoring static-key for 'dh-trust-anchor.': algorithm is unsupported",
                "ignoring static-key for 'indirect-trust-anchor.': algorithm is unsupported",
                "ignoring static-key for 'hmac-157-trust-anchor.': algorithm is unsupported",
                "ignoring static-key for 'hmac-158-trust-anchor.': algorithm is unsupported",
                "ignoring static-key for 'hmac-159-trust-anchor.': algorithm is unsupported",
                "ignoring static-key for 'hmac-160-trust-anchor.': algorithm is unsupported",
                "ignoring static-key for 'hmac-161-trust-anchor.': algorithm is unsupported",
                "ignoring static-key for 'hmac-162-trust-anchor.': algorithm is unsupported",
                "ignoring static-key for 'hmac-163-trust-anchor.': algorithm is unsupported",
                "ignoring static-key for 'hmac-164-trust-anchor.': algorithm is unsupported",
                "ignoring static-key for 'hmac-165-trust-anchor.': algorithm is unsupported",
                "ignoring static-ds for 'dh-trust-anchor.': algorithm is unsupported",
                "ignoring static-ds for 'indirect-trust-anchor.': algorithm is unsupported",
                "ignoring static-ds for 'hmac-157-trust-anchor.': algorithm is unsupported",
                "ignoring static-ds for 'hmac-158-trust-anchor.': algorithm is unsupported",
                "ignoring static-ds for 'hmac-159-trust-anchor.': algorithm is unsupported",
                "ignoring static-ds for 'hmac-160-trust-anchor.': algorithm is unsupported",
                "ignoring static-ds for 'hmac-161-trust-anchor.': algorithm is unsupported",
                "ignoring static-ds for 'hmac-162-trust-anchor.': algorithm is unsupported",
                "ignoring static-ds for 'hmac-163-trust-anchor.': algorithm is unsupported",
                "ignoring static-ds for 'hmac-164-trust-anchor.': algorithm is unsupported",
                "ignoring static-ds for 'hmac-165-trust-anchor.': algorithm is unsupported",
            ]
        )
