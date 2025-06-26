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

from dns import flags, message


def msg(qname: str, qtype: str, **kwargs):
    headerflags = flags.RD
    # "ad" is on by default
    if "ad" not in kwargs or not kwargs["ad"]:
        headerflags |= flags.AD
    # "cd" is off by default
    if "cd" in kwargs and kwargs["cd"]:
        headerflags |= flags.CD
    return message.make_query(
        qname, qtype, use_edns=True, want_dnssec=True, flags=headerflags
    )
