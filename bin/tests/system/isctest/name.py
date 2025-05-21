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

from dns.name import Name


def prepend_label(label: str, name: Name) -> Name:
    return Name((label,) + name.labels)


def len_wire_uncompressed(name: Name) -> int:
    return len(name) + sum(map(len, name.labels))
