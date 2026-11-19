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


import dns.dnssec
import dns.rdatatype
import dns.zone
import pytest

from nsec_synthesis.common import F004_ZONE, F023_ZONE

import isctest.template
import isctest.zone


def zone_key_tags(zone):
    signed = dns.zone.from_file(str(zone.path_signed), zone.dname, relativize=False)
    dnskeys = signed.get_rdataset(zone.dname, dns.rdatatype.DNSKEY)
    assert dnskeys, zone.path_signed
    return {dns.dnssec.key_id(dnskey) for dnskey in dnskeys}


@pytest.fixture(scope="module")
def f004_key_tags():
    return zone_key_tags(
        isctest.zone.Zone(F004_ZONE, isctest.template.ANS1, signed=True)
    )


@pytest.fixture(scope="module")
def f023_key_tags():
    return zone_key_tags(
        isctest.zone.Zone(F023_ZONE, isctest.template.ANS4, signed=True)
    )
