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

import os

# pylint: disable=import-error
from .build import BUILD_VARS  # type: ignore

# pylint: enable=import-error


BASIC_VARS = {
    "ARPANAME": f"{BUILD_VARS['TOP_BUILDDIR']}/arpaname",
    "CDS": f"{BUILD_VARS['TOP_BUILDDIR']}/dnssec-cds",
    "CHECKCONF": f"{BUILD_VARS['TOP_BUILDDIR']}/named-checkconf",
    "CHECKZONE": f"{BUILD_VARS['TOP_BUILDDIR']}/named-checkzone",
    "DIG": f"{BUILD_VARS['TOP_BUILDDIR']}/dig",
    "DNSTAPREAD": f"{BUILD_VARS['TOP_BUILDDIR']}/dnstap-read",
    "DSFROMKEY": f"{BUILD_VARS['TOP_BUILDDIR']}/dnssec-dsfromkey",
    "FEATURETEST": f"{BUILD_VARS['TOP_BUILDDIR']}/feature-test",
    "HOST": f"{BUILD_VARS['TOP_BUILDDIR']}/host",
    "IMPORTKEY": f"{BUILD_VARS['TOP_BUILDDIR']}/dnssec-importkey",
    "JOURNALPRINT": f"{BUILD_VARS['TOP_BUILDDIR']}/named-journalprint",
    "KEYFRLAB": f"{BUILD_VARS['TOP_BUILDDIR']}/dnssec-keyfromlabel",
    "KEYGEN": f"{BUILD_VARS['TOP_BUILDDIR']}/dnssec-keygen",
    "KSR": f"{BUILD_VARS['TOP_BUILDDIR']}/dnssec-ksr",
    "MDIG": f"{BUILD_VARS['TOP_BUILDDIR']}/mdig",
    "NAMED": f"{BUILD_VARS['TOP_BUILDDIR']}/named",
    "NSEC3HASH": f"{BUILD_VARS['TOP_BUILDDIR']}/nsec3hash",
    "NSLOOKUP": f"{BUILD_VARS['TOP_BUILDDIR']}/nslookup",
    "NSUPDATE": f"{BUILD_VARS['TOP_BUILDDIR']}/nsupdate",
    "NZD2NZF": f"{BUILD_VARS['TOP_BUILDDIR']}/named-nzd2nzf",
    "REVOKE": f"{BUILD_VARS['TOP_BUILDDIR']}/dnssec-revoke",
    "RNDC": f"{BUILD_VARS['TOP_BUILDDIR']}/rndc",
    "RNDCCONFGEN": f"{BUILD_VARS['TOP_BUILDDIR']}/rndc-confgen",
    "RRCHECKER": f"{BUILD_VARS['TOP_BUILDDIR']}/named-rrchecker",
    "SETTIME": f"{BUILD_VARS['TOP_BUILDDIR']}/dnssec-settime",
    "SIGNER": f"{BUILD_VARS['TOP_BUILDDIR']}/dnssec-signzone",
    "TSIGKEYGEN": f"{BUILD_VARS['TOP_BUILDDIR']}/tsig-keygen",
    "VERIFY": f"{BUILD_VARS['TOP_BUILDDIR']}/dnssec-verify",
    "WIRETEST": f"{BUILD_VARS['TOP_BUILDDIR']}/wire-test",
    "BIGKEY": f"{BUILD_VARS['TOP_BUILDDIR']}/bigkey",
    "GENCHECK": f"{BUILD_VARS['TOP_BUILDDIR']}/gencheck",
    "MAKEJOURNAL": f"{BUILD_VARS['TOP_BUILDDIR']}/makejournal",
    "PIPEQUERIES": f"{BUILD_VARS['TOP_BUILDDIR']}/pipequeries",
    "TMPDIR": os.getenv("TMPDIR", "/tmp"),
    "KRB5_CONFIG": "/dev/null",  # we don't want a KRB5_CONFIG setting breaking the tests
    "KRB5_KTNAME": "dns.keytab",  # use local keytab instead of default /etc/krb5.keytab
    "DELV": (
        f"{BUILD_VARS['TOP_BUILDDIR']}/delv"
        if not os.getenv("TSAN_OPTIONS", "")
        else ":"  # workaround for GL#4119
    ),
    "LC_ALL": "C",
    "ANS_LOG_LEVEL": "debug",
}
