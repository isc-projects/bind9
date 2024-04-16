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

manrst_srcset.add(when: 'HAVE_DNSTAP', if_true: files('dnstap-read.rst'))
manrst_srcset.add(when: 'HAVE_LMDB', if_true: files('named-nzd2nzf.rst'))

manrst_srcset.add(
    files('conf.py'),

    files(
        'arpaname.rst',
        'ddns-confgen.rst',
        'delv.rst',
        'dig.rst',
        'dnssec-cds.rst',
        'dnssec-dsfromkey.rst',
        'dnssec-importkey.rst',
        'dnssec-keyfromlabel.rst',
        'dnssec-keygen.rst',
        'dnssec-ksr.rst',
        'dnssec-revoke.rst',
        'dnssec-settime.rst',
        'dnssec-signzone.rst',
        'dnssec-verify.rst',
        'filter-a.rst',
        'filter-aaaa.rst',
        'host.rst',
        'mdig.rst',
        'named-checkconf.rst',
        'named-checkzone.rst',
        'named-compilezone.rst',
        'named-journalprint.rst',
        'named-rrchecker.rst',
        'named.rst',
        'nsec3hash.rst',
        'nslookup.rst',
        'nsupdate.rst',
        'rndc-confgen.rst',
        'rndc.rst',
        'tsig-keygen.rst',
    ),
)

if fs.is_file('arpaname.1.in')
    man_srcset.add(when: 'HAVE_DNSTAP', if_true: files('dnstap-read.1.in'))
    man_srcset.add(when: 'HAVE_LMDB', if_true: files('named-nzd2nzf.1.in'))

    man_srcset.add(
        files(
            'arpaname.1.in',
            'ddns-confgen.8.in',
            'delv.1.in',
            'dig.1.in',
            'dnssec-cds.1.in',
            'dnssec-dsfromkey.1.in',
            'dnssec-importkey.1.in',
            'dnssec-keyfromlabel.1.in',
            'dnssec-keygen.1.in',
            'dnssec-ksr.1.in',
            'dnssec-revoke.1.in',
            'dnssec-settime.1.in',
            'dnssec-signzone.1.in',
            'dnssec-verify.1.in',
            'filter-a.8.in',
            'filter-aaaa.8.in',
            'host.1.in',
            'mdig.1.in',
            'named-checkconf.1.in',
            'named-checkzone.1.in',
            'named-compilezone.1.in',
            'named-journalprint.1.in',
            'named-rrchecker.1.in',
            'named.8.in',
            'named.conf.5.in',
            'nsec3hash.1.in',
            'nslookup.1.in',
            'nsupdate.1.in',
            'rndc-confgen.8.in',
            'rndc.8.in',
            'rndc.conf.5.in',
            'tsig-keygen.8.in',
        ),
    )
endif
