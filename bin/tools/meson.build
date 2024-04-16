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

arpaname_src += files('arpaname.c')
dnstap_read_src += files('dnstap-read.c')
mdig_src += files('mdig.c')
named_journalprint_src += files('named-journalprint.c')
named_nzd2nzf_src += files('named-nzd2nzf.c')
named_rrchecker_src += files('named-rrchecker.c')
nsec3hash_src += files('nsec3hash.c')

manrst_srcset.add(when: 'HAVE_DNSTAP', if_true: files('dnstap-read.rst'))
manrst_srcset.add(when: 'HAVE_LMDB', if_true: files('named-nzd2nzf.rst'))
manrst_srcset.add(
    files(
        'arpaname.rst',
        'dnstap-read.rst',
        'mdig.rst',
        'named-journalprint.rst',
        'named-nzd2nzf.rst',
        'named-rrchecker.rst',
        'nsec3hash.rst',
    ),
)
