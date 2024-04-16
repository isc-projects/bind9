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

confgen_inc_p = include_directories('.', 'include')

rndc_confgen_src += files('keygen.c', 'os.c', 'rndc-confgen.c', 'util.c')
tsig_keygen_src += files('keygen.c', 'os.c', 'tsig-keygen.c', 'util.c')

manrst_srcset.add(
    files(
        'ddns-confgen.rst',
        'rndc-confgen.rst',
        'tsig-keygen.rst',
    ),
)
