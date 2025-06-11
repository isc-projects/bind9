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

if fuzz_opt == 'none'
    subdir_done()
endif

fuzz_binaries += {
    'fuzz_dns_master_load': files('dns_master_load.c', 'main.c'),
    'fuzz_dns_message_checksig': files('dns_message_checksig.c', 'main.c'),
    'fuzz_dns_message_parse': files('dns_message_parse.c', 'main.c'),
    'fuzz_dns_name_fromtext_target': files('dns_name_fromtext_target.c', 'main.c'),
    'fuzz_dns_name_fromwire': files('dns_name_fromwire.c', 'main.c', 'old.c'),
    'fuzz_dns_qp': files('dns_qp.c', 'main.c'),
    'fuzz_dns_qpkey_name': files('dns_qpkey_name.c', 'main.c'),
    'fuzz_dns_rdata_fromtext': files('dns_rdata_fromtext.c', 'main.c'),
    'fuzz_dns_rdata_fromwire_text': files('dns_rdata_fromwire_text.c', 'main.c'),
    'fuzz_isc_lex_getmastertoken': files('isc_lex_getmastertoken.c', 'main.c'),
    'fuzz_isc_lex_gettoken': files('isc_lex_gettoken.c', 'main.c'),
}
