/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

provider libdns {
	probe delegdb_cleanup_done(void *, int);
	probe delegdb_cleanup_start(void *, int);
	probe delegdb_create(void *);
	probe delegdb_delete(void *, char *, int, int);
	probe delegdb_evict(void *, void *, char *);
	probe delegdb_insert_done(void *, char *, int);
	probe delegdb_insert_start(void *, char *);
	probe delegdb_lookup_done(void *, char *, int);
	probe delegdb_lookup_start(void *, char *);
	probe delegdb_reuse(void *);
	probe delegdb_shutdown(void *);
	probe xfrin_axfr_finalize_begin(void *, char *);
	probe xfrin_axfr_finalize_end(void *, char *, int);
	probe xfrin_connected(void *, char *, int);
	probe xfrin_done_callback_begin(void *, char *, int);
	probe xfrin_done_callback_end(void *, char *, int);
	probe xfrin_read(void *, char *, int);
	probe xfrin_recv_answer(void *, char *, void *);
	probe xfrin_recv_done(void *, char *, int);
	probe xfrin_recv_parsed(void *, char *, int);
	probe xfrin_recv_question(void *, char *, void *);
	probe xfrin_recv_send_request(void *, char *);
	probe xfrin_recv_start(void *, char *, int);
	probe xfrin_recv_try_axfr(void *, char *, int);
	probe xfrin_sent(void *, char *, int);
	probe xfrin_start(void *, char *);
	probe resolver_query(void *, char *, int);
};
