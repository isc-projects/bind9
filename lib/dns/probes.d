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
	probe xfrin_axfr_finalize_begin(void *);
	probe xfrin_axfr_finalize_end(void *, int);
	probe xfrin_connected(void *, int);
	probe xfrin_done_callback_begin(void *, int);
	probe xfrin_done_callback_end(void *, int);
	probe xfrin_journal_destroy_begin(void *, int);
	probe xfrin_journal_destroy_end(void *, int);
	probe xfrin_read(void *, int);
	probe xfrin_recv_answer(void *, void *);
	probe xfrin_recv_done(void *, int);
	probe xfrin_recv_parsed(void *, int);
	probe xfrin_recv_question(void *, void *);
	probe xfrin_recv_send_request(void *);
	probe xfrin_recv_start(void *, int);
	probe xfrin_recv_try_axfr(void *, int);
	probe xfrin_sent(void *, int);
	probe xfrin_start(void *);
};
