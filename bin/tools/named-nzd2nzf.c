/*
 * Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"

#ifndef HAVE_LMDB
#error This program requires the LMDBlibrary.
#endif

#include <stdio.h>
#include <stdlib.h>
#include <lmdb.h>

int
main (int argc, char *argv[]) {
	int status;
	const char *path;
	MDB_env *env = NULL;
	MDB_txn *txn = NULL;
	MDB_cursor *cursor = NULL;
	MDB_dbi dbi;
	MDB_val key, data;

	if (argc != 2) {
		fprintf(stderr, "Usage: named-nzd2nzf <nzd-path>\n");
		exit(1);
	}

	path = argv[1];

	status = mdb_env_create(&env);
	if (status != 0) {
		fprintf(stderr, "named-nzd2nzf: mdb_env_create: %s",
			mdb_strerror(status));
		exit(1);
	}

	status = mdb_env_open(env, path,
			      MDB_RDONLY|MDB_NOTLS|MDB_NOSUBDIR, 0600);
	if (status != 0) {
		fprintf(stderr, "named-nzd2nzf: mdb_env_open: %s",
			mdb_strerror(status));
		exit(1);
	}

	status = mdb_txn_begin(env, 0, MDB_RDONLY, &txn);
	if (status != 0) {
		fprintf(stderr, "named-nzd2nzf: mdb_txn_begin: %s",
			mdb_strerror(status));
		exit(1);
	}

	status = mdb_dbi_open(txn, NULL, 0, &dbi);
	if (status != 0) {
		fprintf(stderr, "named-nzd2nzf: mdb_dbi_open: %s",
			mdb_strerror(status));
		exit(1);
	}

	status = mdb_cursor_open(txn, dbi, &cursor);
	if (status != 0) {
		fprintf(stderr, "named-nzd2nzf: mdb_cursor_open: %s",
			mdb_strerror(status));
		exit(1);
	}

	while (mdb_cursor_get(cursor, &key, &data, MDB_NEXT) == 0) {
		if (key.mv_data == NULL || key.mv_size == 0 ||
		    data.mv_data == NULL || data.mv_size == 0)
		{
			fprintf(stderr,
				"named-nzd2nzf: empty column found in "
				"database '%s'", path);
			exit(1);
		}

		/* zone zonename { config; }; */
		printf("zone \"%.*s\" %.*s;\n",
		       (int) key.mv_size, (char *) key.mv_data, 
		       (int) data.mv_size, (char *) data.mv_data);
	}

	mdb_cursor_close(cursor);
	mdb_txn_abort(txn);
	mdb_env_close(env);
	exit(0);
}
