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

#include <lmdb.h>
#include <sys/stat.h>
#include <unistd.h>

#include <isc/dir.h> /* Required on GNU/Hurd */
#include <isc/file.h>

#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/zoneproperties.h>

#include <isccfg/cfg.h>
#include <isccfg/namedconf.h>

#include <named/nzd.h>
#include <named/os.h>

void
nzd_setkey(MDB_val *key, dns_name_t *name, char *namebuf, size_t buflen) {
	dns_fixedname_t fixed;

	dns_fixedname_init(&fixed);
	dns_name_downcase(name, dns_fixedname_name(&fixed));
	dns_name_format(&fixed, namebuf, buflen);

	key->mv_data = namebuf;
	key->mv_size = strlen(namebuf);
}

static void
dumpzone(void *arg, const char *buf, int len) {
	ns_dzarg_t *dzarg = arg;
	isc_result_t result;

	REQUIRE(dzarg != NULL && ISC_MAGIC_VALID(dzarg, DZARG_MAGIC));

	result = isc_buffer_reserve(dzarg->text, (unsigned int)len);
	if (result == ISC_R_SUCCESS) {
		isc_buffer_putmem(dzarg->text, (const unsigned char *)buf, len);
	} else if (dzarg->result == ISC_R_SUCCESS) {
		dzarg->result = result;
	}
}

isc_result_t
nzd_save(MDB_txn **txnp, MDB_dbi dbi, dns_zone_t *zone,
	 const cfg_obj_t *zconfig) {
	isc_result_t result;
	int status;
	dns_view_t *view;
	bool commit = false;
	isc_buffer_t *text = NULL;
	char namebuf[1024];
	MDB_val key, data;
	ns_dzarg_t dzarg;

	view = dns_zone_getview(zone);

	nzd_setkey(&key, dns_zone_getorigin(zone), namebuf, sizeof(namebuf));

	if (zconfig == NULL) {
		/* We're deleting the zone from the database */
		status = mdb_del(*txnp, dbi, &key, NULL);
		if (status != MDB_SUCCESS && status != MDB_NOTFOUND) {
			isc_log_write(NAMED_LOGCATEGORY_GENERAL,
				      NAMED_LOGMODULE_SERVER, ISC_LOG_ERROR,
				      "Error deleting zone %s "
				      "from NZD database: %s",
				      namebuf, mdb_strerror(status));
			CLEANUP(ISC_R_FAILURE);
		} else if (status != MDB_NOTFOUND) {
			commit = true;
		}
	} else {
		/* We're creating or overwriting the zone */
		const cfg_obj_t *zoptions = cfg_tuple_get(zconfig, "options");

		isc_buffer_allocate(view->mctx, &text, 256);
		if (zoptions == NULL) {
			isc_log_write(NAMED_LOGCATEGORY_GENERAL,
				      NAMED_LOGMODULE_SERVER, ISC_LOG_ERROR,
				      "Unable to get options from config in "
				      "nzd_save()");
			CLEANUP(ISC_R_FAILURE);
		}

		dzarg.magic = DZARG_MAGIC;
		dzarg.text = text;
		dzarg.result = ISC_R_SUCCESS;
		cfg_printx(zoptions, CFG_PRINTER_ONELINE, dumpzone, &dzarg);
		if (dzarg.result != ISC_R_SUCCESS) {
			isc_log_write(NAMED_LOGCATEGORY_GENERAL,
				      NAMED_LOGMODULE_SERVER, ISC_LOG_ERROR,
				      "Error writing zone config to "
				      "buffer in nzd_save(): %s",
				      isc_result_totext(dzarg.result));
			CHECK(dzarg.result);
		}

		data.mv_data = isc_buffer_base(text);
		data.mv_size = isc_buffer_usedlength(text);

		status = mdb_put(*txnp, dbi, &key, &data, 0);
		if (status != MDB_SUCCESS) {
			isc_log_write(NAMED_LOGCATEGORY_GENERAL,
				      NAMED_LOGMODULE_SERVER, ISC_LOG_ERROR,
				      "Error inserting zone in "
				      "NZD database: %s",
				      mdb_strerror(status));
			CLEANUP(ISC_R_FAILURE);
		}

		commit = true;
	}

	result = ISC_R_SUCCESS;

cleanup:
	if (!commit || result != ISC_R_SUCCESS) {
		(void)mdb_txn_abort(*txnp);
	} else {
		status = mdb_txn_commit(*txnp);
		if (status != MDB_SUCCESS) {
			isc_log_write(NAMED_LOGCATEGORY_GENERAL,
				      NAMED_LOGMODULE_SERVER, ISC_LOG_ERROR,
				      "Error committing "
				      "NZD database: %s",
				      mdb_strerror(status));
			result = ISC_R_FAILURE;
		}
	}
	*txnp = NULL;

	if (text != NULL) {
		isc_buffer_free(&text);
	}

	return result;
}

/*
 * Check whether the new zone database for 'view' can be opened for writing.
 *
 * Caller must hold 'view->newzone.lock'.
 */
isc_result_t
nzd_writable(dns_view_t *view) {
	isc_result_t result = ISC_R_SUCCESS;
	int status;
	MDB_dbi dbi;
	MDB_txn *txn = NULL;

	REQUIRE(view != NULL);

	status = mdb_txn_begin(view->newzone.dbenv, 0, 0, &txn);
	if (status != MDB_SUCCESS) {
		isc_log_write(NAMED_LOGCATEGORY_GENERAL, NAMED_LOGMODULE_SERVER,
			      ISC_LOG_WARNING, "mdb_txn_begin: %s",
			      mdb_strerror(status));
		return ISC_R_FAILURE;
	}

	status = mdb_dbi_open(txn, NULL, 0, &dbi);
	if (status != MDB_SUCCESS) {
		isc_log_write(NAMED_LOGCATEGORY_GENERAL, NAMED_LOGMODULE_SERVER,
			      ISC_LOG_WARNING, "mdb_dbi_open: %s",
			      mdb_strerror(status));
		result = ISC_R_FAILURE;
	}

	mdb_txn_abort(txn);
	return result;
}

/*
 * Open the new zone database for 'view' and start a transaction for it.
 *
 * Caller must hold 'view->newzone.lock'.
 */
isc_result_t
nzd_open(dns_view_t *view, unsigned int flags, MDB_txn **txnp, MDB_dbi *dbi) {
	int status;
	MDB_txn *txn = NULL;

	REQUIRE(view != NULL);
	REQUIRE(txnp != NULL && *txnp == NULL);
	REQUIRE(dbi != NULL);

	status = mdb_txn_begin(view->newzone.dbenv, 0, flags, &txn);
	if (status != MDB_SUCCESS) {
		isc_log_write(NAMED_LOGCATEGORY_GENERAL, NAMED_LOGMODULE_SERVER,
			      ISC_LOG_WARNING, "mdb_txn_begin: %s",
			      mdb_strerror(status));
		goto cleanup;
	}

	status = mdb_dbi_open(txn, NULL, 0, dbi);
	if (status != MDB_SUCCESS) {
		isc_log_write(NAMED_LOGCATEGORY_GENERAL, NAMED_LOGMODULE_SERVER,
			      ISC_LOG_WARNING, "mdb_dbi_open: %s",
			      mdb_strerror(status));
		goto cleanup;
	}

	*txnp = txn;

cleanup:
	if (status != MDB_SUCCESS) {
		if (txn != NULL) {
			mdb_txn_abort(txn);
		}
		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}

/*
 * nzd_env_close() and nzd_env_reopen() are a kluge to address the
 * problem of an NZD file possibly being created before we drop
 * root privileges.
 */
void
nzd_env_close(dns_view_t *view) {
	const char *dbpath = NULL;
	char dbpath_copy[PATH_MAX];
	char lockpath[PATH_MAX];
	struct stat sb;
	int status, ret;

	if (view->newzone.dbenv == NULL) {
		return;
	}

	status = mdb_env_get_path(view->newzone.dbenv, &dbpath);
	INSIST(status == MDB_SUCCESS);
	snprintf(lockpath, sizeof(lockpath), "%s-lock", dbpath);
	strlcpy(dbpath_copy, dbpath, sizeof(dbpath_copy));
	mdb_env_close(view->newzone.dbenv);

	/*
	 * Database files must be owned by the eventual user, not by root.
	 * Use lstat()/S_ISREG/lchown() so a symlink at the path cannot
	 * redirect the chown to an unrelated file.
	 */
	if (lstat(dbpath_copy, &sb) == 0 && S_ISREG(sb.st_mode)) {
		ret = lchown(dbpath_copy, named_os_uid(), -1);
		UNUSED(ret);
	}

	/*
	 * Some platforms need the lockfile not to exist when we reopen the
	 * environment.
	 */
	(void)isc_file_remove(lockpath);

	view->newzone.dbenv = NULL;
}

isc_result_t
nzd_env_reopen(dns_view_t *view) {
	isc_result_t result;
	MDB_env *env = NULL;
	int status;

	if (view->newzone.db == NULL) {
		return ISC_R_SUCCESS;
	}

	nzd_env_close(view);

	status = mdb_env_create(&env);
	if (status != MDB_SUCCESS) {
		isc_log_write(DNS_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER,
			      ISC_LOG_ERROR, "mdb_env_create failed: %s",
			      mdb_strerror(status));
		CLEANUP(ISC_R_FAILURE);
	}

	if (view->newzone.mapsize != 0ULL) {
		status = mdb_env_set_mapsize(env, view->newzone.mapsize);
		if (status != MDB_SUCCESS) {
			isc_log_write(DNS_LOGCATEGORY_GENERAL,
				      ISC_LOGMODULE_OTHER, ISC_LOG_ERROR,
				      "mdb_env_set_mapsize failed: %s",
				      mdb_strerror(status));
			CLEANUP(ISC_R_FAILURE);
		}
	}

	status = mdb_env_open(env, view->newzone.db, DNS_LMDB_FLAGS, 0600);
	if (status != MDB_SUCCESS) {
		isc_log_write(DNS_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER,
			      ISC_LOG_ERROR, "mdb_env_open of '%s' failed: %s",
			      view->newzone.db, mdb_strerror(status));
		CLEANUP(ISC_R_FAILURE);
	}

	view->newzone.dbenv = env;
	env = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	if (env != NULL) {
		mdb_env_close(env);
	}
	return result;
}

/*
 * If 'commit' is true, commit the new zone database transaction pointed to by
 * 'txnp'; otherwise, abort that transaction.
 *
 * Caller must hold 'view->newzone.lock' for the view that the transaction
 * pointed to by 'txnp' was started for.
 */
isc_result_t
nzd_close(MDB_txn **txnp, bool commit) {
	isc_result_t result = ISC_R_SUCCESS;
	int status;

	REQUIRE(txnp != NULL);

	if (*txnp != NULL) {
		if (commit) {
			status = mdb_txn_commit(*txnp);
			if (status != MDB_SUCCESS) {
				result = ISC_R_FAILURE;
			}
		} else {
			mdb_txn_abort(*txnp);
		}
		*txnp = NULL;
	}

	return result;
}

/*
 * If there's an existing NZF file, load it and migrate its data
 * to the NZD.
 *
 * Caller must hold view->newzone.lock.
 */
isc_result_t
nzd_load_nzf(dns_view_t *view) {
	isc_result_t result;
	cfg_obj_t *nzf_config = NULL;
	int status;
	isc_buffer_t *text = NULL;
	bool commit = false;
	const cfg_obj_t *zonelist = NULL;
	char tempname[PATH_MAX];
	MDB_txn *txn = NULL;
	MDB_dbi dbi;
	MDB_val key, data;
	ns_dzarg_t dzarg;

	/*
	 * If NZF file doesn't exist, or NZD DB exists and already
	 * has data, return without attempting migration.
	 */
	if (!isc_file_exists(view->newzone.file)) {
		result = ISC_R_SUCCESS;
		goto cleanup;
	}

	isc_log_write(NAMED_LOGCATEGORY_GENERAL, NAMED_LOGMODULE_SERVER,
		      ISC_LOG_INFO,
		      "Migrating zones from NZF file '%s' to "
		      "NZD database '%s'",
		      view->newzone.file, view->newzone.db);
	/*
	 * Instead of blindly copying lines, we parse the NZF file using
	 * the configuration parser, because it validates it against the
	 * config type, giving us a guarantee that valid configuration
	 * will be written to DB.
	 */
	result = cfg_parse_file(view->newzone.file, &cfg_type_addzoneconf, 0,
				&nzf_config);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(NAMED_LOGCATEGORY_GENERAL, NAMED_LOGMODULE_SERVER,
			      ISC_LOG_ERROR, "Error parsing NZF file '%s': %s",
			      view->newzone.file, isc_result_totext(result));
		goto cleanup;
	}

	zonelist = NULL;
	CHECK(cfg_map_get(nzf_config, "zone", &zonelist));
	if (!cfg_obj_islist(zonelist)) {
		CLEANUP(ISC_R_FAILURE);
	}

	CHECK(nzd_open(view, 0, &txn, &dbi));

	isc_buffer_allocate(view->mctx, &text, 256);

	CFG_LIST_FOREACH(zonelist, element) {
		const cfg_obj_t *zconfig = cfg_listelt_value(element);
		const cfg_obj_t *zoptions;
		char zname[DNS_NAME_FORMATSIZE];
		dns_fixedname_t fname;
		dns_name_t *name = NULL;
		const char *origin = NULL;
		isc_buffer_t b;

		origin = cfg_obj_asstring(cfg_tuple_get(zconfig, "name"));
		if (origin == NULL) {
			CLEANUP(ISC_R_FAILURE);
		}

		/* Normalize zone name */
		isc_buffer_constinit(&b, origin, strlen(origin));
		isc_buffer_add(&b, strlen(origin));
		name = dns_fixedname_initname(&fname);
		CHECK(dns_name_fromtext(name, &b, dns_rootname,
					DNS_NAME_DOWNCASE));
		dns_name_format(name, zname, sizeof(zname));

		key.mv_data = zname;
		key.mv_size = strlen(zname);

		zoptions = cfg_tuple_get(zconfig, "options");
		if (zoptions == NULL) {
			CLEANUP(ISC_R_FAILURE);
		}

		isc_buffer_clear(text);
		dzarg.magic = DZARG_MAGIC;
		dzarg.text = text;
		dzarg.result = ISC_R_SUCCESS;
		cfg_printx(zoptions, CFG_PRINTER_ONELINE, dumpzone, &dzarg);
		if (dzarg.result != ISC_R_SUCCESS) {
			isc_log_write(NAMED_LOGCATEGORY_GENERAL,
				      NAMED_LOGMODULE_SERVER, ISC_LOG_ERROR,
				      "Error writing zone config to "
				      "buffer in load_nzf(): %s",
				      isc_result_totext(result));
			CHECK(dzarg.result);
		}

		data.mv_data = isc_buffer_base(text);
		data.mv_size = isc_buffer_usedlength(text);

		status = mdb_put(txn, dbi, &key, &data, MDB_NOOVERWRITE);
		if (status != MDB_SUCCESS) {
			isc_log_write(NAMED_LOGCATEGORY_GENERAL,
				      NAMED_LOGMODULE_SERVER, ISC_LOG_ERROR,
				      "Error inserting zone in "
				      "NZD database: %s",
				      mdb_strerror(status));
			CLEANUP(ISC_R_FAILURE);
		}

		commit = true;
	}

	result = ISC_R_SUCCESS;

	/*
	 * Leaving the NZF file in place is harmless as we won't use it
	 * if an NZD database is found for the view. But we rename NZF file
	 * to a backup name here.
	 */
	strlcpy(tempname, view->newzone.file, sizeof(tempname));
	if (strlen(tempname) < sizeof(tempname) - 1) {
		strlcat(tempname, "~", sizeof(tempname));
		isc_file_rename(view->newzone.file, tempname);
	}

cleanup:
	if (result != ISC_R_SUCCESS) {
		(void)nzd_close(&txn, false);
	} else {
		result = nzd_close(&txn, commit);
	}

	if (text != NULL) {
		isc_buffer_free(&text);
	}

	if (nzf_config != NULL) {
		cfg_obj_detach(&nzf_config);
	}

	return result;
}
