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

/*! \file */

#include <stdbool.h>
#include <stdlib.h>

#include <isc/attributes.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/hash.h>
#include <isc/lib.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/ds.h>
#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/lib.h>
#include <dns/master.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatatype.h>

#include <dst/dst.h>

#include "dnssectool.h"

static dns_rdataclass_t rdclass;
static dns_fixedname_t fixed;
static dns_name_t *name = NULL;
static isc_mem_t *mctx = NULL;
static bool setpub = false, setdel = false;
static bool setttl = false;
static isc_stdtime_t pub = 0, del = 0;
static dns_ttl_t ttl = 0;
static isc_stdtime_t syncadd = 0, syncdel = 0;
static bool setsyncadd = false;
static bool setsyncdel = false;

static isc_result_t
initname(char *setname) {
	isc_result_t result;
	isc_buffer_t buf;

	name = dns_fixedname_initname(&fixed);

	isc_buffer_init(&buf, setname, strlen(setname));
	isc_buffer_add(&buf, strlen(setname));
	result = dns_name_fromtext(name, &buf, dns_rootname, 0);
	return result;
}

static void
db_load_from_stream(dns_db_t *db, FILE *fp) {
	isc_result_t result;
	dns_rdatacallbacks_t callbacks;

	dns_rdatacallbacks_init(&callbacks);
	result = dns_db_beginload(db, &callbacks);
	if (result != ISC_R_SUCCESS) {
		fatal("dns_db_beginload failed: %s", isc_result_totext(result));
	}

	result = dns_master_loadstream(fp, name, name, rdclass, 0, &callbacks,
				       mctx);
	if (result != ISC_R_SUCCESS) {
		fatal("can't load from input: %s", isc_result_totext(result));
	}

	result = dns_db_endload(db, &callbacks);
	if (result != ISC_R_SUCCESS) {
		fatal("dns_db_endload failed: %s", isc_result_totext(result));
	}
}

static isc_result_t
loadset(const char *filename, dns_rdataset_t *rdataset) {
	isc_result_t result;
	dns_db_t *db = NULL;
	dns_dbnode_t *node = NULL;
	char setname[DNS_NAME_FORMATSIZE];

	dns_name_format(name, setname, sizeof(setname));

	result = dns_db_create(mctx, ZONEDB_DEFAULT, name, dns_dbtype_zone,
			       rdclass, 0, NULL, &db);
	if (result != ISC_R_SUCCESS) {
		fatal("can't create database");
	}

	if (strcmp(filename, "-") == 0) {
		db_load_from_stream(db, stdin);
		filename = "input";
	} else {
		result = dns_db_load(db, filename, dns_masterformat_text,
				     DNS_MASTER_NOTTL);
		if (result != ISC_R_SUCCESS && result != DNS_R_SEENINCLUDE) {
			fatal("can't load %s: %s", filename,
			      isc_result_totext(result));
		}
	}

	result = dns_db_findnode(db, name, false, &node);
	if (result != ISC_R_SUCCESS) {
		fatal("can't find %s node in %s", setname, filename);
	}

	result = dns_db_findrdataset(db, node, NULL, dns_rdatatype_dnskey, 0, 0,
				     rdataset, NULL);

	if (result == ISC_R_NOTFOUND) {
		fatal("no DNSKEY RR for %s in %s", setname, filename);
	} else if (result != ISC_R_SUCCESS) {
		fatal("dns_db_findrdataset");
	}

	if (node != NULL) {
		dns_db_detachnode(db, &node);
	}
	if (db != NULL) {
		dns_db_detach(&db);
	}
	return result;
}

static void
loadkey(char *filename, unsigned char *key_buf, unsigned int key_buf_size,
	dns_rdata_t *rdata) {
	isc_result_t result;
	dst_key_t *key = NULL;
	isc_buffer_t keyb;
	isc_region_t r;

	dns_rdata_init(rdata);

	isc_buffer_init(&keyb, key_buf, key_buf_size);

	result = dst_key_fromnamedfile(filename, NULL, DST_TYPE_PUBLIC, mctx,
				       &key);
	if (result != ISC_R_SUCCESS) {
		fatal("invalid keyfile name %s: %s", filename,
		      isc_result_totext(result));
	}

	if (verbose > 2) {
		char keystr[DST_KEY_FORMATSIZE];

		dst_key_format(key, keystr, sizeof(keystr));
		fprintf(stderr, "%s: %s\n", isc_commandline_progname, keystr);
	}

	result = dst_key_todns(key, &keyb);
	if (result != ISC_R_SUCCESS) {
		fatal("can't decode key");
	}

	isc_buffer_usedregion(&keyb, &r);
	dns_rdata_fromregion(rdata, dst_key_class(key), dns_rdatatype_dnskey,
			     &r);

	rdclass = dst_key_class(key);

	name = dns_fixedname_initname(&fixed);
	dns_name_copy(dst_key_name(key), name);

	dst_key_free(&key);
}

static void
emit(const char *dir, dns_rdata_t *rdata) {
	isc_result_t result;
	char keystr[DST_KEY_FORMATSIZE];
	char pubname[1024];
	char priname[1024];
	isc_buffer_t buf;
	dst_key_t *key = NULL, *tmp = NULL;

	isc_buffer_init(&buf, rdata->data, rdata->length);
	isc_buffer_add(&buf, rdata->length);
	result = dst_key_fromdns(name, rdclass, &buf, mctx, &key);
	if (result != ISC_R_SUCCESS) {
		fatal("dst_key_fromdns: %s", isc_result_totext(result));
	}

	isc_buffer_init(&buf, pubname, sizeof(pubname));
	result = dst_key_buildfilename(key, DST_TYPE_PUBLIC, dir, &buf);
	if (result != ISC_R_SUCCESS) {
		fatal("Failed to build public key filename: %s",
		      isc_result_totext(result));
	}
	isc_buffer_init(&buf, priname, sizeof(priname));
	result = dst_key_buildfilename(key, DST_TYPE_PRIVATE, dir, &buf);
	if (result != ISC_R_SUCCESS) {
		fatal("Failed to build private key filename: %s",
		      isc_result_totext(result));
	}

	result = dst_key_fromfile(
		dst_key_name(key), dst_key_id(key), dst_key_alg(key),
		DST_TYPE_PUBLIC | DST_TYPE_PRIVATE, dir, mctx, &tmp);
	if (result == ISC_R_SUCCESS) {
		if (dst_key_isprivate(tmp) && !dst_key_isexternal(tmp)) {
			fatal("Private key already exists in %s", priname);
		}
		dst_key_free(&tmp);
	}

	dst_key_setexternal(key, true);
	if (setpub) {
		dst_key_settime(key, DST_TIME_PUBLISH, pub);
	}
	if (setdel) {
		dst_key_settime(key, DST_TIME_DELETE, del);
	}
	if (setsyncadd) {
		dst_key_settime(key, DST_TIME_SYNCPUBLISH, syncadd);
	}
	if (setsyncdel) {
		dst_key_settime(key, DST_TIME_SYNCDELETE, syncdel);
	}

	if (setttl) {
		dst_key_setttl(key, ttl);
	}

	result = dst_key_tofile(key, DST_TYPE_PUBLIC | DST_TYPE_PRIVATE, dir);
	if (result != ISC_R_SUCCESS) {
		dst_key_format(key, keystr, sizeof(keystr));
		fatal("Failed to write key %s: %s", keystr,
		      isc_result_totext(result));
	}
	printf("%s\n", pubname);

	isc_buffer_clear(&buf);
	result = dst_key_buildfilename(key, DST_TYPE_PRIVATE, dir, &buf);
	if (result != ISC_R_SUCCESS) {
		fatal("Failed to build private key filename: %s",
		      isc_result_totext(result));
	}
	printf("%s\n", priname);
	dst_key_free(&key);
}

ISC_NORETURN static void
usage(void);

static void
usage(void) {
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "    %s options [-K dir] keyfile\n\n",
		isc_commandline_progname);
	fprintf(stderr, "    %s options -f file [keyname]\n\n",
		isc_commandline_progname);
	fprintf(stderr, "Version: %s\n", PACKAGE_VERSION);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -f file: read key from zone file\n");
	fprintf(stderr, "    -K <directory>: directory in which to store "
			"the key files\n");
	fprintf(stderr, "    -L ttl:             set default key TTL\n");
	fprintf(stderr, "    -v <verbose level>\n");
	fprintf(stderr, "    -V: print version information\n");
	fprintf(stderr, "    -h: print usage and exit\n");
	fprintf(stderr, "Timing options:\n");
	fprintf(stderr, "    -P date/[+-]offset/none: set/unset key "
			"publication date\n");
	fprintf(stderr, "    -P sync date/[+-]offset/none: set/unset "
			"CDS and CDNSKEY publication date\n");
	fprintf(stderr, "    -D date/[+-]offset/none: set/unset key "
			"deletion date\n");
	fprintf(stderr, "    -D sync date/[+-]offset/none: set/unset "
			"CDS and CDNSKEY deletion date\n");

	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv) {
	char *classname = NULL;
	char *filename = NULL, *dir = NULL, *namestr;
	char *endp = NULL;
	int ch;
	isc_result_t result;
	dns_rdataset_t rdataset;
	isc_stdtime_t now = isc_stdtime_now();

	if (argc == 1) {
		usage();
	}

	isc_commandline_init(argc, argv);

	isc_mem_create(isc_commandline_progname, &mctx);

	isc_commandline_errprint = false;

#define CMDLINE_FLAGS "D:f:hK:L:P:v:V"
	while ((ch = isc_commandline_parse(argc, argv, CMDLINE_FLAGS)) != -1) {
		switch (ch) {
		case 'D':
			/* -Dsync ? */
			if (isoptarg("sync", argv, usage)) {
				if (setsyncdel) {
					fatal("-D sync specified more than "
					      "once");
				}

				syncdel = strtotime(isc_commandline_argument,
						    now, now, &setsyncdel);
				break;
			}
			/* -Ddnskey ? */
			(void)isoptarg("dnskey", argv, usage);
			if (setdel) {
				fatal("-D specified more than once");
			}

			del = strtotime(isc_commandline_argument, now, now,
					&setdel);
			break;
		case 'K':
			dir = isc_commandline_argument;
			if (strlen(dir) == 0U) {
				fatal("directory must be non-empty string");
			}
			break;
		case 'L':
			ttl = strtottl(isc_commandline_argument);
			setttl = true;
			break;
		case 'P':
			/* -Psync ? */
			if (isoptarg("sync", argv, usage)) {
				if (setsyncadd) {
					fatal("-P sync specified more than "
					      "once");
				}

				syncadd = strtotime(isc_commandline_argument,
						    now, now, &setsyncadd);
				break;
			}
			/* -Pdnskey ? */
			(void)isoptarg("dnskey", argv, usage);
			if (setpub) {
				fatal("-P specified more than once");
			}

			pub = strtotime(isc_commandline_argument, now, now,
					&setpub);
			break;
		case 'f':
			filename = isc_commandline_argument;
			break;
		case 'v':
			verbose = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0') {
				fatal("-v must be followed by a number");
			}
			break;
		case '?':
			if (isc_commandline_option != '?') {
				fprintf(stderr, "%s: invalid argument -%c\n",
					isc_commandline_progname,
					isc_commandline_option);
			}
			FALLTHROUGH;
		case 'h':
			/* Does not return. */
			usage();

		case 'V':
			/* Does not return. */
			version(isc_commandline_progname);

		default:
			fprintf(stderr, "%s: unhandled option -%c\n",
				isc_commandline_progname,
				isc_commandline_option);
			exit(EXIT_FAILURE);
		}
	}

	rdclass = strtoclass(classname);

	if (argc < isc_commandline_index + 1 && filename == NULL) {
		fatal("the key file name was not specified");
	}
	if (argc > isc_commandline_index + 1) {
		fatal("extraneous arguments");
	}

	setup_logging();

	dns_rdataset_init(&rdataset);

	if (filename != NULL) {
		if (argc < isc_commandline_index + 1) {
			/* using filename as zone name */
			namestr = filename;
		} else {
			namestr = argv[isc_commandline_index];
		}

		result = initname(namestr);
		if (result != ISC_R_SUCCESS) {
			fatal("could not initialize name %s", namestr);
		}

		result = loadset(filename, &rdataset);

		if (result != ISC_R_SUCCESS) {
			fatal("could not load DNSKEY set: %s\n",
			      isc_result_totext(result));
		}

		DNS_RDATASET_FOREACH (&rdataset) {
			dns_rdata_t rdata = DNS_RDATA_INIT;
			dns_rdataset_current(&rdataset, &rdata);
			emit(dir, &rdata);
		}
	} else {
		unsigned char key_buf[DST_KEY_MAXSIZE];
		dns_rdata_t rdata = DNS_RDATA_INIT;

		loadkey(argv[isc_commandline_index], key_buf, DST_KEY_MAXSIZE,
			&rdata);

		emit(dir, &rdata);
	}

	if (dns_rdataset_isassociated(&rdataset)) {
		dns_rdataset_disassociate(&rdataset);
	}
	if (verbose > 10) {
		isc_mem_stats(mctx, stdout);
	}
	isc_mem_detach(&mctx);

	fflush(stdout);
	if (ferror(stdout)) {
		fprintf(stderr, "write error\n");
		return 1;
	} else {
		return 0;
	}
}
