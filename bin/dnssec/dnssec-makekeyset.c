/*
 * Portions Copyright (C) 2000  Internet Software Consortium.
 * Portions Copyright (C) 1995-2000 by Network Associates, Inc.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM AND
 * NETWORK ASSOCIATES DISCLAIM ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE CONSORTIUM OR NETWORK
 * ASSOCIATES BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: dnssec-makekeyset.c,v 1.28.2.1 2000/08/02 21:59:30 gson Exp $ */

#include <config.h>

#include <stdlib.h>

#include <isc/commandline.h>
#include <isc/entropy.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dnssec.h>
#include <dns/fixedname.h>
#include <dns/log.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/result.h>
#include <dns/secalg.h>
#include <dns/time.h>

#include <dst/dst.h>

#include "dnssectool.h"

#define BUFSIZE 2048

const char *program = "dnssec-makekeyset";
int verbose;

typedef struct keynode keynode_t;
struct keynode {
	dst_key_t *key;
	ISC_LINK(keynode_t) link;
};
typedef ISC_LIST(keynode_t) keylist_t;

static isc_stdtime_t starttime = 0, endtime = 0, now;
static int ttl = -1;

static isc_mem_t *mctx = NULL;
static isc_entropy_t *ectx = NULL;

static keylist_t keylist;

static isc_stdtime_t
strtotime(char *str, isc_int64_t now, isc_int64_t base) {
	isc_int64_t val, offset;
	isc_result_t result;
	char *endp;

	if (str[0] == '+') {
		offset = strtol(str + 1, &endp, 0);
		if (*endp != '\0')
			fatal("time value %s is invalid", str);
		val = base + offset;
	} else if (strncmp(str, "now+", 4) == 0) {
		offset = strtol(str + 4, &endp, 0);
		if (*endp != '\0')
			fatal("time value %s is invalid", str);
		val = now + offset;
	} else {
		result = dns_time64_fromtext(str, &val);
		if (result != ISC_R_SUCCESS)
			fatal("time %s must be numeric", str);
	}

	return ((isc_stdtime_t) val);
}

static void
usage(void) {
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t%s [options] keys\n", program);

	fprintf(stderr, "\n");

	fprintf(stderr, "Options: (default value in parenthesis) \n");
	fprintf(stderr, "\t-s YYYYMMDDHHMMSS|+offset:\n");
	fprintf(stderr, "\t\tSIG start time - absolute|offset (now)\n");
	fprintf(stderr, "\t-e YYYYMMDDHHMMSS|+offset|\"now\"+offset]:\n");
	fprintf(stderr, "\t\tSIG end time  - "
			     "absolute|from start|from now (now + 30 days)\n");
	fprintf(stderr, "\t-t ttl\n");
	fprintf(stderr, "\t-r randomdev:\n");
	fprintf(stderr, "\t\ta file containing random data\n");
	fprintf(stderr, "\t-v level:\n");
	fprintf(stderr, "\t\tverbose level (0)\n");

	fprintf(stderr, "\n");

	fprintf(stderr, "keys:\n");
	fprintf(stderr, "\tkeyfile (Kname+alg+id)\n");
	exit(0);
}

int
main(int argc, char *argv[]) {
	int i, ch;
	char *startstr = NULL, *endstr = NULL;
	char *randomfile = NULL;
	dns_fixedname_t fdomain;
	dns_name_t *domain = NULL;
	char *output = NULL;
	char *endp;
	unsigned char *data;
	dns_db_t *db;
	dns_dbnode_t *node;
	dns_dbversion_t *version;
	dst_key_t *key = NULL;
	dns_rdata_t *rdata;
	dns_rdatalist_t rdatalist, sigrdatalist;
	dns_rdataset_t rdataset, sigrdataset;
	isc_result_t result;
	isc_buffer_t b;
	isc_region_t r;
	isc_log_t *log = NULL;
	keynode_t *keynode;
	dns_name_t *savedname = NULL;

	result = isc_mem_create(0, 0, &mctx);
	if (result != ISC_R_SUCCESS)
		fatal("failed to create memory context: %s",
		      isc_result_totext(result));

	dns_result_register();

	while ((ch = isc_commandline_parse(argc, argv, "s:e:t:r:v:h")) != -1)
	{
		switch (ch) {
		case 's':
			startstr = isc_mem_strdup(mctx,
						  isc_commandline_argument);
			if (startstr == NULL)
				fatal("out of memory");
			break;

		case 'e':
			endstr = isc_mem_strdup(mctx,
						isc_commandline_argument);
			if (endstr == NULL)
				fatal("out of memory");
			break;

		case 't':
			endp = NULL;
			ttl = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0')
				fatal("TTL must be numeric");
			break;

		case 'r':
			randomfile = isc_mem_strdup(mctx,
						    isc_commandline_argument);
			if (randomfile == NULL)
				fatal("out of memory");
			break;

		case 'v':
			endp = NULL;
			verbose = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0')
				fatal("verbose level must be numeric");
			break;

		case 'h':
		default:
			usage();

		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc < 1)
		usage();

	setup_entropy(mctx, randomfile, &ectx);
	if (randomfile != NULL)
		isc_mem_free(mctx, randomfile);
	result = dst_lib_init(mctx, ectx,
			      ISC_ENTROPY_BLOCKING | ISC_ENTROPY_GOODONLY);
	if (result != ISC_R_SUCCESS)
		fatal("could not initialize dst");

	isc_stdtime_get(&now);

	if (startstr != NULL) {
		starttime = strtotime(startstr, now, now);
		isc_mem_free(mctx, startstr);
	}
	else
		starttime = now;

	if (endstr != NULL) {
		endtime = strtotime(endstr, now, starttime);
		isc_mem_free(mctx, endstr);
	}
	else
		endtime = starttime + (30 * 24 * 60 * 60);

	if (ttl == -1) {
		ttl = 3600;
		fprintf(stderr, "%s: TTL not specified, assuming 3600\n",
			program);
	}

	setup_logging(verbose, mctx, &log);

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_key;
	rdatalist.covers = 0;
	rdatalist.ttl = ttl;

	ISC_LIST_INIT(keylist);

	for (i = 0; i < argc; i++) {
		char namestr[1025];
		key = NULL;
		result = dst_key_fromnamedfile(argv[i], DST_TYPE_PUBLIC,
					       mctx, &key);
		if (result != ISC_R_SUCCESS)
			fatal("error loading key from %s", argv[i]);

		strncpy(namestr, nametostr(dst_key_name(key)),
			sizeof(namestr) - 1);
		namestr[sizeof(namestr) - 1] = 0;

		if (savedname == NULL) {
			savedname = isc_mem_get(mctx, sizeof(dns_name_t));
			if (savedname == NULL)
				fatal("out of memory");
			dns_name_init(savedname, NULL);
			result = dns_name_dup(dst_key_name(key), mctx,
					      savedname);
			if (result != ISC_R_SUCCESS)
				fatal("out of memory");
		} else {
			if (!dns_name_equal(savedname, dst_key_name(key)) != 0)
				fatal("all keys must have the same owner - %s "
				      "and %s do not match",
				      nametostr(savedname), namestr);
		}
		if (output == NULL) {
			output = isc_mem_allocate(mctx,
						  strlen(namestr) +
						  strlen("keyset") + 1);
			if (output == NULL)
				fatal("out of memory");
			strcpy(output, namestr);
			strcat(output, "keyset");
		}
		if (domain == NULL) {
			dns_fixedname_init(&fdomain);
			domain = dns_fixedname_name(&fdomain);
			isc_buffer_init(&b, namestr, strlen(namestr));
			isc_buffer_add(&b, strlen(namestr));
			result = dns_name_fromtext(domain, &b, dns_rootname,
						   ISC_FALSE, NULL);
			if (result != ISC_R_SUCCESS)
				fatal("%s is not a valid name: %s",
				      namestr, isc_result_totext(result));
		}
		if (dst_key_iszonekey(key)) {
			dst_key_t *zonekey = NULL;
			result = dst_key_fromnamedfile(argv[i],
						       DST_TYPE_PRIVATE,
						       mctx, &zonekey);
			if (result != ISC_R_SUCCESS)
				fatal("failed to read key %s: %s",
				      argv[i], isc_result_totext(result));
			keynode = isc_mem_get(mctx, sizeof (keynode_t));
			if (keynode == NULL)
				fatal("out of memory");
			keynode->key = zonekey;
			ISC_LINK_INIT(keynode, link);
			ISC_LIST_APPEND(keylist, keynode, link);
		}
		rdata = isc_mem_get(mctx, sizeof(dns_rdata_t));
		if (rdata == NULL)
			fatal("out of memory");
		data = isc_mem_get(mctx, BUFSIZE);
		if (data == NULL)
			fatal("out of memory");
		isc_buffer_init(&b, data, BUFSIZE);
		result = dst_key_todns(key, &b);
		if (result != ISC_R_SUCCESS)
			fatal("failed to convert key %s to a DNS KEY: %s",
			      argv[i], isc_result_totext(result));
		isc_buffer_usedregion(&b, &r);
		dns_rdata_fromregion(rdata, dns_rdataclass_in,
				     dns_rdatatype_key, &r);
		ISC_LIST_APPEND(rdatalist.rdata, rdata, link);
		dst_key_free(&key);
	}

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	check_result(result, "dns_rdatalist_tordataset()");

	dns_rdatalist_init(&sigrdatalist);
	sigrdatalist.rdclass = dns_rdataclass_in;
	sigrdatalist.type = dns_rdatatype_sig;
	sigrdatalist.covers = dns_rdatatype_key;
	sigrdatalist.ttl = ttl;

	if (ISC_LIST_EMPTY(keylist))
		fprintf(stderr,
			"%s: no private zone key found; not self-signing\n",
			program);
	for (keynode = ISC_LIST_HEAD(keylist);
	     keynode != NULL;
	     keynode = ISC_LIST_NEXT(keynode, link))
	{
		rdata = isc_mem_get(mctx, sizeof(dns_rdata_t));
		if (rdata == NULL)
			fatal("out of memory");
		data = isc_mem_get(mctx, BUFSIZE);
		if (data == NULL)
			fatal("out of memory");
		isc_buffer_init(&b, data, BUFSIZE);
		result = dns_dnssec_sign(domain, &rdataset, keynode->key,
					 &starttime, &endtime, mctx, &b,
					 rdata);
		isc_entropy_stopcallbacksources(ectx);
		if (result != ISC_R_SUCCESS)
			fatal("failed to sign keyset with key %s/%s/%d: %s",
			      nametostr(dst_key_name(keynode->key)),
			      algtostr(dst_key_alg(keynode->key)),
			      dst_key_id(keynode->key),
			      isc_result_totext(result));
		ISC_LIST_APPEND(sigrdatalist.rdata, rdata, link);
		dns_rdataset_init(&sigrdataset);
		result = dns_rdatalist_tordataset(&sigrdatalist, &sigrdataset);
		check_result(result, "dns_rdatalist_tordataset()");
	}

	db = NULL;
	result = dns_db_create(mctx, "rbt", domain, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	if (result != ISC_R_SUCCESS)
		fatal("failed to create a database for %s", nametostr(domain));

	version = NULL;
	dns_db_newversion(db, &version);

	node = NULL;
	result = dns_db_findnode(db, domain, ISC_TRUE, &node);
	check_result(result, "dns_db_findnode()");

	dns_db_addrdataset(db, node, version, 0, &rdataset, 0, NULL);
	if (!ISC_LIST_EMPTY(keylist))
		dns_db_addrdataset(db, node, version, 0, &sigrdataset, 0,
				   NULL);

	dns_db_detachnode(db, &node);
	dns_db_closeversion(db, &version, ISC_TRUE);
	result = dns_db_dump(db, version, output);
	if (result != ISC_R_SUCCESS)
		fatal("failed to write database for %s to %s",
		      nametostr(domain), output);

	dns_db_detach(&db);

	dns_rdataset_disassociate(&rdataset);
	while (!ISC_LIST_EMPTY(rdatalist.rdata)) {
		rdata = ISC_LIST_HEAD(rdatalist.rdata);
		ISC_LIST_UNLINK(rdatalist.rdata, rdata, link);
		isc_mem_put(mctx, rdata->data, BUFSIZE);
		isc_mem_put(mctx, rdata, sizeof *rdata);
	}
	while (!ISC_LIST_EMPTY(sigrdatalist.rdata)) {
		rdata = ISC_LIST_HEAD(sigrdatalist.rdata);
		ISC_LIST_UNLINK(sigrdatalist.rdata, rdata, link);
		isc_mem_put(mctx, rdata->data, BUFSIZE);
		isc_mem_put(mctx, rdata, sizeof *rdata);
	}

	while (!ISC_LIST_EMPTY(keylist)) {
		keynode = ISC_LIST_HEAD(keylist);
		ISC_LIST_UNLINK(keylist, keynode, link);
		dst_key_free(&keynode->key);
		isc_mem_put(mctx, keynode, sizeof(keynode_t));
	}

	if (savedname != NULL) {
		dns_name_free(savedname, mctx);
		isc_mem_put(mctx, savedname, sizeof(dns_name_t));
	}

	if (log != NULL)
		isc_log_destroy(&log);
	cleanup_entropy(&ectx);

	isc_mem_free(mctx, output);
	dst_lib_destroy();
	if (verbose > 10)
		isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);
	return (0);
}
