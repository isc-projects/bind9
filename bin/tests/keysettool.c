/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/types.h>
#include <isc/assertions.h>
#include <isc/commandline.h>
#include <isc/boolean.h>
#include <isc/buffer.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/stdtime.h>
#include <isc/list.h>

#include <dns/types.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/dnssec.h>
#include <dns/keyvalues.h>
#include <dns/secalg.h>
#include <dns/nxt.h>
#include <dns/time.h>
#include <dns/log.h>

#include <dst/dst.h>

#define BUFSIZE 2048

typedef struct keynode keynode_t;
struct keynode {
	dst_key_t *key;
	ISC_LINK(keynode_t) link;
};
typedef ISC_LIST(keynode_t) keylist_t;

static isc_stdtime_t starttime = 0, endtime = 0, now;
static int ttl = -1;
static int verbose;

static isc_mem_t *mctx = NULL;

static keylist_t keylist;
static inline void
fatal(char *message) {
	fprintf(stderr, "%s\n", message);
	exit(1);
}

static inline void
check_result(isc_result_t result, char *message) {
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "%s: %s\n", message,
			isc_result_totext(result));
		exit(1);
	}
}

static isc_stdtime_t
strtotime(char *str, isc_int64_t now, isc_int64_t base) {
	isc_int64_t val, offset;
	isc_result_t result;
	char *endp = "";

	if (str[0] == '+') {
		offset = strtol(str + 1, &endp, 0);
		val = base + offset;
	}
	else if (strncmp(str, "now+", 4) == 0) {
		offset = strtol(str + 4, &endp, 0);
		val = now + offset;
	}
	else {
		result = dns_time64_fromtext(str, &val);
		check_result(result, "dns_time64_fromtext()");
	}
	if (*endp != '\0')
		check_result(ISC_R_FAILURE, "strtol()");

	return ((isc_stdtime_t) val);
}

static void
usage() {
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\tkeysettool [options] domain keyfiles\n");

	fprintf(stderr, "\n");

	fprintf(stderr, "Options: (default value in parenthesis) \n");
	fprintf(stderr, "\t-s YYYYMMDDHHMMSS|+offset:\n");
	fprintf(stderr, "\t\tSIG start time - absolute|offset (now)\n");
	fprintf(stderr, "\t-e YYYYMMDDHHMMSS|+offset|\"now\"+offset]:\n");
	fprintf(stderr, "\t\tSIG end time  - absolute|from start|from now (now + 30 days)\n");
	fprintf(stderr, "\t-t ttl\n");
	fprintf(stderr, "\t-v level:\n");
	fprintf(stderr, "\t\tverbose level (0)\n");

	fprintf(stderr, "\n");

	fprintf(stderr, "domain:\n");
	fprintf(stderr, "\tdomain name associated with the keys\n");
	fprintf(stderr, "Keyfiles:\n");
	fprintf(stderr, "\tid/alg:\t\t");
	fprintf(stderr, "key matching keyid, algorithm, and domain\n");
	exit(0);
}

int
main(int argc, char *argv[]) {
	int i, ch;
	char *startstr = NULL, *endstr = NULL;
	char tdomain[1025];
	dns_fixedname_t fdomain;
	dns_name_t *domain;
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
	isc_logconfig_t *logconfig;
	keynode_t *keynode;

	dns_result_register();

	result = isc_mem_create(0, 0, &mctx);
	check_result(result, "isc_mem_create()");

	while ((ch = isc_commandline_parse(argc, argv, "s:e:t:v:")) != -1)
	{
		switch (ch) {
		case 's':
			startstr = isc_mem_strdup(mctx,
						  isc_commandline_argument);
			if (startstr == NULL)
				check_result(ISC_R_FAILURE, "isc_mem_strdup()");
			break;

		case 'e':
			endstr = isc_mem_strdup(mctx,
						isc_commandline_argument);
			if (endstr == NULL)
				check_result(ISC_R_FAILURE, "isc_mem_strdup()");
			break;

		case 't':
			endp = NULL;
			ttl = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0')
				check_result(ISC_R_FAILURE, "strtol()");
			break;

		case 'v':
			endp = NULL;
			verbose = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0')
				check_result(ISC_R_FAILURE, "strtol()");
			break;

		default:
			usage();

		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc < 2)
		usage();

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
		fprintf(stderr, "TTL not specified, assuming 3600\n");
	}

	if (verbose > 0) {
		RUNTIME_CHECK(isc_log_create(mctx, &log, &logconfig)
			      == ISC_R_SUCCESS);
		dns_log_init(log);
		RUNTIME_CHECK(isc_log_usechannel(logconfig, "default_stderr",
						 NULL, NULL) == ISC_R_SUCCESS);
	}

	dns_fixedname_init(&fdomain);
	domain = dns_fixedname_name(&fdomain);
	isc_buffer_init(&b, argv[0], strlen(argv[0]), ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&b, strlen(argv[0]));
	result = dns_name_fromtext(domain, &b, dns_rootname, ISC_FALSE, NULL);
	check_result(result, "dns_name_fromtext()");
	isc_buffer_init(&b, tdomain, sizeof(tdomain) - 1, ISC_BUFFERTYPE_TEXT);
	result = dns_name_totext(domain, ISC_FALSE, &b);
	check_result(result, "dns_name_totext()");
	isc_buffer_used(&b, &r);
	tdomain[r.length] = 0;

	output = isc_mem_allocate(mctx, strlen(tdomain) + strlen("keyset") + 1);
	if (output == NULL)
		check_result(ISC_R_FAILURE, "isc_mem_allocate()");
	strcpy(output, tdomain);
	strcat(output, "keyset");

	argc -= 1;
	argv += 1;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_key;
	rdatalist.covers = 0;
	rdatalist.ttl = ttl;

	ISC_LIST_INIT(keylist);

	for (i = 0; i < argc; i++) {
		int id, alg;
		char *idstr = NULL, *algstr = NULL;

		idstr = argv[i];
		algstr = strchr(idstr, '/');
		if (algstr == NULL)
			usage();
		*algstr++ = 0;

		endp = NULL;
		id = strtol(idstr, &endp, 10);
		if (*endp != '\0')
			check_result(ISC_R_FAILURE, "strtol");

		endp = NULL;
		alg = strtol(algstr, &endp, 10);
		if (*endp != '\0')
			check_result(ISC_R_FAILURE, "strtol");

		key = NULL;
		result = dst_key_fromfile(tdomain, id, alg, DST_TYPE_PUBLIC,
					  mctx, &key);
		check_result (result, "dst_key_fromfile");
		if (dst_key_iszonekey(key)) {
			dst_key_t *zonekey = NULL;
			result = dst_key_fromfile(tdomain, id, alg,
						  DST_TYPE_PRIVATE, mctx,
						  &zonekey);
			check_result(result, "dst_key_fromfile()");
			keynode = isc_mem_get(mctx, sizeof (keynode_t));
			if (keynode == NULL)
				check_result(ISC_R_NOMEMORY, "isc_mem_get()");
			keynode->key = zonekey;
			ISC_LINK_INIT(keynode, link);
			ISC_LIST_APPEND(keylist, keynode, link);
		}
		rdata = isc_mem_get(mctx, sizeof(dns_rdata_t));
		if (rdata == NULL)
			check_result(ISC_R_NOMEMORY, "isc_mem_get()");
		data = isc_mem_get(mctx, BUFSIZE);
		if (data == NULL)
			check_result(ISC_R_NOMEMORY, "isc_mem_get()");
		isc_buffer_init(&b, data, BUFSIZE, ISC_BUFFERTYPE_BINARY);
		result = dst_key_todns(key, &b);
		check_result(result, "dst_key_todns()");
		isc_buffer_used(&b, &r);
		dns_rdata_fromregion(rdata, dns_rdataclass_in,
				     dns_rdatatype_key, &r);
		ISC_LIST_APPEND(rdatalist.rdata, rdata, link);
		dst_key_free(key);
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
			"no private zone key found; not self-signing\n");
	for (keynode = ISC_LIST_HEAD(keylist);
	     keynode != NULL;
	     keynode = ISC_LIST_NEXT(keynode, link))
	{
		rdata = isc_mem_get(mctx, sizeof(dns_rdata_t));
		if (rdata == NULL)
			check_result(ISC_R_NOMEMORY, "isc_mem_get()");
		data = isc_mem_get(mctx, BUFSIZE);
		if (data == NULL)
			check_result(ISC_R_NOMEMORY, "isc_mem_get()");
		isc_buffer_init(&b, data, BUFSIZE, ISC_BUFFERTYPE_BINARY);
		result = dns_dnssec_sign(domain, &rdataset, keynode->key,
					 &starttime, &endtime, mctx, &b, rdata);
		check_result(result, "dst_key_todns()");
		ISC_LIST_APPEND(sigrdatalist.rdata, rdata, link);
		dns_rdataset_init(&sigrdataset);
		result = dns_rdatalist_tordataset(&sigrdatalist, &sigrdataset);
		check_result(result, "dns_rdatalist_tordataset()");
	}

	db = NULL;
	result = dns_db_create(mctx, "rbt", domain, ISC_FALSE,
			       dns_rdataclass_in, 0, NULL, &db);
	check_result(result, "dns_db_create()");

	version = NULL;
	dns_db_newversion(db, &version);

	node = NULL;
	result = dns_db_findnode(db, domain, ISC_TRUE, &node);
	check_result(result, "dns_db_findnode()");

	dns_db_addrdataset(db, node, version, 0, &rdataset, 0, NULL);
	if (!ISC_LIST_EMPTY(keylist))
		dns_db_addrdataset(db, node, version, 0, &sigrdataset, 0, NULL);

	dns_db_detachnode(db, &node);
	dns_db_closeversion(db, &version, ISC_TRUE);
	result = dns_db_dump(db, version, output);
	check_result(result, "dns_db_dump()");

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
		dst_key_free(keynode->key);
		isc_mem_put(mctx, keynode, sizeof(keynode_t));
	}

	if (log != NULL)
		isc_log_destroy(&log);

	isc_mem_free(mctx, output);
	isc_mem_destroy(&mctx);
	return (0);
}
