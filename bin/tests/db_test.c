/*
 * Copyright (C) 1999  Internet Software Consortium.
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

/*
 * Principal Author: Bob Halley
 */

#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>	/* XXX Naughty. */
#include <unistd.h>	/* XXX Naughty. */

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/boolean.h>
#include <isc/region.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/compress.h>
#include <dns/db.h>

static void
makename(isc_mem_t *mctx, char *text, dns_name_t *name, dns_name_t *origin) {
	char b[255];
	isc_buffer_t source, target;
	size_t len;
	isc_region_t r1, r2;
	dns_result_t result;

	if (origin == NULL)
		origin = dns_rootname;
	dns_name_init(name, NULL);
	len = strlen(text);
	isc_buffer_init(&source, text, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);
	isc_buffer_init(&target, b, sizeof b, ISC_BUFFERTYPE_BINARY);
	result = dns_name_fromtext(name, &source, origin, ISC_FALSE, &target);
	RUNTIME_CHECK(result == DNS_R_SUCCESS);
	dns_name_toregion(name, &r1);
	r2.base = isc_mem_get(mctx, r1.length);
	RUNTIME_CHECK(r2.base != NULL);
	r2.length = r1.length;
	memcpy(r2.base, r1.base, r1.length);
	dns_name_fromregion(name, &r2);
}

static void
freename(isc_mem_t *mctx, dns_name_t *name) {
	isc_region_t r;

	dns_name_toregion(name, &r);
	isc_mem_put(mctx, r.base, r.length);
	dns_name_invalidate(name);
}

static void
print_rdataset(dns_name_t *name, dns_rdataset_t *rdataset) {
	isc_buffer_t text;
	char t[1000];
	dns_result_t result;
	isc_region_t r;

	isc_buffer_init(&text, t, sizeof t, ISC_BUFFERTYPE_TEXT);
	result = dns_rdataset_totext(rdataset, name, ISC_FALSE, &text);
	isc_buffer_used(&text, &r);
	if (result == DNS_R_SUCCESS)
		printf("%.*s", (int)r.length, (char *)r.base);
	else
		printf("%s\n", dns_result_totext(result));
}

static void
print_rdatasets(dns_name_t *name, dns_rdatasetiter_t *rdsiter) {
	dns_result_t result;
	dns_rdataset_t rdataset;

	dns_rdataset_init(&rdataset);
	result = dns_rdatasetiter_first(rdsiter);
	while (result == DNS_R_SUCCESS) {
		dns_rdatasetiter_current(rdsiter, &rdataset);
		print_rdataset(name, &rdataset);
		dns_rdataset_disassociate(&rdataset);
		result = dns_rdatasetiter_next(rdsiter);
	}
	if (result != DNS_R_NOMORE)
		printf("%s\n", dns_result_totext(result));
}

int
main(int argc, char *argv[]) {
	isc_mem_t *mctx = NULL;
	dns_db_t *db;
	dns_dbnode_t *node;
	dns_result_t result;
	dns_name_t name, base, *origin;
	dns_offsets_t offsets;
	size_t len;
	isc_buffer_t source, target;
	char s[1000];
	char b[255];
	dns_rdataset_t rdataset;
	char basetext[1000];
	char dbtype[128];
	int ch;
	dns_rdatatype_t type = 1;
	isc_boolean_t printnode = ISC_FALSE;
	isc_boolean_t addmode = ISC_FALSE;
	isc_boolean_t delmode = ISC_FALSE;
	isc_boolean_t verbose = ISC_FALSE;
	isc_boolean_t done = ISC_FALSE;
	isc_boolean_t cache = ISC_FALSE;
	isc_boolean_t quiet = ISC_FALSE;
	isc_boolean_t time_lookups = ISC_FALSE;
	isc_boolean_t found_as;
	dns_dbversion_t *version = NULL;
	dns_dbversion_t *wversion = NULL;
	dns_dbversion_t *rversions[100];
	int i, rcount = 0, v;
	dns_rdatasetiter_t *rdsiter;
	char t1[256];
	char t2[256];
	isc_buffer_t tb1, tb2;
	isc_region_t r1, r2;
	dns_fixedname_t foundname;
	dns_name_t *fname;
	unsigned int options = 0;
	struct timeval start, finish;

	strcpy(basetext, "");
	strcpy(dbtype, "rbt");
	while ((ch = getopt(argc, argv, "z:d:t:gpqvcT")) != -1) {
		switch (ch) {
		case 'c':
			cache = ISC_TRUE;
			break;
		case 'd':
			strcpy(dbtype, optarg);
			break;
		case 'g':
			options |= (DNS_DBFIND_GLUEOK|DNS_DBFIND_VALIDATEGLUE);
			break;
		case 'q':
			quiet = ISC_TRUE;
			verbose = ISC_FALSE;
			break;
		case 'p':
			printnode = ISC_TRUE;
			break;
		case 't':
			type = atoi(optarg);
			break;
		case 'T':
			time_lookups = ISC_TRUE;
			break;
		case 'v':
			verbose = ISC_TRUE;
			break;
		case 'z':
			strcpy(basetext, optarg);
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		fprintf(stderr, "usage: db_test filename\n");
		exit(1);
	}

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	if (strcmp(basetext, "") == 0)
		strcpy(basetext, "vix.com.");
	makename(mctx, basetext, &base, NULL);

	db = NULL;
	result = dns_db_create(mctx, dbtype, &base, cache, dns_rdataclass_in,
			       0, NULL, &db);
	if (result != DNS_R_SUCCESS) {
		printf("dns_db_create(), DB type '%s', failed: %s\n",
		       dbtype, dns_result_totext(result));
		exit(1);
	}

	dns_fixedname_init(&foundname);
	fname = dns_fixedname_name(&foundname);

	origin = &base;
	printf("loading %s\n", argv[0]);
	result = dns_db_load(db, argv[0]);
	if (result != DNS_R_SUCCESS) {
		printf("couldn't load master file: %s\n",
		       dns_result_totext(result));
		exit(1);
	}
	printf("loaded\n");

	if (time_lookups) {
		/* Naughty */
		(void)gettimeofday(&start, NULL);
	}

	for (i = 0; i < 100; i++)
		rversions[i] = NULL;
	while (!done) {
		if (!quiet)
			printf("\n");
		if (gets(s) == NULL) {
			done = ISC_TRUE;
			continue;
		}
		if (verbose) {
			if (wversion != NULL)
				printf("future version (%p)\n", wversion);
			for (i = 0; i < rcount; i++)
				if (rversions[i] != NULL)
					printf("open version %d (%p)\n", i,
					       rversions[i]);
		}
		dns_name_init(&name, offsets);
		len = strlen(s);
		if (strcmp(s, "!R") == 0) {
			if (rcount == 100) {
				printf("too many open versions\n");
				continue;
			}
			dns_db_currentversion(db, &rversions[rcount]);
			printf("opened version %d\n", rcount);
			version = rversions[rcount];
			rcount++;
			continue;
		} else if (strcmp(s, "!W") == 0) {
			if (wversion != NULL) {
				printf("using existing future version\n");
				version = wversion;
				continue;
			}
			result = dns_db_newversion(db, &wversion);
			if (result != DNS_R_SUCCESS)
				printf("%s\n", dns_result_totext(result));
			else
				printf("newversion\n");
			version = wversion;
			continue;
		} else if (strcmp(s, "!C") == 0) {
			addmode = ISC_FALSE;
			delmode = ISC_FALSE;
			if (version == NULL)
				continue;
			if (version == wversion) {
				printf("closing future version\n");
				wversion = NULL;
			} else {
				for (i = 0; i < rcount; i++) {
					if (version == rversions[i]) {
						rversions[i] = NULL;
					  printf("closing open version %d\n",
						 i);
						break;
					}
				}
			}
			dns_db_closeversion(db, &version, ISC_TRUE);
			continue;
		} else if (strcmp(s, "!X") == 0) {
			addmode = ISC_FALSE;
			delmode = ISC_FALSE;
			if (version == NULL)
				continue;
			if (version == wversion) {
				printf("aborting future version\n");
				wversion = NULL;
			} else {
				for (i = 0; i < rcount; i++) {
					if (version == rversions[i]) {
						rversions[i] = NULL;
					  printf("closing open version %d\n",
						 i);
						break;
					}
				}
			}
			dns_db_closeversion(db, &version, ISC_FALSE);
			continue;
		} else if (strcmp(s, "!A") == 0) {
			delmode = ISC_FALSE;
			if (addmode)
				addmode = ISC_FALSE;
			else
				addmode = ISC_TRUE;
			printf("addmode = %s\n", addmode ? "TRUE" : "FALSE");
			continue;
		} else if (strcmp(s, "!D") == 0) {
			addmode = ISC_FALSE;
			if (delmode)
				delmode = ISC_FALSE;
			else
				delmode = ISC_TRUE;
			printf("delmode = %s\n", delmode ? "TRUE" : "FALSE");
			continue;
		} else if (strstr(s, "!V") == s) {
			v = atoi(&s[2]);
			if (v >= rcount) {
				printf("unknown open version %d\n", v);
				continue;
			} else if (rversions[v] == NULL) {
				printf("version %d is not open\n", v);
				continue;
			}
			printf("switching to open version %d\n", v);
			version = rversions[v];
			continue;
		} else if (strstr(s, "!T") == s) {
			type = (unsigned int)atoi(&s[2]);
			printf("now searching for type %u\n", type);
			continue;
		} else if (strcmp(s, "!G") == 0) {
			if ((options & DNS_DBFIND_GLUEOK) != 0)
				options &= ~DNS_DBFIND_GLUEOK;
			else
				options |= DNS_DBFIND_GLUEOK;
			printf("glue ok = %s\n",
			       ((options & DNS_DBFIND_GLUEOK) != 0) ?
			       "TRUE" : "FALSE");
			continue;
		} else if (strcmp(s, "!GV") == 0) {
			if ((options & DNS_DBFIND_VALIDATEGLUE) != 0)
				options &= ~DNS_DBFIND_VALIDATEGLUE;
			else
				options |= DNS_DBFIND_VALIDATEGLUE;
			printf("validate glue = %s\n",
			       ((options & DNS_DBFIND_VALIDATEGLUE) != 0) ?
			       "TRUE" : "FALSE");
			continue;
		}
		isc_buffer_init(&source, s, len, ISC_BUFFERTYPE_TEXT);
		isc_buffer_add(&source, len);
		isc_buffer_init(&target, b, sizeof b, ISC_BUFFERTYPE_BINARY);
		result = dns_name_fromtext(&name, &source, origin, ISC_FALSE,
					   &target);
		if (result != DNS_R_SUCCESS) {
			printf("bad name: %s\n", dns_result_totext(result));
			continue;
		}

		node = NULL;
		dns_rdataset_init(&rdataset);
		result = dns_db_find(db, &name, version, type, options, 0,
				     &node, fname, &rdataset);
		if (!quiet)
			printf("\n%s\n", dns_result_totext(result));

		found_as = ISC_FALSE;
		switch (result) {
		case DNS_R_SUCCESS:
		case DNS_R_GLUE:
		case DNS_R_CNAME:
		case DNS_R_ZONECUT:
			break;
		case DNS_R_DNAME:
		case DNS_R_DELEGATION:
			found_as = ISC_TRUE;
			break;
		case DNS_R_NXRDATASET:
			dns_db_detachnode(db, &node);
			continue;
		default:
			if (quiet)
				printf("%s\n", dns_result_totext(result));
			continue;
		}
		if (found_as && !quiet) {
			isc_buffer_init(&tb1, t1, sizeof t1,
					ISC_BUFFERTYPE_TEXT);
			isc_buffer_init(&tb2, t2, sizeof t2,
					ISC_BUFFERTYPE_TEXT);
			result = dns_name_totext(&name, ISC_FALSE, &tb1);
			if (result != DNS_R_SUCCESS) {
				printf("%s\n", dns_result_totext(result));
				continue;
			}
			result = dns_name_totext(fname, ISC_FALSE, &tb2);
			if (result != DNS_R_SUCCESS) {
				printf("%s\n", dns_result_totext(result));
				continue;
			}
			isc_buffer_used(&tb1, &r1);
			isc_buffer_used(&tb2, &r2);
			printf("found %.*s as %.*s\n",
			       (int)r1.length, r1.base,
			       (int)r2.length, r2.base);
		}

		if (printnode)
			dns_db_printnode(db, node, stdout);

		if (!found_as && type == dns_rdatatype_any) {
			rdsiter = NULL;
			result = dns_db_allrdatasets(db, node, version, 0,
						     &rdsiter);
			if (result == DNS_R_SUCCESS) {
				if (!quiet)
					print_rdatasets(fname, rdsiter);
				dns_rdatasetiter_destroy(&rdsiter);
			} else
				printf("%s\n", dns_result_totext(result));
		} else {
			if (!quiet)
				print_rdataset(fname, &rdataset);
			if (addmode && !found_as) {
				rdataset.ttl++;
				result = dns_db_addrdataset(db, node, version,
							    0, &rdataset);
				if (result != DNS_R_SUCCESS)
					printf("%s\n",
					       dns_result_totext(result));
				if (printnode)
					dns_db_printnode(db, node, stdout);
			} else if (delmode && !found_as) {
				result = dns_db_deleterdataset(db, node,
							       version, type);
				if (result != DNS_R_SUCCESS)
					printf("%s\n",
					       dns_result_totext(result));
				if (printnode)
					dns_db_printnode(db, node, stdout);
			}
			dns_rdataset_disassociate(&rdataset);
		}

		dns_db_detachnode(db, &node);
	}

	if (time_lookups) {
		struct timeval interval;

		/* Naughty */
		(void)gettimeofday(&finish, NULL);
		if (start.tv_usec > finish.tv_usec) {
			finish.tv_sec--;
			interval.tv_usec = 1000000 -
				start.tv_usec + finish.tv_usec;
		} else
			interval.tv_usec = finish.tv_usec - start.tv_usec;
		interval.tv_sec = finish.tv_sec - start.tv_sec;
		printf("elapsed time: %lu.%06lu seconds\n",
		       (unsigned long)interval.tv_sec,
		       (unsigned long)interval.tv_usec);
	}

	dns_db_detach(&db);
	freename(mctx, &base);

	if (!quiet)
		isc_mem_stats(mctx, stdout);

	return (0);
}
