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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <config.h>


#include <isc/app.h>
#include <isc/error.h>
#include <isc/mem.h>

#include <dns/confparser.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/journal.h>

#define ERRRET(result, function) \
	do { \
		if (result != DNS_R_SUCCESS) { \
			fprintf(stdout, "%s() returned %s\n", \
				function, dns_result_totext(result)); \
			return; \
		} \
	} while (0)

#define ERRCONT(result, function) \
		if (result != DNS_R_SUCCESS) { \
			fprintf(stdout, "%s() returned %s\n", \
				function, dns_result_totext(result)); \
			continue; \
		} else \
			(void)NULL
static void
print_rdataset(dns_name_t *name, dns_rdataset_t *rdataset) {
        isc_buffer_t text;
        char t[1000];
        isc_result_t result;
        isc_region_t r;

        isc_buffer_init(&text, t, sizeof t, ISC_BUFFERTYPE_TEXT);
        result = dns_rdataset_totext(rdataset, name, ISC_FALSE, ISC_FALSE,
				     &text);
        isc_buffer_used(&text, &r);
        if (result == DNS_R_SUCCESS)
                printf("%.*s", (int)r.length, (char *)r.base);
        else
                printf("%s\n", dns_result_totext(result));
}

static void
query(dns_view_t *view) {
	char buf[1024];
	dns_fixedname_t name;
	char *s;
	isc_buffer_t buffer;
	isc_result_t result;
	dns_rdataset_t rdataset;
	dns_rdataset_t sigset;
	fd_set rfdset;
	int reload = 0;


	dns_rdataset_init(&rdataset);
	dns_rdataset_init(&sigset);

	do {
		
		fprintf(stdout, "zone_test ");
		fflush(stdout);
		FD_ZERO(&rfdset);
		FD_SET(0, &rfdset);
		select(1, &rfdset, NULL, NULL, NULL);
		if (fgets(buf, sizeof buf, stdin) == NULL) {
			fprintf(stdout, "\n");
			break;
		}
		buf[sizeof(buf) - 1] = '\0';
		
		s = strchr(buf, '\n');
		if (s != NULL)
			*s = '\0';
		s = strchr(buf, '\r');
		if (s != NULL)
			*s = '\0';
		if (strlen(buf) == 0) {
			reload = 0;
			continue;
		}
		if (strcasecmp(buf, "exit") == 0 ||
		    strcasecmp(buf, "quit") == 0)
			break;
		if (strcasecmp(buf, "reload") == 0) {
			reload = 1;
			continue;
		}
		if (strcasecmp(buf, "journal") == 0) {
			dns_journal_print(view->mctx, "dv.isc.org.ixfr");
			reload = 0;
			continue;
		}

		dns_fixedname_init(&name);
		isc_buffer_init(&buffer, buf, strlen(buf), ISC_BUFFERTYPE_TEXT);
		isc_buffer_add(&buffer, strlen(buf));
		result = dns_name_fromtext(dns_fixedname_name(&name),
				  &buffer, dns_rootname, ISC_FALSE, NULL);
		ERRCONT(result, "dns_name_fromtext");
		
		if (reload) {
			dns_zone_t *zone = NULL;
			result = dns_zt_find(view->zonetable,
					     dns_fixedname_name(&name), NULL,
					     &zone);
			if (result != DNS_R_SUCCESS) {
				if (result == DNS_R_PARTIALMATCH)
					dns_zone_detach(&zone);
				reload = 0;
				continue;
			}
			result = dns_zone_load(zone);
			fprintf(stdout, "%s() returned %s\n", "dns_zone_reload",
				dns_result_totext(result));
			reload = 0;
			dns_zone_detach(&zone);
		} else {
			result = dns_view_simplefind(view,
				       dns_fixedname_name(&name),
				       dns_rdatatype_a, 0, 0,
				       ISC_FALSE, &rdataset, &sigset);
			fprintf(stdout, "%s() returned %s\n",
				"dns_view_simplefind",
				dns_result_totext(result));
			switch (result) {
			case DNS_R_SUCCESS:
				print_rdataset(dns_fixedname_name(&name), 
					       &rdataset);
				break;
			default:
				continue;
			}
			dns_rdataset_disassociate(&rdataset);
		}
	} while (1);
	dns_rdataset_invalidate(&rdataset);
}

int
main(int argc, char **argv) {
	char *conf = "named.conf";
	isc_mem_t *mctx = NULL;
	dns_c_ctx_t *configctx = NULL;
	dns_view_t *view1 = NULL;
	dns_view_t *view2 = NULL;
	dns_view_t *view = NULL;
	dns_c_cbks_t cbks;
	int quiet = 0, stats = 0;
	isc_result_t result;
	int c;
	char *dir;
	dns_zone_callbackarg_t cba;

	while ((c = getopt(argc, argv, "c:qs")) != EOF) {
		switch (c) {
		case 'c':
			conf = optarg;
			break;
		case 'q':
			quiet = 1;
			break;
		case 's':
			stats = 1;
			break;
		default:
			break;
		}
	}

        RUNTIME_CHECK(isc_app_start() == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);
#if 0
	RUNTIME_CHECK(isc_taskmgr_create(mctx, 2, 0, &manager) ==
					      ISC_R_SUCCESS);
#endif

/*
	RUNTIME_CHECK(dns_view_create(mctx, dns_rdataclass_in,
				      "default/IN", &view1) == DNS_R_SUCCESS);
	RUNTIME_CHECK(dns_view_create(mctx, dns_rdataclass_in,
				      "default/IN", &view2) == DNS_R_SUCCESS);
 */

	cba.mctx = mctx;
	ISC_LIST_INIT(cba.oldviews);
	ISC_LIST_INIT(cba.newviews);

	cbks.zonecbk = dns_zone_callback;
	cbks.zonecbkuap = &cba;
	cbks.optscbk = NULL;
	cbks.optscbkuap = NULL;

	result = dns_c_parse_namedconf(NULL, conf, mctx, &configctx, &cbks);
	fprintf(stdout, "%s() returned %s\n", "dns_c_parse_namedconf",
		dns_result_totext(result));
	if (configctx != NULL)
		dns_c_ctx_delete(NULL, &configctx);

	view = ISC_LIST_HEAD(cba.newviews);

	while (view != NULL) {
		dns_zt_print(view->zonetable);
		view = ISC_LIST_NEXT(view, link);
	}

	/* mv new ->old */
	cba.oldviews = cba.newviews;
	ISC_LIST_INIT(cba.newviews);

	/*
	view = ISC_LIST_HEAD(cba.newviews);
	while (view != NULL) {
		dns_view_t *next;
		next = ISC_LIST_NEXT(view, link);
		ISC_LIST_UNLINK(cba.newviews, view, link);
		ISC_LIST_APPEND(cba.oldviews, view, link);
		view = next;
	}
	*/

	result = dns_c_parse_namedconf(NULL, conf, mctx, &configctx, &cbks);
	fprintf(stdout, "%s() returned %s\n", "dns_c_parse_namedconf",
		dns_result_totext(result));
	if (result == DNS_R_SUCCESS) {
		result = dns_c_ctx_getdirectory(NULL, configctx, &dir);
		if (result == DNS_R_SUCCESS)
			chdir(dir);
		view = ISC_LIST_HEAD(cba.newviews);
		while (view != NULL) {
			dns_zt_print(view->zonetable);
			dns_zt_load(view->zonetable);
			dns_view_freeze(view);
			view = ISC_LIST_NEXT(view, link);
		}
		view = ISC_LIST_HEAD(cba.newviews);
		query(view);
	} else {
		view = ISC_LIST_HEAD(cba.oldviews);
		while (view != NULL) {
			dns_view_t *next;
			next = ISC_LIST_NEXT(view, link);
			ISC_LIST_UNLINK(cba.oldviews, view, link);
			dns_view_detach(&view);
		}
	}

	/* cleanup */
	view = ISC_LIST_HEAD(cba.oldviews);
	while (view != NULL) {
		dns_view_t *next;
		next = ISC_LIST_NEXT(view, link);
		ISC_LIST_UNLINK(cba.oldviews, view, link);
		dns_view_detach(&view);
		view = next;
	}

	view = ISC_LIST_HEAD(cba.newviews);
	while (view != NULL) {
		dns_view_t *next;
		next = ISC_LIST_NEXT(view, link);
		ISC_LIST_UNLINK(cba.newviews, view, link);
		dns_view_detach(&view);
		view = next;
	}

	if (configctx != NULL)
		dns_c_ctx_delete(NULL, &configctx);
	if (view2 != NULL)
		dns_view_detach(&view2);
	if (view1 != NULL)
		dns_view_detach(&view1);

	if (!quiet && stats)
		isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	exit(0);
}
