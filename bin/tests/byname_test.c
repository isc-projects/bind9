/*
 * Copyright (C) 2000  Internet Software Consortium.
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

/* XXXRTH */
#define ISC_MEM_DEBUG 1

#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/error.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/app.h>
#include <isc/mutex.h>
#include <isc/boolean.h>
#include <isc/net.h>
#include <isc/region.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>
#include <isc/util.h>
#include <isc/netaddr.h>
#include <isc/log.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/adb.h>
#include <dns/cache.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/resolver.h>
#include <dns/events.h>
#include <dns/dispatch.h>
#include <dns/byaddr.h>
#include <dns/view.h>
#include <dns/log.h>

static isc_mem_t *mctx = NULL;
static dns_view_t *view = NULL;
static dns_adbfind_t *find = NULL;
static isc_task_t *task = NULL;
static dns_fixedname_t name;
static dns_fixedname_t target;
static isc_log_t *lctx;
static unsigned int level = 0;

static void adb_callback(isc_task_t *task, isc_event_t *event);

static void
log_init(void) {
	isc_logdestination_t destination;
	unsigned int flags;

	/*
	 * Setup a logging context.
	 */
	RUNTIME_CHECK(isc_log_create(mctx, &lctx) == ISC_R_SUCCESS);
	RUNTIME_CHECK(dns_log_init(lctx) == ISC_R_SUCCESS);

	/*
	 * Create and install the default channel.
	 */
	destination.file.stream = stderr;
	destination.file.name = NULL;
	destination.file.versions = ISC_LOG_ROLLNEVER;
	destination.file.maximum_size = 0;
	flags = ISC_LOG_PRINTTIME;
	RUNTIME_CHECK(isc_log_createchannel(lctx, "_default",
					    ISC_LOG_TOFILEDESC,
					    ISC_LOG_DYNAMIC,
					    &destination, flags) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_log_usechannel(lctx, "_default", NULL, NULL) ==
		      ISC_R_SUCCESS);
	isc_log_setdebuglevel(lctx, level);
}

static void
print_addresses(dns_adbfind_t *find) {
	dns_adbaddrinfo_t *address;
	isc_result_t result;
	isc_buffer_t b;
	isc_region_t r;
	char text[1024];

	isc_buffer_init(&b, text, sizeof text, ISC_BUFFERTYPE_TEXT);

	for (address = ISC_LIST_HEAD(find->list);
	     address != NULL;
	     address = ISC_LIST_NEXT(address, publink)) {
		isc_buffer_clear(&b);
		result = isc_sockaddr_totext(address->sockaddr, &b);
		if (result == ISC_R_SUCCESS) {
			isc_buffer_used(&b, &r);
			printf("%.*s\n", (int)r.length, r.base);
		} else
			printf("isc_sockaddr_totext() failed: %s\n",
			       isc_result_totext(result));
	}
}

static void
print_name(dns_name_t *name) {
	isc_result_t result;
	isc_buffer_t b;
	isc_region_t r;
	char text[1024];

	isc_buffer_init(&b, text, sizeof text, ISC_BUFFERTYPE_TEXT);

	result = dns_name_totext(name, ISC_FALSE, &b);
	if (result == ISC_R_SUCCESS) {
		isc_buffer_used(&b, &r);
		printf("%.*s\n", (int)r.length, r.base);
	} else
		printf("dns_name_totext() failed: %s\n",
		       isc_result_totext(result));
}

static void
do_find(isc_boolean_t want_event) {
	isc_result_t result;
	isc_boolean_t done = ISC_FALSE;
	unsigned int options;

	options = DNS_ADBFIND_INET | DNS_ADBFIND_INET6;
	if (want_event)
		options |= DNS_ADBFIND_WANTEVENT | DNS_ADBFIND_EMPTYEVENT;
	dns_fixedname_init(&target);
	result = dns_adb_createfind(view->adb, task, adb_callback, NULL,
				    dns_fixedname_name(&name),
				    dns_rootname, options, 0,
				    dns_fixedname_name(&target),
				    &find);
	if (result == ISC_R_SUCCESS) {
		if (!ISC_LIST_EMPTY(find->list)) {
			/*
			 * We have at least some of the addresses for the
			 * name.
			 */
			INSIST((find->options & DNS_ADBFIND_WANTEVENT) == 0);
			print_addresses(find);
			done = ISC_TRUE;
		} else {
			/*
			 * We don't know any of the addresses for this
			 * name.
			 */
			if ((find->options & DNS_ADBFIND_WANTEVENT) == 0) {
				/*
				 * And ADB isn't going to send us any events
				 * either.  This query loses.
				 */
				done = ISC_TRUE;
			}
			/*
			 * If the DNS_ADBFIND_WANTEVENT flag was set, we'll
			 * get an event when something happens.
			 */
		}
	} else if (result == DNS_R_ALIAS) {
		print_name(dns_fixedname_name(&target));
		done = ISC_TRUE;
	} else {
		printf("dns_adb_createfind() returned %s\n",
		       isc_result_totext(result));
		done = ISC_TRUE;
	}

	if (done) {
		if (find != NULL)
			dns_adb_destroyfind(&find);
		isc_app_shutdown();
	}
}

static void
adb_callback(isc_task_t *etask, isc_event_t *event) {
	unsigned int type = event->type;

	REQUIRE(etask == task);

	isc_event_free(&event);
	dns_adb_destroyfind(&find);

	if (type == DNS_EVENT_ADBMOREADDRESSES)
		do_find(ISC_FALSE);
	else if (type == DNS_EVENT_ADBNOMOREADDRESSES) {
		printf("no more addresses\n");
		isc_app_shutdown();
	} else {
		printf("unexpected ADB event type %u\n", type);
		isc_app_shutdown();
	}
}

static void
run(isc_task_t *task, isc_event_t *event) {
	(void)task;
	do_find(ISC_TRUE);
	isc_event_free(&event);
}

int
main(int argc, char *argv[]) {
	isc_boolean_t verbose = ISC_FALSE;
	unsigned int workers = 2;
	isc_taskmgr_t *taskmgr;
	isc_timermgr_t *timermgr;
	int ch;
	isc_socketmgr_t *socketmgr;
	dns_cache_t *cache;
	isc_buffer_t b;

	RUNTIME_CHECK(isc_app_start() == ISC_R_SUCCESS);

	dns_result_register();

	mctx = NULL;
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	while ((ch = isc_commandline_parse(argc, argv, "d:vw:")) != -1) {
		switch (ch) {
		case 'd':
			level = (unsigned int)atoi(isc_commandline_argument);
			break;
		case 'v':
			verbose = ISC_TRUE;
			break;
		case 'w':
			workers = (unsigned int)atoi(isc_commandline_argument);
			break;
		}
	}

	log_init();

	if (verbose) {
		printf("%u workers\n", workers);
		printf("IPv4: %s\n", isc_result_totext(isc_net_probeipv4()));
		printf("IPv6: %s\n", isc_result_totext(isc_net_probeipv6()));
	}

	taskmgr = NULL;
	RUNTIME_CHECK(isc_taskmgr_create(mctx, workers, 0, &taskmgr) ==
		      ISC_R_SUCCESS);
	task = NULL;
	RUNTIME_CHECK(isc_task_create(taskmgr, mctx, 0, &task) ==
		      ISC_R_SUCCESS);

	timermgr = NULL;
	RUNTIME_CHECK(isc_timermgr_create(mctx, &timermgr) == ISC_R_SUCCESS);
	socketmgr = NULL;
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);

	cache = NULL;
	RUNTIME_CHECK(dns_cache_create(mctx, taskmgr, timermgr,
				       dns_rdataclass_in, "rbt", 0, NULL,
				       &cache) == ISC_R_SUCCESS);

	view = NULL;
	RUNTIME_CHECK(dns_view_create(mctx, dns_rdataclass_in, "default",
				      &view) == ISC_R_SUCCESS);

	RUNTIME_CHECK(dns_view_createresolver(view, taskmgr, 10, socketmgr,
					      timermgr, 0, NULL, NULL) ==
		      DNS_R_SUCCESS);

	{
		struct in_addr ina;
		isc_sockaddr_t sa;
		isc_sockaddrlist_t sal;

		ISC_LIST_INIT(sal);
		ina.s_addr = inet_addr("127.0.0.1");
		isc_sockaddr_fromin(&sa, &ina, 53);
		ISC_LIST_APPEND(sal, &sa, link);

		dns_resolver_setforwarders(view->resolver, &sal);
		dns_resolver_setfwdpolicy(view->resolver, dns_fwdpolicy_only);
	}

	dns_view_setcache(view, cache);
	dns_view_freeze(view);

	dns_cache_detach(&cache);

	printf("name = %s\n", argv[isc_commandline_index]);
	isc_buffer_init(&b, argv[isc_commandline_index],
			strlen(argv[isc_commandline_index]),
			ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&b, strlen(argv[isc_commandline_index]));
	dns_fixedname_init(&name);
	dns_fixedname_init(&target);
	RUNTIME_CHECK(dns_name_fromtext(dns_fixedname_name(&name), &b,
					dns_rootname, ISC_FALSE, NULL) ==
		      ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_app_onrun(mctx, task, run, NULL) == ISC_R_SUCCESS);

	(void)isc_app_run();

	dns_view_detach(&view);
	isc_task_shutdown(task);
	isc_task_detach(&task);
	isc_taskmgr_destroy(&taskmgr);

	isc_socketmgr_destroy(&socketmgr);
	isc_timermgr_destroy(&timermgr);

	isc_log_destroy(&lctx);

	if (verbose)
		isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	isc_app_finish();

	return (0);
}
