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

#include <isc/assertions.h>
#include <isc/commandline.h>
#include <isc/error.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/app.h>
#include <isc/mutex.h>
#include <isc/boolean.h>
#include <isc/net.h>
#include <isc/socket.h>
#include <isc/util.h>
#include <isc/netaddr.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/cache.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/resolver.h>
#include <dns/events.h>
#include <dns/dispatch.h>
#include <dns/byaddr.h>
#include <dns/view.h>

static void
done(isc_task_t *task, isc_event_t *event) {
	dns_byaddrevent_t *bevent;

	REQUIRE(event->type == DNS_EVENT_BYADDRDONE);
	bevent = (dns_byaddrevent_t *)event;

	(void)task;

	printf("byaddr event result = %s\n",
	       isc_result_totext(bevent->result));

	dns_byaddr_destroy(&bevent->byaddr);
	isc_event_free(&event);

	isc_app_shutdown();
}

int
main(int argc, char *argv[]) {
	isc_mem_t *mctx;
	isc_boolean_t verbose = ISC_FALSE;
	unsigned int workers = 2;
	isc_taskmgr_t *taskmgr;
	isc_task_t *task;
	isc_timermgr_t *timermgr;
	dns_view_t *view;
	int ch;
	isc_socketmgr_t *socketmgr;
	isc_netaddr_t na;
	dns_byaddr_t *byaddr;
	isc_result_t result;
	unsigned int options = 0;
	dns_cache_t *cache;

	RUNTIME_CHECK(isc_app_start() == ISC_R_SUCCESS);

	dns_result_register();

	mctx = NULL;
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	while ((ch = isc_commandline_parse(argc, argv, "nvw:")) != -1) {
		switch (ch) {
		case 'n':
			options |= DNS_BYADDROPT_IPV6NIBBLE;
			break;
		case 'v':
			verbose = ISC_TRUE;
			break;
		case 'w':
			workers = (unsigned int)atoi(isc_commandline_argument);
			break;
		}
	}

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

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc != 0)
		printf("ignoring trailing arguments\n");

	cache = NULL;
	RUNTIME_CHECK(dns_cache_create(mctx, taskmgr, timermgr,
				       dns_rdataclass_in, "rbt", 0, NULL,
				       &cache) == ISC_R_SUCCESS);

	view = NULL;
	RUNTIME_CHECK(dns_view_create(mctx, dns_rdataclass_in, "default",
				      &view) == ISC_R_SUCCESS);

	RUNTIME_CHECK(dns_view_createresolver(view, taskmgr, 10, socketmgr,
					      timermgr, NULL) ==
		      DNS_R_SUCCESS);

	{
		struct in_addr ina;
		isc_sockaddr_t sa;
		isc_sockaddrlist_t sal;

		ISC_LIST_INIT(sal);
		ina.s_addr = inet_addr("204.152.187.11");
		isc_sockaddr_fromin(&sa, &ina, 53);
		ISC_LIST_APPEND(sal, &sa, link);

		dns_resolver_setforwarders(view->resolver, &sal);
		dns_resolver_setfwdpolicy(view->resolver, dns_fwdpolicy_only);
	}

	dns_view_setcache(view, cache);
	dns_view_freeze(view);

	dns_cache_detach(&cache);

#if 1
	na.family = AF_INET;
	na.type.in.s_addr = inet_addr("204.152.187.11");
#else
	na.family = AF_INET6;
	INSIST(inet_pton(AF_INET6, "fe80::210:4bff:fefe:f18d",
			 (char *)&na.type.in6) == 1);
#endif

	result = dns_byaddr_create(mctx, &na, view, options, task,
				   done, NULL, &byaddr);
	if (result != ISC_R_SUCCESS) {
		printf("dns_byaddr_create() returned %s\n",
		       isc_result_totext(result));
		RUNTIME_CHECK(0);
	}

	(void)isc_app_run();

	/*
	 * XXXRTH if we get a control-C before we get to isc_app_run(),
	 * we're in trouble (because we might try to destroy things before
	 * they've been created.
	 */

	dns_view_detach(&view);

	isc_task_shutdown(task);
	isc_task_detach(&task);
	isc_taskmgr_destroy(&taskmgr);

	isc_socketmgr_destroy(&socketmgr);
	isc_timermgr_destroy(&timermgr);

	if (verbose)
		isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	isc_app_finish();

	return (0);
}
