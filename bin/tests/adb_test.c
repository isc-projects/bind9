/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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
#include <unistd.h>
#include <string.h>

#include <isc/app.h>
#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/net.h>

#include <dns/name.h>
#include <dns/address.h>

isc_mem_t *mctx;
isc_taskmgr_t *manager;

static void lookup_callback(isc_task_t *, isc_event_t *);
static void fatal(char *, ...);
static inline void check_result(isc_result_t, char *);

static void
fatal(char *format, ...)
{
	va_list args;

	va_start(args, format);	
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(1);
}

static inline void
check_result(isc_result_t result, char *msg)
{
	if (result != ISC_R_SUCCESS)
		fatal("%s: %s", msg, isc_result_totext(result));
}

static void
lookup_callback(isc_task_t *task, isc_event_t *ev)
{
	dns_name_t *name;
	dns_adbhandle_t *handle;

	printf("Task %p got event %p type %08x from %p, arg %p\n",
	       task, ev, ev->type, ev->sender, ev->arg);

	name = ev->arg;
	handle = ev->sender;

	isc_event_free(&ev);
	isc_app_shutdown();
}

int
main(int argc, char **argv)
{
	isc_task_t *t1, *t2;
	isc_sockaddr_t sockaddr;
	struct in_addr ina;
	isc_result_t result;
	dns_name_t name1, name2;
	isc_buffer_t t, namebuf;
	unsigned char namestorage1[512];
	unsigned char namestorage2[512];
	dns_view_t *view;
	dns_adb_t *adb;
	dns_adbhandle_t *handle;

	(void)argc;
	(void)argv;

	dns_result_register();
	result = isc_app_start();
	check_result(result, "isc_app_start()");

	/*
	 * EVERYTHING needs a memory context.
	 */
	mctx = NULL;
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	/*
	 * The task manager is independent (other than memory context)
	 */
	manager = NULL;
	result = isc_taskmgr_create(mctx, 2, 0, &manager);
	check_result(result, "isc_taskmgr_create");

	t1 = NULL;
	result = isc_task_create(manager, NULL, 0, &t1);
	check_result(result, "isc_task_create t1");
	t2 = NULL;
	result = isc_task_create(manager, NULL, 0, &t2);
	check_result(result, "isc_task_create t2");

	printf("task 1 = %p\n", t1);
	printf("task 2 = %p\n", t2);

	view = NULL;
	result = dns_view_create(mctx, dns_rdataclass_in, "foo", &view);
	check_result(result, "dns_view_create");

	/*
	 * Create the address database.
	 */
	adb = NULL;
	result = dns_adb_create(mctx, view, &adb);
	check_result(result, "dns_adb_create");

#define NAME1 "nonexistant.flame.org."
#define NAME2 "badname.isc.org."

	isc_buffer_init(&t, NAME1, sizeof NAME1 - 1, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&t, strlen(NAME1));
	isc_buffer_init(&namebuf, namestorage1, sizeof namestorage1,
			ISC_BUFFERTYPE_BINARY);
	dns_name_init(&name1, NULL);
	result = dns_name_fromtext(&name1, &t, dns_rootname, ISC_FALSE,
				   &namebuf);
	check_result(result, "dns_name_fromtext NAME1");

	isc_buffer_init(&t, NAME2, sizeof NAME2 - 1, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&t, strlen(NAME2));
	isc_buffer_init(&namebuf, namestorage2, sizeof namestorage2,
			ISC_BUFFERTYPE_BINARY);
	dns_name_init(&name2, NULL);
	result = dns_name_fromtext(&name2, &t, dns_rootname, ISC_FALSE,
				   &namebuf);
	check_result(result, "dns_name_fromtext NAME2");

	/*
	 * Store this address for this name.
	 */
	ina.s_addr = inet_addr("1.2.3.4");
	isc_sockaddr_fromin(&sockaddr, &ina, 53);
	result = dns_adb_insert(adb, &name1, &sockaddr);
	check_result(result, "dns_adb_insert 1.2.3.4");
	printf("Added 1.2.3.4\n");

	ina.s_addr = inet_addr("1.2.3.5");
	isc_sockaddr_fromin(&sockaddr, &ina, 53);
	result = dns_adb_insert(adb, &name1, &sockaddr);
	check_result(result, "dns_adb_insert 1.2.3.5");
	printf("Added 1.2.3.5\n");

	ina.s_addr = inet_addr("1.2.3.6");
	isc_sockaddr_fromin(&sockaddr, &ina, 53);
	result = dns_adb_insert(adb, &name1, &sockaddr);
	check_result(result, "dns_adb_insert 1.2.3.6");
	printf("Added 1.2.3.6\n");

	ina.s_addr = inet_addr("1.2.3.5");
	isc_sockaddr_fromin(&sockaddr, &ina, 53);
	result = dns_adb_insert(adb, &name2, &sockaddr);
	check_result(result, "dns_adb_insert 1.2.3.5");
	printf("Added 1.2.3.5\n");

	/*
	 * Try to look up a name or two.
	 */
	handle = NULL;
	result = dns_adb_lookup(adb, t2, lookup_callback, &name1,
				&name1, &name1, &handle);
	check_result(result, "dns_adb_lookup name1");
	check_result(handle->result, "handle->result");

	dns_adb_dump(adb, stderr);
	dns_adb_dumphandle(adb, handle, stderr);

	/*
	 * delete one of the names, and kill the adb
	 */
	result = dns_adb_deletename(adb, &name2);
	check_result(result, "dns_adb_deletename name2");

	dns_adb_dump(adb, stderr);
	dns_adb_dumphandle(adb, handle, stderr);

	dns_adb_done(adb, &handle);
	isc_task_detach(&t1);
	isc_task_detach(&t2);

	isc_mem_stats(mctx, stdout);
	dns_adb_dump(adb, stderr);
	dns_adb_destroy(&adb);

	isc_app_run();

	dns_view_detach(&view);

	fprintf(stderr, "Destroying task manager\n");
	isc_taskmgr_destroy(&manager);

	isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	isc_app_finish();

	return (0);
}
