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

int
main(int argc, char **argv)
{
	isc_task_t *t1, *t2;
	isc_sockaddr_t sockaddr;
	struct in_addr ina;
	isc_result_t result;
	dns_name_t name;
	isc_buffer_t t, namebuf;
	unsigned char namestorage[512];
	dns_adb_t *adb;

	(void)argc;
	(void)argv;

	dns_result_register();

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

	/*
	 * Create the address database.
	 */
	adb = NULL;
	result = dns_adb_create(mctx, &adb);
	check_result(result, "dns_adb_create");

#define NAME1 "nonexistant.flame.org."

	isc_buffer_init(&t, NAME1, sizeof NAME1 - 1, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&t, strlen(NAME1));
	isc_buffer_init(&namebuf, namestorage, sizeof namestorage,
			ISC_BUFFERTYPE_BINARY);
	dns_name_init(&name, NULL);
	result = dns_name_fromtext(&name, &t, dns_rootname, ISC_FALSE,
				   &namebuf);
	check_result(result, "dns_name_fromtext");

	/*
	 * Store this address for this name.
	 */
	ina.s_addr = inet_addr("1.2.3.4");
	isc_sockaddr_fromin(&sockaddr, &ina, 53);
	result = dns_adb_insert(adb, &name, &sockaddr);
	check_result(result, "dns_adb_insert 1.2.3.4");
	printf("Added 1.2.3.4\n");

	ina.s_addr = inet_addr("1.2.3.5");
	isc_sockaddr_fromin(&sockaddr, &ina, 53);
	result = dns_adb_insert(adb, &name, &sockaddr);
	check_result(result, "dns_adb_insert 1.2.3.5");
	printf("Added 1.2.3.5\n");

	ina.s_addr = inet_addr("1.2.3.6");
	isc_sockaddr_fromin(&sockaddr, &ina, 53);
	result = dns_adb_insert(adb, &name, &sockaddr);
	check_result(result, "dns_adb_insert 1.2.3.6");
	printf("Added 1.2.3.6\n");

	isc_task_detach(&t1);
	isc_task_detach(&t2);

	dns_adb_dump(adb, stderr);

	result = dns_adb_deletename(adb, &name);
	check_result(result, "dns_adb_deletename");

	dns_adb_dump(adb, stderr);

	isc_mem_stats(mctx, stdout);
	dns_adb_destroy(&adb);

	fprintf(stderr, "Destroying task manager\n");
	isc_taskmgr_destroy(&manager);

	isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	return (0);
}
