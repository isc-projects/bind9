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

#include <config.h>

#include <lwres/lwres.h>

#include <isc/assertions.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/task.h>
#include <isc/util.h>

#include "client.h"

/*
 * The goal number of clients we can handle will be NTASKS * NRECVS.
 */
#define NTASKS		10	/* tasks to create to handle lwres queries */
#define NRECVS		 5	/* max clients per task */
#define NTHREADS	 1	/* # threads to create in thread manager */

/*
 * Array of client managers.  Each of these will have a task associated
 * with it.
 */
clientmgr_t    *cmgr;
unsigned int	ntasks;	/* number of tasks actually created */

int
main(int argc, char **argv)
{
	isc_mem_t *mem;
	isc_taskmgr_t *taskmgr;
	isc_result_t result;
	unsigned int i, j;
	client_t *client;

	UNUSED(argc);
	UNUSED(argv);

	mem = NULL;
	result = isc_mem_create(0, 0, &mem);
	INSIST(result == ISC_R_SUCCESS);

	cmgr = isc_mem_get(mem, sizeof(clientmgr_t) * NTHREADS);
	INSIST(cmgr != NULL);

	taskmgr = NULL;
	result = isc_taskmgr_create(mem, NTHREADS, 0, &taskmgr);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * Create one task for each client manager.
	 */
	for (i = 0 ; i < NTASKS ; i++) {
		cmgr[i].task = NULL;
		ISC_LIST_INIT(cmgr[i].idle);
		ISC_LIST_INIT(cmgr[i].running);
		result = isc_task_create(taskmgr, mem, 0, &cmgr[i].task);
		INSIST(result == ISC_R_SUCCESS);
	}
	INSIST(i > 0);
	ntasks = i;  /* remember how many we managed to create */

	/*
	 * Now, run through each client manager and populate it with
	 * client structures.  Do this by creating one receive for each
	 * task, in a loop, so each task has a chance of getting at least
	 * one client structure.
	 */
	for (i = 0 ; i < NRECVS ; i++) {
		client = isc_mem_get(mem, sizeof(client_t) * ntasks);
		if (client == NULL)
			break;
		for (j = 0 ; j < ntasks ; j++) {
			client[j].socket = NULL;
			ISC_LINK_INIT(&client[j], link);
			ISC_LIST_APPEND(cmgr[j].idle, &client[j], link);
		}
	}
	INSIST(i > 0);

	/*
	 * Now, create a socket.  Issue one read request for each task
	 * we have.
	 */

	/*
	 * Wait for ^c or kill.
	 */

	return (0);
}
