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

#include <config.h>

#include <isc/assertions.h>
#include <isc/ondestroy.h>
#include <isc/result.h>
#include <isc/task.h>

#define ONDESTROY_MAGIC		0x44655374 /* DeSt */
#define VALID_ONDESTROY(s)	(s != NULL && (s->magic == ONDESTROY_MAGIC))

void
isc_ondestroy_init(isc_ondestroy_t *ondest)
{
	ondest->magic = ONDESTROY_MAGIC;
	ISC_LIST_INIT(ondest->events);
}


isc_result_t
isc_ondestroy_register(isc_ondestroy_t *ondest,
		       isc_task_t *task, isc_event_t **eventp)
{
	isc_event_t *theevent;
	isc_task_t *thetask = NULL;

	REQUIRE(VALID_ONDESTROY(ondest));
	REQUIRE(task != NULL);
	REQUIRE(eventp != NULL);

	theevent = *eventp;

	REQUIRE(theevent != NULL);

	isc_task_attach(task, &thetask);

	theevent->sender = thetask;
	
	ISC_LIST_APPEND(ondest->events, theevent, link);

	return (ISC_R_SUCCESS);
}



void
isc_ondestroy_notify(isc_ondestroy_t *ondest, void *sender)
{
	isc_event_t *eventp;
	isc_task_t *task;
	
	REQUIRE(VALID_ONDESTROY(ondest));

	eventp = ISC_LIST_HEAD(ondest->events);
	while (eventp != NULL) {
		ISC_LIST_UNLINK(ondest->events, eventp, link);

		task = eventp->sender;
		eventp->sender = sender;
		
		isc_task_sendanddetach(&task, &eventp);

		eventp = ISC_LIST_HEAD(ondest->events);
	}
}

	
