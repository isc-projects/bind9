/*
 * Copyright (C) 1998  Internet Software Consortium.
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

#ifndef ISC_TASK_H
#define ISC_TASK_H 1

#include <stddef.h>

#include <isc/list.h>
#include <isc/mem.h>

#include <isc/boolean.h>
#include <isc/result.h>


/***
 *** Core Types.
 ***/

typedef struct isc_event *		isc_event_t;
typedef struct isc_task *		isc_task_t;
typedef struct isc_taskmgr *		isc_taskmgr_t;


/***
 *** Events.
 ***/

/*
 * Negative event types are reserved for use by the task manager.
 *
 * Type 0 means "any type".
 */
typedef int				isc_eventtype_t;

typedef isc_boolean_t (*isc_taskaction_t)(isc_task_t, isc_event_t);
typedef void (*isc_eventdestructor_t)(isc_event_t);

/*
 * This structure is public because "subclassing" it may be useful when
 * defining new event types.
 */ 
struct isc_event {
	isc_memctx_t			mctx;
	size_t				size;
	void *				sender;
	isc_eventtype_t			type;
	isc_taskaction_t		action;
	void *				arg;
	isc_eventdestructor_t		destroy;
	LINK(struct isc_event)		link;
};

#define ISC_TASKEVENT_ANYEVENT		0
#define ISC_TASKEVENT_SHUTDOWN		(-1)

typedef LIST(struct isc_event)		isc_eventlist_t;

isc_event_t				isc_event_allocate(isc_memctx_t,
							   void *,
							   isc_eventtype_t,
							   isc_taskaction_t,
							   void *arg,
							   size_t);
void					isc_event_free(isc_event_t *);


/***
 *** Tasks.
 ***/

isc_result_t				isc_task_create(isc_taskmgr_t,
							isc_taskaction_t,
							void *,
							unsigned int,
							isc_task_t *);
void					isc_task_attach(isc_task_t,
							isc_task_t *);
void					isc_task_detach(isc_task_t *);
isc_result_t				isc_task_send(isc_task_t, 
						      isc_event_t *);
unsigned int				isc_task_purge(isc_task_t, void *,
						   isc_eventtype_t);
void					isc_task_shutdown(isc_task_t);
void					isc_task_destroy(isc_task_t *);

/***
 *** Task Manager.
 ***/

isc_result_t				isc_taskmgr_create(isc_memctx_t,
							   unsigned int,
							   unsigned int,
							   isc_taskmgr_t *);
void					isc_taskmgr_destroy(isc_taskmgr_t *);

#endif /* ISC_TASK_H */
