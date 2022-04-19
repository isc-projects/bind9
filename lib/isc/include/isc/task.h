/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*****
 ***** Module Info
 *****/

/*! \file isc/task.h
 * \brief The task system provides a lightweight execution context, which is
 * basically an event queue.
 *
 * When a task's event queue is non-empty, the
 * task is runnable.  A small work crew of threads, typically one per CPU,
 * execute runnable tasks by dispatching the events on the tasks' event
 * queues.  Context switching between tasks is fast.
 *
 * \li MP:
 *	The module ensures appropriate synchronization of data structures it
 *	creates and manipulates.
 *	The caller must ensure that isc_taskmgr_destroy() is called only
 *	once for a given manager.
 *
 * \li Reliability:
 *	No anticipated impact.
 *
 * \li Resources:
 *	TBS
 *
 * \li Security:
 *	No anticipated impact.
 *
 * \li Standards:
 *	None.
 *
 * \section purge Purging and Unsending
 *
 * Events which have been queued for a task but not delivered may be removed
 * from the task's event queue by purging or unsending.
 *
 * With both types, the caller specifies a matching pattern that selects
 * events based upon their sender, type, and tag.
 *
 * Purging calls isc_event_free() on the matching events.
 *
 */

/***
 *** Imports.
 ***/

#include <stdbool.h>

#include <isc/eventclass.h>
#include <isc/lang.h>
#include <isc/netmgr.h>
#include <isc/stdtime.h>
#include <isc/types.h>
#include <isc/util.h>

#if TASKMGR_TRACE
#define ISC__TASKTRACE_SIZE 8
#define ISC__TASKFILELINE   , __func__, __FILE__, __LINE__
#define ISC__TASKFLARG	    , const char *func, const char *file, unsigned int line

#else
#define ISC__TASKFILELINE
#define ISC__TASKFLARG
#endif

#define ISC_TASKEVENT_SHUTDOWN (ISC_EVENTCLASS_TASK + 0)
#define ISC_TASKEVENT_TEST     (ISC_EVENTCLASS_TASK + 1)

/*****
 ***** Tasks.
 *****/

ISC_LANG_BEGINDECLS

/***
 *** Types
 ***/

#define isc_task_create(m, q, t) \
	isc__task_create_bound(m, q, t, -1 ISC__TASKFILELINE)
#define isc_task_create_bound(m, q, t, i) \
	isc__task_create_bound(m, q, t, i ISC__TASKFILELINE)

isc_result_t
isc__task_create_bound(isc_taskmgr_t *manager, unsigned int quantum,
		       isc_task_t **taskp, int tid ISC__TASKFLARG);
/*%<
 * Create a task, optionally bound to a particular tid.
 *
 * Notes:
 *
 *\li	If 'quantum' is non-zero, then only that many events can be dispatched
 *	before the task must yield to other tasks waiting to execute.  If
 *	quantum is zero, then the default quantum of the task manager will
 *	be used.
 *
 *\li	The 'quantum' option may be removed from isc_task_create() in the
 *	future.  If this happens, isc_task_getquantum() and
 *	isc_task_setquantum() will be provided.
 *
 * Requires:
 *
 *\li	'manager' is a valid task manager.
 *
 *\li	taskp != NULL && *taskp == NULL
 *
 * Ensures:
 *
 *\li	On success, '*taskp' is bound to the new task.
 *
 * Returns:
 *
 *\li   #ISC_R_SUCCESS
 *\li	#ISC_R_NOMEMORY
 *\li	#ISC_R_UNEXPECTED
 *\li	#ISC_R_SHUTTINGDOWN
 */

void
isc_task_ready(isc_task_t *task);
/*%<
 * Enqueue the task onto netmgr queue.
 */

isc_result_t
isc_task_run(isc_task_t *task);
/*%<
 * Run all the queued events for the 'task', returning
 * when the queue is empty or the number of events executed
 * exceeds the 'quantum' specified when the task was created.
 *
 * Requires:
 *
 *\li	'task' is a valid task.
 *
 * Returns:
 *
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_QUOTA
 */

void
isc_task_attach(isc_task_t *source, isc_task_t **targetp);
/*%<
 * Attach *targetp to source.
 *
 * Requires:
 *
 *\li	'source' is a valid task.
 *
 *\li	'targetp' points to a NULL isc_task_t *.
 *
 * Ensures:
 *
 *\li	*targetp is attached to source.
 */

void
isc_task_detach(isc_task_t **taskp);
/*%<
 * Detach *taskp from its task.
 *
 * Requires:
 *
 *\li	'*taskp' is a valid task.
 *
 * Ensures:
 *
 *\li	*taskp is NULL.
 *
 *\li	If '*taskp' is the last reference to the task, the task is idle (has
 *	an empty event queue), and has not been shutdown, the task will be
 *	shutdown.
 *
 *\li	If '*taskp' is the last reference to the task and
 *	the task has been shutdown,
 *		all resources used by the task will be freed.
 */

void
isc_task_send(isc_task_t *task, isc_event_t **eventp);
/*%<
 * Send '*event' to 'task', if task is idle try starting it on cpu 'c'
 *
 * Requires:
 *
 *\li	'task' is a valid task.
 *\li	eventp != NULL && *eventp != NULL.
 *
 * Ensures:
 *
 *\li	*eventp == NULL.
 */

void
isc_task_sendanddetach(isc_task_t **taskp, isc_event_t **eventp);
/*%<
 * Send '*event' to '*taskp' and then detach '*taskp' from its
 * task. If task is idle try starting it on cpu 'c'
 *
 * Requires:
 *
 *\li	'*taskp' is a valid task.
 *\li	eventp != NULL && *eventp != NULL.
 *
 * Ensures:
 *
 *\li	*eventp == NULL.
 *
 *\li	*taskp == NULL.
 *
 *\li	If '*taskp' is the last reference to the task, the task is
 *	idle (has an empty event queue), and has not been shutdown,
 *	the task will be shutdown.
 *
 *\li	If '*taskp' is the last reference to the task and
 *	the task has been shutdown,
 *		all resources used by the task will be freed.
 */

bool
isc_task_purgeevent(isc_task_t *task, isc_event_t *event);
/*%<
 * Purge 'event' from a task's event queue.
 *
 * XXXRTH:  WARNING:  This method may be removed before beta.
 *
 * Notes:
 *
 *\li	If 'event' is on the task's event queue, it will be purged,
 * 	unless it is marked as unpurgeable.  'event' does not have to be
 *	on the task's event queue; in fact, it can even be an invalid
 *	pointer.  Purging only occurs if the event is actually on the task's
 *	event queue.
 *
 * \li	Purging never changes the state of the task.
 *
 * Requires:
 *
 *\li	'task' is a valid task.
 *
 * Ensures:
 *
 *\li	'event' is not in the event queue for 'task'.
 *
 * Returns:
 *
 *\li	#true			The event was purged.
 *\li	#false			The event was not in the event queue,
 *					or was marked unpurgeable.
 */

isc_result_t
isc_task_onshutdown(isc_task_t *task, isc_taskaction_t action, void *arg);
/*%<
 * Send a shutdown event with action 'action' and argument 'arg' when
 * 'task' is shutdown.
 *
 * Notes:
 *
 *\li	Shutdown events are posted in LIFO order.
 *
 * Requires:
 *
 *\li	'task' is a valid task.
 *
 *\li	'action' is a valid task action.
 *
 * Ensures:
 *
 *\li	When the task is shutdown, shutdown events requested with
 *	isc_task_onshutdown() will be appended to the task's event queue.
 *
 *
 * Returns:
 *
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMEMORY
 *\li	#ISC_R_SHUTTINGDOWN			Task is shutting down.
 */

void
isc_task_shutdown(isc_task_t *task);
/*%<
 * Shutdown 'task'.
 *
 * Notes:
 *
 *\li	Shutting down a task causes any shutdown events requested with
 *	isc_task_onshutdown() to be posted (in LIFO order).  The task
 *	moves into a "shutting down" mode which prevents further calls
 *	to isc_task_onshutdown().
 *
 *\li	Trying to shutdown a task that has already been shutdown has no
 *	effect.
 *
 * Requires:
 *
 *\li	'task' is a valid task.
 *
 * Ensures:
 *
 *\li	Any shutdown events requested with isc_task_onshutdown() have been
 *	posted (in LIFO order).
 */

void
isc_task_destroy(isc_task_t **taskp);
/*%<
 * Destroy '*taskp'.
 *
 * Notes:
 *
 *\li	This call is equivalent to:
 *
 *\code
 *		isc_task_shutdown(*taskp);
 *		isc_task_detach(taskp);
 *\endcode
 *
 * Requires:
 *
 *	'*taskp' is a valid task.
 *
 * Ensures:
 *
 *\li	Any shutdown events requested with isc_task_onshutdown() have been
 *	posted (in LIFO order).
 *
 *\li	*taskp == NULL
 *
 *\li	If '*taskp' is the last reference to the task,
 *		all resources used by the task will be freed.
 */

void
isc_task_setname(isc_task_t *task, const char *name, void *tag);
/*%<
 * Name 'task'.
 *
 * Notes:
 *
 *\li	Only the first 15 characters of 'name' will be copied.
 *
 *\li	Naming a task is currently only useful for debugging purposes.
 *
 * Requires:
 *
 *\li	'task' is a valid task.
 */

const char *
isc_task_getname(isc_task_t *task);
/*%<
 * Get the name of 'task', as previously set using isc_task_setname().
 *
 * Notes:
 *\li	This function is for debugging purposes only.
 *
 * Requires:
 *\li	'task' is a valid task.
 *
 * Returns:
 *\li	A non-NULL pointer to a null-terminated string.
 * 	If the task has not been named, the string is
 * 	empty.
 *
 */

isc_nm_t *
isc_task_getnetmgr(isc_task_t *task);

void *
isc_task_gettag(isc_task_t *task);
/*%<
 * Get the tag value for  'task', as previously set using isc_task_settag().
 *
 * Notes:
 *\li	This function is for debugging purposes only.
 *
 * Requires:
 *\li	'task' is a valid task.
 */

void
isc_task_setquantum(isc_task_t *task, unsigned int quantum);
/*%<
 * Set future 'task' quantum to 'quantum'.  The current 'task' quantum will be
 * kept for the current isc_task_run() loop, and will be changed for the next
 * run.  Therefore, the function is save to use from the event callback as it
 * will not affect the current event loop processing.
 */

isc_result_t
isc_task_beginexclusive(isc_task_t *task);
/*%<
 * Request exclusive access for 'task', which must be the calling
 * task.  Waits for any other concurrently executing tasks to finish their
 * current event, and prevents any new events from executing in any of the
 * tasks sharing a task manager with 'task'.
 * It also pauses processing of network events in netmgr if it was provided
 * when taskmgr was created.
 *
 * The exclusive access must be relinquished by calling
 * isc_task_endexclusive() before returning from the current event handler.
 *
 * Requires:
 *\li	'task' is the calling task.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS		The current task now has exclusive access.
 *\li	#ISC_R_LOCKBUSY		Another task has already requested exclusive
 *				access.
 */

void
isc_task_endexclusive(isc_task_t *task);
/*%<
 * Relinquish the exclusive access obtained by isc_task_beginexclusive(),
 * allowing other tasks to execute.
 *
 * Requires:
 *\li	'task' is the calling task, and has obtained
 *		exclusive access by calling isc_task_spl().
 */

bool
isc_task_exiting(isc_task_t *t);
/*%<
 * Returns true if the task is in the process of shutting down,
 * false otherwise.
 *
 * Requires:
 *\li	'task' is a valid task.
 */

/*****
 ***** Task Manager.
 *****/

void
isc_taskmgr_attach(isc_taskmgr_t *, isc_taskmgr_t **);
void
isc_taskmgr_detach(isc_taskmgr_t **);
/*%<
 * Attach/detach the task manager.
 */

void
isc_taskmgr_setexcltask(isc_taskmgr_t *mgr, isc_task_t *task);
/*%<
 * Set a task which will be used for all task-exclusive operations.
 *
 * Requires:
 *\li	'manager' is a valid task manager.
 *
 *\li	'task' is a valid task.
 */

isc_result_t
isc_taskmgr_excltask(isc_taskmgr_t *mgr, isc_task_t **taskp);
/*%<
 * Attach '*taskp' to the task set by isc_taskmgr_getexcltask().
 * This task should be used whenever running in task-exclusive mode,
 * so as to prevent deadlock between two exclusive tasks.
 *
 * Requires:
 *\li	'manager' is a valid task manager.
 *
 *\li	taskp != NULL && *taskp == NULL
 */

#ifdef HAVE_LIBXML2
int
isc_taskmgr_renderxml(isc_taskmgr_t *mgr, void *writer0);
#endif /* ifdef HAVE_LIBXML2 */

#ifdef HAVE_JSON_C
isc_result_t
isc_taskmgr_renderjson(isc_taskmgr_t *mgr, void *tasksobj0);
#endif /* HAVE_JSON_C */

ISC_LANG_ENDDECLS
