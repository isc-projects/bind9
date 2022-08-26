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
 * from the task's event queue by purging the event.
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
#include <isc/refcount.h>
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

#define isc_task_create(manager, taskp, tid) \
	isc__task_create(manager, taskp, tid ISC__TASKFILELINE)

isc_result_t
isc__task_create(isc_taskmgr_t *manager, isc_task_t **taskp,
		 int tid ISC__TASKFLARG);
/*%<
 * Create a task, bound to a particular thread id.
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
 *\li	#ISC_R_UNEXPECTED
 *\li	#ISC_R_SHUTTINGDOWN
 */

ISC_REFCOUNT_DECL(isc_task);

void
isc_task_send(isc_task_t *task, isc_event_t **eventp);
/*%<
 * Send '*event' to 'task'.
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
 * task.
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

isc_loopmgr_t *
isc_task_getloopmgr(isc_task_t *task);

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
 *	If the task has not been named, the string is
 *	empty.
 *
 */

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
 * Relinquish the exclusive access obtained by
 *isc_task_beginexclusive(), allowing other tasks to execute.
 *
 * Requires:
 *\li	'task' is the calling task, and has obtained
 *		exclusive access by calling isc_task_spl().
 */

/*****
 ***** Task Manager.
 *****/

void
isc_taskmgr_create(isc_mem_t *mctx, isc_loopmgr_t *loopmgr,
		   isc_taskmgr_t **managerp);
/*%<
 * Create a new task manager.
 *
 * Notes:
 *
 *\li	This is meant to be called from isc_managers_create().
 *
 * Requires:
 *
 *\li      'mctx' is a valid memory context.

 *\li      'loopmgr' is a valid loop manager.
 *
 *\li	managerp != NULL && *managerp == NULL
 *
 * Ensures:
 *
 *\li	On success, '*managerp' will be attached to the newly created task
 *	manager.
 *
 * Returns:
 *
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMEMORY
 *\li	#ISC_R_NOTHREADS		No threads could be created.
 *\li	#ISC_R_UNEXPECTED		An unexpected error occurred.
 *\li	#ISC_R_SHUTTINGDOWN		The non-threaded, shared, task
 *					manager shutting down.
 */

void
isc_taskmgr_destroy(isc_taskmgr_t **managerp);
/*%<
 * Destroy '*managerp'.
 *
 * Notes:
 *
 *\li	Calling isc__taskmgr_destroy() will shut down all tasks managed by
 *	*managerp that haven't already been shutdown. The call will block
 *	until all tasks have entered the done state.
 *
 *\li	isc__taskmgr_destroy() must not be called by a task event action,
 *	because it would block forever waiting for the event action to
 *	complete. An event action that wants to cause task manager shutdown
 *	should request some non-event action thread of execution to do the
 *	shutdown, e.g. by signaling a condition variable or using
 *	isc_loopmgr_shutdown().
 *
 *\li	The task manager is reference counted and will be destroyed when
 *	the last reference is detached. The only difference between this
 *	function and isc_task_detach() is that this one will assert if
 *	more than 1 reference is held. This function is only meant to be
 *	called from isc_managers_destroy(), by which time all other
 *	references should have been detached. If any are still being held,
 *	it's a programming error, and we want to crash.
 *
 * Requires:
 *
 *\li	'*managerp' is a valid task manager.
 *
 *\li   No other references to the task manager are being held.
 */

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
