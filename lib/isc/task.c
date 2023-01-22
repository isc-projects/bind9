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

/*! \file */

#include <stdbool.h>
#include <unistd.h>

#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/backtrace.h>
#include <isc/condition.h>
#include <isc/event.h>
#include <isc/job.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/tid.h>
#include <isc/time.h>
#include <isc/util.h>
#include <isc/uv.h>

#ifdef HAVE_LIBXML2
#include <libxml/xmlwriter.h>
#define ISC_XMLCHAR (const xmlChar *)
#endif /* HAVE_LIBXML2 */

#ifdef HAVE_JSON_C
#include <json_object.h>
#endif /* HAVE_JSON_C */

#include "loop_p.h"

/*
 * Task manager is built around 'as little locking as possible' concept.
 * Each thread has his own queue of tasks to be run, if a task is in running
 * state it will stay on the runner it's currently on - that helps with data
 * locality on CPU.
 *
 * To make load even some tasks (from task pools) are bound to specific
 * queues using isc_task_create. This way load balancing between
 * CPUs/queues happens on the higher layer.
 */

#ifdef ISC_TASK_TRACE
#define XTRACE(m)                                                 \
	fprintf(stderr, "task %p.tid %zu thread %zu: %s\n", task, \
		(size_t)task->tid, (size_t)task->tid, (m))
#define XTTRACE(t, m) \
	fprintf(stderr, "task %p thread %zu: %s\n", (t), (size_t)isc_tid(), (m))
#define XTHREADTRACE(m) \
	fprintf(stderr, "thread %zu: %s\n", (size_t)isc_tid(), (m))
#else /* ifdef ISC_TASK_TRACE */
#define XTRACE(m)
#define XTTRACE(t, m)
#define XTHREADTRACE(m)
#endif /* ifdef ISC_TASK_TRACE */

/***
 *** Types.
 ***/

typedef enum {
	task_state_idle,    /* not doing anything, events queue empty */
	task_state_ready,   /* waiting in worker's queue */
	task_state_running, /* actively processing events */
	task_state_done	    /* shutting down, no events or references */
} task_state_t;

#if defined(HAVE_LIBXML2) || defined(HAVE_JSON_C)
static const char *statenames[] = {
	"idle",
	"ready",
	"running",
	"done",
};
#endif /* if defined(HAVE_LIBXML2) || defined(HAVE_JSON_C) */

#define TASK_MAGIC    ISC_MAGIC('T', 'A', 'S', 'K')
#define VALID_TASK(t) ISC_MAGIC_VALID(t, TASK_MAGIC)

#if TASKMGR_TRACE
void
isc__taskmgr_dump_active(isc_taskmgr_t *taskmgr);
#endif

struct isc_task {
	/* Not locked. */
	unsigned int magic;
	isc_taskmgr_t *manager;
	isc_mutex_t lock;
	/* Locked by task lock. */
	isc_loop_t *loop;
	uint32_t tid;
	task_state_t state;
	isc_refcount_t references;
	isc_eventlist_t events;
	unsigned int nevents;
	isc_stdtime_t now;
	isc_time_t tnow;
	char name[16];
	void *tag;
	/* Locked by task manager lock. */
#if TASKMGR_TRACE
	char func[PATH_MAX];
	char file[PATH_MAX];
	unsigned int line;
	void *backtrace[ISC__TASKTRACE_SIZE];
	int backtrace_size;
#endif
	LINK(isc_task_t) qlink;
	LINK(isc_task_t) link;
};

#define TASK_SHUTTINGDOWN(t) (atomic_load_acquire(&(t)->manager->shuttingdown))

#define TASK_TASKMGR_MAGIC ISC_MAGIC('T', 'S', 'K', 'M')
#define VALID_TASKMGR(m)   ISC_MAGIC_VALID(m, TASK_TASKMGR_MAGIC)

typedef ISC_LIST(isc_task_t) isc_tasklist_t;

struct isc_taskmgr {
	/* Not locked. */
	unsigned int magic;
	isc_refcount_t references;
	isc_mem_t *mctx;
	isc_mutex_t lock;
	isc_loopmgr_t *loopmgr;
	uint32_t nloops;

	/* Locked by task manager lock. */
	isc_mutex_t *locks;
	isc_tasklist_t *tasks;
	atomic_uint_fast32_t mode;
	uint32_t exclusive_req;
	atomic_bool shuttingdown;
	isc_task_t *excl;
};

static void
task_setstate(isc_task_t *task, task_state_t state);

/***
 *** Tasks.
 ***/

static void
task_destroy(void *arg) {
	isc_task_t *task = arg;
	isc_loop_t *loop = task->loop;
	isc_taskmgr_t *taskmgr = task->manager;
	REQUIRE(EMPTY(task->events));

	XTRACE("task_finished");

	task_setstate(task, task_state_done);

	isc_refcount_destroy(&task->references);

	LOCK(&taskmgr->locks[task->tid]);
	UNLINK(taskmgr->tasks[task->tid], task, link);
	UNLOCK(&taskmgr->locks[task->tid]);

	isc_mutex_destroy(&task->lock);
	task->magic = 0;

	isc_mem_put(loop->mctx, task, sizeof(*task));

	isc_taskmgr_detach(&taskmgr);

	isc_loop_detach(&loop);
}
ISC_REFCOUNT_IMPL(isc_task, task_destroy);

static isc_result_t
task_run(isc_task_t *task);
static void
task_ready(isc_task_t *task);
static void
task__run(void *arg);

isc_result_t
isc__task_create(isc_taskmgr_t *taskmgr, isc_task_t **taskp,
		 int tid ISC__TASKFLARG) {
	isc_task_t *task = NULL;
	isc_loop_t *loop = NULL;

	REQUIRE(VALID_TASKMGR(taskmgr));
	REQUIRE(taskp != NULL && *taskp == NULL);
	REQUIRE(tid >= 0 && tid < (int)taskmgr->nloops);

	if (atomic_load(&taskmgr->shuttingdown)) {
		return (ISC_R_SHUTTINGDOWN);
	}

	loop = isc_loop_get(taskmgr->loopmgr, tid);

	task = isc_mem_get(loop->mctx, sizeof(*task));
	*task = (isc_task_t){
		.tid = tid,
		.state = task_state_idle,
	};

	isc_loop_attach(loop, &task->loop);

#if TASKMGR_TRACE
	strlcpy(task->func, func, sizeof(task->func));
	strlcpy(task->file, file, sizeof(task->file));
	task->line = line;
	task->backtrace_size = isc_backtrace(task->backtrace,
					     ISC__TASKTRACE_SIZE);
#endif

	isc_taskmgr_attach(taskmgr, &task->manager);

	isc_mutex_init(&task->lock);

	isc_refcount_init(&task->references, 1);

	INIT_LIST(task->events);

	isc_time_settoepoch(&task->tnow);

	INIT_LINK(task, link);
	INIT_LINK(task, qlink);

	task->magic = TASK_MAGIC;

	LOCK(&taskmgr->locks[task->tid]);
	APPEND(taskmgr->tasks[task->tid], task, link);
	UNLOCK(&taskmgr->locks[task->tid]);

	*taskp = task;

	return (ISC_R_SUCCESS);
}

static void
task_setstate(isc_task_t *task, task_state_t state) {
	switch (state) {
	case task_state_idle:
		INSIST(task->state == task_state_running);
		break;
	case task_state_ready:
		if (task->state == task_state_idle) {
			INSIST(EMPTY(task->events));
		} else {
			INSIST(task->state == task_state_running);
		}
		break;
	case task_state_running:
		INSIST(task->state == task_state_ready);
		break;
	case task_state_done:
		INSIST(task->state == task_state_ready ||
		       task->state == task_state_running ||
		       task->state == task_state_idle);
		break;
	default:
		UNREACHABLE();
	}

	task->state = state;
}

static void
task__run(void *arg) {
	isc_task_t *task = arg;
	isc_result_t result = task_run(task);

	switch (result) {
	case ISC_R_QUOTA:
		task_ready(task);
		break;
	case ISC_R_SUCCESS:
	case ISC_R_NOMORE:
		break;
	default:
		UNREACHABLE();
	}
}

/*
 * Moves a task onto the appropriate run queue.
 *
 * Caller must NOT hold queue lock.
 */
static void
task_ready(isc_task_t *task) {
	isc_async_run(task->loop, task__run, task);
}

static bool
task_send(isc_task_t *task, isc_event_t **eventp) {
	bool was_idle = false;
	isc_event_t *event;

	/*
	 * Caller must be holding the task lock.
	 */

	REQUIRE(eventp != NULL);
	event = *eventp;
	*eventp = NULL;
	REQUIRE(event != NULL);
	REQUIRE(task->state != task_state_done);
	REQUIRE(!ISC_LINK_LINKED(event, ev_ratelink));

	XTRACE("task_send");

	if (task->state == task_state_idle) {
		was_idle = true;
		task_setstate(task, task_state_ready);
		isc_task_attach(task, &(isc_task_t *){ NULL });
	}
	INSIST(task->state == task_state_ready ||
	       task->state == task_state_running);
	ENQUEUE(task->events, event, ev_link);

	return (was_idle);
}

void
isc_task_send(isc_task_t *task, isc_event_t **eventp) {
	bool was_idle;

	/*
	 * Send '*event' to 'task'.
	 */

	REQUIRE(VALID_TASK(task));
	XTRACE("isc_task_send");

	/*
	 * We're trying hard to hold locks for as short a time as possible.
	 * We're also trying to hold as few locks as possible.  This is why
	 * some processing is deferred until after the lock is released.
	 */
	LOCK(&task->lock);
	was_idle = task_send(task, eventp);
	UNLOCK(&task->lock);

	if (was_idle) {
		/*
		 * We need to add this task to the ready queue.
		 *
		 * We've waited until now to do it because making a task
		 * ready requires locking the manager.  If we tried to do
		 * this while holding the task lock, we could deadlock.
		 *
		 * We've changed the state to ready, so no one else will
		 * be trying to add this task to the ready queue.  The
		 * only way to leave the ready state is by executing the
		 * task.  It thus doesn't matter if events are added,
		 * removed, or a shutdown is started in the interval
		 * between the time we released the task lock, and the time
		 * we add the task to the ready queue.
		 */
		task_ready(task);
	}
}

void
isc_task_sendanddetach(isc_task_t **taskp, isc_event_t **eventp) {
	isc_task_t *task = NULL;

	REQUIRE(taskp != NULL);

	task = *taskp;
	*taskp = NULL;

	REQUIRE(VALID_TASK(task));
	XTRACE("isc_task_sendanddetach");

	isc_task_send(task, eventp);
	isc_task_detach(&task);
}

void
isc_task_setname(isc_task_t *task, const char *name, void *tag) {
	/*
	 * Name 'task'.
	 */

	REQUIRE(VALID_TASK(task));

	LOCK(&task->lock);
	strlcpy(task->name, name, sizeof(task->name));
	task->tag = tag;
	UNLOCK(&task->lock);
}

isc_loopmgr_t *
isc_task_getloopmgr(isc_task_t *task) {
	REQUIRE(VALID_TASK(task));

	return (task->manager->loopmgr);
}

const char *
isc_task_getname(isc_task_t *task) {
	REQUIRE(VALID_TASK(task));

	return (task->name);
}

void *
isc_task_gettag(isc_task_t *task) {
	REQUIRE(VALID_TASK(task));

	return (task->tag);
}

/***
 *** Task Manager.
 ***/

static isc_result_t
task_run(isc_task_t *task) {
	isc_event_t *event = NULL;
	isc_result_t result = ISC_R_UNSET;
	isc_eventlist_t events;

	REQUIRE(VALID_TASK(task));

	LOCK(&task->lock);

	ISC_LIST_INIT(events);
	ISC_LIST_MOVE(events, task->events);

	REQUIRE(task->state == task_state_ready);

	task_setstate(task, task_state_running);
	XTRACE("running");
	XTRACE(task->name);
	TIME_NOW(&task->tnow);
	task->now = isc_time_seconds(&task->tnow);
	UNLOCK(&task->lock);

	event = ISC_LIST_HEAD(events);
	while (event != NULL) {
		isc_event_t *next = ISC_LIST_NEXT(event, ev_link);
		ISC_LIST_UNLINK(events, event, ev_link);

		/*
		 * Execute the event action.
		 */
		XTRACE("execute action");
		XTRACE(task->name);
		if (event->ev_action != NULL) {
			(event->ev_action)(task, event);
		}
		XTRACE("execution complete");

		event = next;
	}

	LOCK(&task->lock);
	if (EMPTY(task->events)) {
		/*
		 * Nothing else to do for this task right now.
		 */
		XTRACE("empty");
		XTRACE("idling");
		task_setstate(task, task_state_idle);

		result = ISC_R_SUCCESS;
	} else {
		/*
		 * More tasks were scheduled.
		 */
		XTRACE("quantum");
		task_setstate(task, task_state_ready);
		result = ISC_R_QUOTA;
	}
	UNLOCK(&task->lock);

	if (result == ISC_R_SUCCESS) {
		isc_task_detach(&task);
	}

	return (result);
}

static void
taskmgr_destroy(isc_taskmgr_t *taskmgr) {
	taskmgr->magic = 0;

	for (size_t tid = 0; tid < taskmgr->nloops; tid++) {
		INSIST(EMPTY(taskmgr->tasks[tid]));
		isc_mutex_destroy(&taskmgr->locks[tid]);
	}

	isc_mem_put(taskmgr->mctx, taskmgr->tasks,
		    taskmgr->nloops * sizeof(taskmgr->tasks[0]));
	isc_mem_put(taskmgr->mctx, taskmgr->locks,
		    taskmgr->nloops * sizeof(taskmgr->locks[0]));

	isc_refcount_destroy(&taskmgr->references);
	isc_mutex_destroy(&taskmgr->lock);
	isc_mem_putanddetach(&taskmgr->mctx, taskmgr, sizeof(*taskmgr));
}

void
isc_taskmgr_attach(isc_taskmgr_t *source, isc_taskmgr_t **targetp) {
	REQUIRE(VALID_TASKMGR(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);

	*targetp = source;
}

void
isc_taskmgr_detach(isc_taskmgr_t **managerp) {
	REQUIRE(managerp != NULL);
	REQUIRE(VALID_TASKMGR(*managerp));

	isc_taskmgr_t *manager = *managerp;
	*managerp = NULL;

	if (isc_refcount_decrement(&manager->references) == 1) {
		taskmgr_destroy(manager);
	}
}

static void
taskmgr_teardown(void *arg) {
	isc_taskmgr_t *taskmgr = (void *)arg;
	uint32_t tid = isc_tid();
	isc_task_t *excl = NULL;

	REQUIRE(VALID_TASKMGR(taskmgr));

	atomic_store(&taskmgr->shuttingdown, true);

	isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_NETMGR,
		      ISC_LOG_DEBUG(1), "Shutting down task manager");

	LOCK(&taskmgr->lock);
	if (taskmgr->excl != NULL && taskmgr->excl->tid == tid) {
		XTTRACE(taskmgr->excl, "taskmgr_teardown: excl");
		excl = taskmgr->excl;
		taskmgr->excl = NULL;
	}
	UNLOCK(&taskmgr->lock);
	if (excl != NULL) {
		isc_task_detach(&excl);
	}
}

void
isc_taskmgr_create(isc_mem_t *mctx, isc_loopmgr_t *loopmgr,
		   isc_taskmgr_t **taskmgrp) {
	isc_taskmgr_t *taskmgr = NULL;

	/*
	 * Create a new task manager.
	 */

	REQUIRE(taskmgrp != NULL && *taskmgrp == NULL);

	taskmgr = isc_mem_get(mctx, sizeof(*taskmgr));
	*taskmgr = (isc_taskmgr_t){
		.loopmgr = loopmgr,
		.magic = TASK_TASKMGR_MAGIC,
		.nloops = isc_loopmgr_nloops(loopmgr),
	};

	isc_mem_attach(mctx, &taskmgr->mctx);

	isc_mutex_init(&taskmgr->lock);

	taskmgr->tasks = isc_mem_get(
		taskmgr->mctx, taskmgr->nloops * sizeof(taskmgr->tasks[0]));
	taskmgr->locks = isc_mem_get(
		taskmgr->mctx, taskmgr->nloops * sizeof(taskmgr->locks[0]));

	for (size_t tid = 0; tid < taskmgr->nloops; tid++) {
		isc_mutex_init(&taskmgr->locks[tid]);
		ISC_LIST_INIT(taskmgr->tasks[tid]);
	}

	isc_loopmgr_teardown(loopmgr, taskmgr_teardown, taskmgr);

	isc_refcount_init(&taskmgr->references, 1);

	*taskmgrp = taskmgr;
}

void
isc_taskmgr_destroy(isc_taskmgr_t **managerp) {
	isc_taskmgr_t *manager = NULL;
	uint_fast32_t refs;

	REQUIRE(managerp != NULL && VALID_TASKMGR(*managerp));
	XTHREADTRACE("isc_taskmgr_destroy");

	manager = *managerp;
	*managerp = NULL;

	/*
	 * The isc_loopmgr is not running, there's nothing that can finish now
	 */
	refs = isc_refcount_decrement(&manager->references);
#if TASKMGR_TRACE
	if (refs > 1) {
		isc__taskmgr_dump_active(*managerp);
	}
#endif
	INSIST(refs == 1);
	taskmgr_destroy(manager);
}

void
isc_taskmgr_setexcltask(isc_taskmgr_t *mgr, isc_task_t *task) {
	REQUIRE(VALID_TASKMGR(mgr));
	REQUIRE(VALID_TASK(task));

	LOCK(&task->lock);
	REQUIRE(task->tid == 0);
	UNLOCK(&task->lock);

	LOCK(&mgr->lock);
	if (mgr->excl != NULL) {
		isc_task_detach(&mgr->excl);
	}
	isc_task_attach(task, &mgr->excl);
	UNLOCK(&mgr->lock);
}

isc_result_t
isc_taskmgr_excltask(isc_taskmgr_t *mgr, isc_task_t **taskp) {
	isc_result_t result;

	REQUIRE(VALID_TASKMGR(mgr));
	REQUIRE(taskp != NULL && *taskp == NULL);

	if (atomic_load(&mgr->shuttingdown)) {
		return (ISC_R_SHUTTINGDOWN);
	}

	LOCK(&mgr->lock);
	if (mgr->excl != NULL) {
		isc_task_attach(mgr->excl, taskp);
		result = ISC_R_SUCCESS;
	} else {
		result = ISC_R_NOTFOUND;
	}
	UNLOCK(&mgr->lock);

	return (result);
}

void
isc_task_beginexclusive(isc_task_t *task) {
	isc_taskmgr_t *manager;
	bool first;

	REQUIRE(VALID_TASK(task));

	manager = task->manager;

	REQUIRE(task->state == task_state_running);

	LOCK(&manager->lock);
	REQUIRE(task == manager->excl ||
		(atomic_load(&manager->shuttingdown) && manager->excl == NULL));
	first = (manager->exclusive_req++ == 0);
	UNLOCK(&manager->lock);

	if (!first) {
		return;
	}

	if (isc_log_wouldlog(isc_lctx, ISC_LOG_DEBUG(1))) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(1),
			      "exclusive task mode: %s", "starting");
	}

	isc_loopmgr_pause(manager->loopmgr);

	if (isc_log_wouldlog(isc_lctx, ISC_LOG_DEBUG(1))) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(1),
			      "exclusive task mode: %s", "started");
	}
}

void
isc_task_endexclusive(isc_task_t *task) {
	isc_taskmgr_t *manager = NULL;
	bool last;

	REQUIRE(VALID_TASK(task));
	REQUIRE(task->state == task_state_running);

	manager = task->manager;

	LOCK(&manager->lock);
	INSIST(manager->exclusive_req > 0);
	last = (--manager->exclusive_req == 0);
	UNLOCK(&manager->lock);

	if (!last) {
		return;
	}

	if (isc_log_wouldlog(isc_lctx, ISC_LOG_DEBUG(1))) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(1),
			      "exclusive task mode: %s", "ending");
	}

	isc_loopmgr_resume(manager->loopmgr);

	if (isc_log_wouldlog(isc_lctx, ISC_LOG_DEBUG(1))) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(1),
			      "exclusive task mode: %s", "ended");
	}
}

#ifdef HAVE_LIBXML2
#define TRY0(a)                     \
	do {                        \
		xmlrc = (a);        \
		if (xmlrc < 0)      \
			goto error; \
	} while (0)
int
isc_taskmgr_renderxml(isc_taskmgr_t *mgr, void *writer0) {
	isc_task_t *task = NULL;
	int xmlrc;
	xmlTextWriterPtr writer = (xmlTextWriterPtr)writer0;

	LOCK(&mgr->lock);

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "tasks"));
	for (size_t tid = 0; tid < mgr->nloops; tid++) {
		for (task = ISC_LIST_HEAD(mgr->tasks[tid]); task != NULL;
		     task = ISC_LIST_NEXT(task, link))
		{
			LOCK(&task->lock);
			TRY0(xmlTextWriterStartElement(writer,
						       ISC_XMLCHAR "task"));

			if (task->name[0] != 0) {
				TRY0(xmlTextWriterStartElement(
					writer, ISC_XMLCHAR "name"));
				TRY0(xmlTextWriterWriteFormatString(
					writer, "%s", task->name));
				TRY0(xmlTextWriterEndElement(writer)); /* name
									*/
			}

			TRY0(xmlTextWriterStartElement(writer,
						       ISC_XMLCHAR "reference"
								   "s"));
			TRY0(xmlTextWriterWriteFormatString(
				writer, "%" PRIuFAST32,
				isc_refcount_current(&task->references)));
			TRY0(xmlTextWriterEndElement(writer)); /* references */

			TRY0(xmlTextWriterStartElement(writer,
						       ISC_XMLCHAR "id"));
			TRY0(xmlTextWriterWriteFormatString(writer, "%p",
							    task));
			TRY0(xmlTextWriterEndElement(writer)); /* id */

			TRY0(xmlTextWriterStartElement(writer,
						       ISC_XMLCHAR "state"));
			TRY0(xmlTextWriterWriteFormatString(
				writer, "%s", statenames[task->state]));
			TRY0(xmlTextWriterEndElement(writer)); /* state */

			TRY0(xmlTextWriterEndElement(writer));

			UNLOCK(&task->lock);
		}
	}
	TRY0(xmlTextWriterEndElement(writer)); /* tasks */

error:
	if (task != NULL) {
		UNLOCK(&task->lock);
	}
	UNLOCK(&mgr->lock);

	return (xmlrc);
}
#endif /* HAVE_LIBXML2 */

#ifdef HAVE_JSON_C
#define CHECKMEM(m)                              \
	do {                                     \
		if (m == NULL) {                 \
			result = ISC_R_NOMEMORY; \
			goto error;              \
		}                                \
	} while (0)

isc_result_t
isc_taskmgr_renderjson(isc_taskmgr_t *mgr, void *tasks0) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_task_t *task = NULL;
	json_object *obj = NULL, *array = NULL, *taskobj = NULL;
	json_object *tasks = (json_object *)tasks0;

	LOCK(&mgr->lock);

	array = json_object_new_array();
	CHECKMEM(array);

	for (size_t tid = 0; tid < mgr->nloops; tid++) {
		for (task = ISC_LIST_HEAD(mgr->tasks[tid]); task != NULL;
		     task = ISC_LIST_NEXT(task, link))
		{
			char buf[255];

			LOCK(&task->lock);

			taskobj = json_object_new_object();
			CHECKMEM(taskobj);
			json_object_array_add(array, taskobj);

			snprintf(buf, sizeof(buf), "%p", task);
			obj = json_object_new_string(buf);
			CHECKMEM(obj);
			json_object_object_add(taskobj, "id", obj);

			if (task->name[0] != 0) {
				obj = json_object_new_string(task->name);
				CHECKMEM(obj);
				json_object_object_add(taskobj, "name", obj);
			}

			obj = json_object_new_int(
				isc_refcount_current(&task->references));
			CHECKMEM(obj);
			json_object_object_add(taskobj, "references", obj);

			obj = json_object_new_string(statenames[task->state]);
			CHECKMEM(obj);
			json_object_object_add(taskobj, "state", obj);

			UNLOCK(&task->lock);
		}
	}

	json_object_object_add(tasks, "tasks", array);
	array = NULL;
	result = ISC_R_SUCCESS;

error:
	if (array != NULL) {
		json_object_put(array);
	}

	if (task != NULL) {
		UNLOCK(&task->lock);
	}
	UNLOCK(&mgr->lock);

	return (result);
}
#endif /* ifdef HAVE_JSON_C */

#if TASKMGR_TRACE

static void
event_dump(isc_event_t *event) {
	fprintf(stderr, "  - event: %p\n", event);
	fprintf(stderr, "    func: %s\n", event->func);
	fprintf(stderr, "    file: %s\n", event->file);
	fprintf(stderr, "    line: %u\n", event->line);
	fprintf(stderr, "    backtrace: |\n");
	isc_backtrace_symbols_fd(event->backtrace, event->backtrace_size,
				 STDERR_FILENO);
}

static void
task_dump(isc_task_t *task) {
	LOCK(&task->lock);
	fprintf(stderr, "- task: %p\n", task);
	fprintf(stderr, "  tid: %" PRIu32 "\n", task->tid);
	fprintf(stderr, "  nevents: %u\n", task->nevents);
	fprintf(stderr, "    func: %s\n", task->func);
	fprintf(stderr, "    file: %s\n", task->file);
	fprintf(stderr, "    line: %u\n", task->line);
	fprintf(stderr, "  backtrace: |\n");
	isc_backtrace_symbols_fd(task->backtrace, task->backtrace_size,
				 STDERR_FILENO);
	fprintf(stderr, "\n");

	for (isc_event_t *event = ISC_LIST_HEAD(task->events); event != NULL;
	     event = ISC_LIST_NEXT(event, ev_link))
	{
		event_dump(event);
	}

	UNLOCK(&task->lock);
}

void
isc__taskmgr_dump_active(isc_taskmgr_t *taskmgr) {
	LOCK(&taskmgr->lock);
	fprintf(stderr, "- taskmgr: %p\n", taskmgr);

	for (size_t tid = 0; tid < taskmgr->nloops; tid++) {
		for (isc_task_t *task = ISC_LIST_HEAD(taskmgr->tasks[tid]);
		     task != NULL; task = ISC_LIST_NEXT(task, link))
		{
			task_dump(task);
		}
	}

	UNLOCK(&taskmgr->lock);
}

#endif
