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

/*
 * XXXRTH  Need to document the states a task can be in, and the rules
 * for changing states.
 */

#include <stdbool.h>
#include <unistd.h>

#include <isc/app.h>
#include <isc/atomic.h>
#include <isc/backtrace.h>
#include <isc/condition.h>
#include <isc/event.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/thread.h>
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

#include "task_p.h"

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
#define XTRACE(m) \
	fprintf(stderr, "task %p thread %zu: %s\n", task, isc_tid_v, (m))
#define XTTRACE(t, m) \
	fprintf(stderr, "task %p thread %zu: %s\n", (t), isc_tid_v, (m))
#define XTHREADTRACE(m) fprintf(stderr, "thread %zu: %s\n", isc_tid_v, (m))
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
	int tid;
	task_state_t state;
	isc_refcount_t references;
	isc_eventlist_t events;
	unsigned int nevents;
	unsigned int quantum;
	isc_stdtime_t now;
	isc_time_t tnow;
	char name[16];
	void *tag;
	/* Protected by atomics */
	atomic_bool shuttingdown;
	/* Locked by task manager lock. */
#if TASKMGR_TRACE
	char func[PATH_MAX];
	char file[PATH_MAX];
	unsigned int line;
	void *backtrace[ISC__TASKTRACE_SIZE];
	int backtrace_size;
#endif
	LINK(isc_task_t) link;
};

#define TASK_MANAGER_MAGIC ISC_MAGIC('T', 'S', 'K', 'M')
#define VALID_MANAGER(m)   ISC_MAGIC_VALID(m, TASK_MANAGER_MAGIC)

struct isc_taskmgr {
	/* Not locked. */
	unsigned int magic;
	isc_refcount_t references;
	isc_mem_t *mctx;
	isc_mutex_t lock;
	atomic_uint_fast32_t tasks_count;
	isc_nm_t *netmgr;
	uint32_t nworkers;

	/* Locked by task manager lock. */
	unsigned int default_quantum;
	LIST(isc_task_t) tasks;
	atomic_uint_fast32_t mode;
	atomic_bool exclusive_req;
	bool exiting;
	isc_task_t *excl;
};

#define DEFAULT_DEFAULT_QUANTUM 25

/*%
 * The following are intended for internal use (indicated by "isc__"
 * prefix) but are not declared as static, allowing direct access from
 * unit tests etc.
 */

bool
isc_task_purgeevent(isc_task_t *task, isc_event_t *event);
void
isc_taskmgr_setexcltask(isc_taskmgr_t *mgr, isc_task_t *task);
isc_result_t
isc_taskmgr_excltask(isc_taskmgr_t *mgr, isc_task_t **taskp);

/***
 *** Tasks.
 ***/

static void
task_destroy(isc_task_t *task) {
	isc_taskmgr_t *manager = task->manager;
	isc_mem_t *mctx = manager->mctx;
	REQUIRE(EMPTY(task->events));
	REQUIRE(task->nevents == 0);
	REQUIRE(task->state == task_state_done);

	XTRACE("task_finished");

	isc_refcount_destroy(&task->references);

	LOCK(&manager->lock);
	UNLINK(manager->tasks, task, link);
	atomic_fetch_sub(&manager->tasks_count, 1);
	UNLOCK(&manager->lock);

	isc_mutex_destroy(&task->lock);
	task->magic = 0;
	isc_mem_put(mctx, task, sizeof(*task));

	isc_taskmgr_detach(&manager);
}

isc_result_t
isc__task_create(isc_taskmgr_t *manager, unsigned int quantum,
		 isc_task_t **taskp, int tid ISC__TASKFLARG) {
	isc_task_t *task = NULL;
	bool exiting;

	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(taskp != NULL && *taskp == NULL);
	REQUIRE(tid >= 0 && tid < (int)manager->nworkers);

	XTRACE("isc_task_create");

	task = isc_mem_get(manager->mctx, sizeof(*task));
	*task = (isc_task_t){
		.state = task_state_idle,
		.tid = tid,
	};

#if TASKMGR_TRACE
	strlcpy(task->func, func, sizeof(task->func));
	strlcpy(task->file, file, sizeof(task->file));
	task->line = line;
	task->backtrace_size = isc_backtrace(task->backtrace,
					     ISC__TASKTRACE_SIZE);
#endif

	isc_taskmgr_attach(manager, &task->manager);

	isc_mutex_init(&task->lock);

	isc_refcount_init(&task->references, 1);
	INIT_LIST(task->events);
	task->quantum = (quantum > 0) ? quantum : manager->default_quantum;
	atomic_init(&task->shuttingdown, false);
	isc_time_settoepoch(&task->tnow);
	memset(task->name, 0, sizeof(task->name));
	INIT_LINK(task, link);
	task->magic = TASK_MAGIC;

	LOCK(&manager->lock);
	exiting = manager->exiting;
	if (!exiting) {
		APPEND(manager->tasks, task, link);
		atomic_fetch_add(&manager->tasks_count, 1);
	}
	UNLOCK(&manager->lock);

	if (exiting) {
		isc_refcount_decrement(&task->references);
		isc_refcount_destroy(&task->references);
		isc_mutex_destroy(&task->lock);
		isc_taskmgr_detach(&task->manager);
		isc_mem_put(manager->mctx, task, sizeof(*task));
		return (ISC_R_SHUTTINGDOWN);
	}

	*taskp = task;

	return (ISC_R_SUCCESS);
}

void
isc_task_attach(isc_task_t *source, isc_task_t **targetp) {
	/*
	 * Attach *targetp to source.
	 */

	REQUIRE(VALID_TASK(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	XTTRACE(source, "isc_task_attach");

	isc_refcount_increment(&source->references);

	*targetp = source;
}

/*
 * Moves a task onto the appropriate run queue.
 *
 * Caller must NOT hold queue lock.
 */
static void
task_ready(isc_task_t *task) {
	isc_taskmgr_t *manager = task->manager;
	REQUIRE(VALID_MANAGER(manager));

	XTRACE("task_ready");

	isc_task_attach(task, &(isc_task_t *){ NULL });
	LOCK(&task->lock);
	isc_nm_task_enqueue(manager->netmgr, task, task->tid);
	UNLOCK(&task->lock);
}

void
isc_task_ready(isc_task_t *task) {
	task_ready(task);
}

void
isc_task_detach(isc_task_t **taskp) {
	isc_task_t *task;

	REQUIRE(taskp != NULL);
	REQUIRE(VALID_TASK(*taskp));

	task = *taskp;
	*taskp = NULL;

	XTRACE("isc_task_detach");

	if (isc_refcount_decrement(&task->references) == 1) {
		LOCK(&task->lock);
		task->state = task_state_done;
		UNLOCK(&task->lock);

		task_destroy(task);
	}
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
	REQUIRE(event->ev_type > 0);
	REQUIRE(task->state != task_state_done);
	REQUIRE(!ISC_LINK_LINKED(event, ev_ratelink));

	XTRACE("task_send");

	if (task->state == task_state_idle) {
		was_idle = true;
		INSIST(EMPTY(task->events));
		task->state = task_state_ready;
	}
	INSIST(task->state == task_state_ready ||
	       task->state == task_state_running);
	ENQUEUE(task->events, event, ev_link);
	task->nevents++;

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
	isc_task_t *task;

	REQUIRE(taskp != NULL);
	task = *taskp;
	*taskp = NULL;
	REQUIRE(VALID_TASK(task));
	XTRACE("isc_task_sendanddetach");

	isc_task_send(task, eventp);
	isc_task_detach(&task);
}

bool
isc_task_purgeevent(isc_task_t *task, isc_event_t *event) {
	bool found = false;

	/*
	 * Purge 'event' from a task's event queue.
	 */

	REQUIRE(VALID_TASK(task));

	/*
	 * If 'event' is on the task's event queue, it will be purged, 'event'
	 * does not have to be on the task's event queue; in fact, it can even
	 * be an invalid pointer.  Purging only occurs if the event is actually
	 * on the task's event queue.
	 *
	 * Purging never changes the state of the task.
	 */

	LOCK(&task->lock);
	if (ISC_LINK_LINKED(event, ev_link)) {
		DEQUEUE(task->events, event, ev_link);
		task->nevents--;
		found = true;
	}
	UNLOCK(&task->lock);

	if (!found) {
		return (false);
	}

	isc_event_free(&event);

	return (true);
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

isc_nm_t *
isc_task_getnetmgr(isc_task_t *task) {
	REQUIRE(VALID_TASK(task));

	return (task->manager->netmgr);
}

void
isc_task_setquantum(isc_task_t *task, unsigned int quantum) {
	REQUIRE(VALID_TASK(task));

	LOCK(&task->lock);
	task->quantum = (quantum > 0) ? quantum
				      : task->manager->default_quantum;
	UNLOCK(&task->lock);
}

/***
 *** Task Manager.
 ***/

static isc_result_t
task_run(isc_task_t *task) {
	unsigned int dispatch_count = 0;
	isc_event_t *event = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	uint32_t quantum;

	REQUIRE(VALID_TASK(task));

	LOCK(&task->lock);
	quantum = task->quantum;

	if (task->state != task_state_ready) {
		goto done;
	}

	INSIST(task->state == task_state_ready);
	task->state = task_state_running;
	XTRACE("running");
	XTRACE(task->name);
	TIME_NOW(&task->tnow);
	task->now = isc_time_seconds(&task->tnow);

	while (true) {
		if (!EMPTY(task->events)) {
			event = HEAD(task->events);
			DEQUEUE(task->events, event, ev_link);
			task->nevents--;

			/*
			 * Execute the event action.
			 */
			XTRACE("execute action");
			XTRACE(task->name);
			if (event->ev_action != NULL) {
				UNLOCK(&task->lock);
				(event->ev_action)(task, event);
				LOCK(&task->lock);
			}
			XTRACE("execution complete");
			dispatch_count++;
		}

		if (EMPTY(task->events)) {
			/*
			 * Nothing else to do for this task right now.
			 */
			XTRACE("empty");
			if (isc_refcount_current(&task->references) == 0) {
				/*
				 * The task is done.
				 */
				XTRACE("done");
				task->state = task_state_done;
			} else if (task->state == task_state_running) {
				XTRACE("idling");
				task->state = task_state_idle;
			}
			break;
		} else if (dispatch_count >= quantum) {
			/*
			 * Our quantum has expired, but there is more work to be
			 * done.  We'll requeue it to the ready queue later.
			 *
			 * We don't check quantum until dispatching at least one
			 * event, so the minimum quantum is one.
			 */
			XTRACE("quantum");
			task->state = task_state_ready;
			result = ISC_R_QUOTA;
			break;
		}
	}

done:
	UNLOCK(&task->lock);
	isc_task_detach(&task);

	return (result);
}

isc_result_t
isc_task_run(isc_task_t *task) {
	return (task_run(task));
}

static void
manager_free(isc_taskmgr_t *manager) {
	isc_refcount_destroy(&manager->references);
	isc_nm_detach(&manager->netmgr);

	isc_mutex_destroy(&manager->lock);
	manager->magic = 0;
	isc_mem_putanddetach(&manager->mctx, manager, sizeof(*manager));
}

void
isc_taskmgr_attach(isc_taskmgr_t *source, isc_taskmgr_t **targetp) {
	REQUIRE(VALID_MANAGER(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);

	*targetp = source;
}

void
isc_taskmgr_detach(isc_taskmgr_t **managerp) {
	REQUIRE(managerp != NULL);
	REQUIRE(VALID_MANAGER(*managerp));

	isc_taskmgr_t *manager = *managerp;
	*managerp = NULL;

	if (isc_refcount_decrement(&manager->references) == 1) {
		manager_free(manager);
	}
}

isc_result_t
isc__taskmgr_create(isc_mem_t *mctx, unsigned int default_quantum, isc_nm_t *nm,
		    isc_taskmgr_t **managerp) {
	isc_taskmgr_t *manager;

	/*
	 * Create a new task manager.
	 */

	REQUIRE(managerp != NULL && *managerp == NULL);
	REQUIRE(nm != NULL);

	manager = isc_mem_get(mctx, sizeof(*manager));
	*manager = (isc_taskmgr_t){ .magic = TASK_MANAGER_MAGIC };

	isc_mutex_init(&manager->lock);

	if (default_quantum == 0) {
		default_quantum = DEFAULT_DEFAULT_QUANTUM;
	}
	manager->default_quantum = default_quantum;

	isc_nm_attach(nm, &manager->netmgr);
	manager->nworkers = isc_nm_getnworkers(nm);

	INIT_LIST(manager->tasks);
	atomic_init(&manager->exclusive_req, false);
	atomic_init(&manager->tasks_count, 0);

	isc_mem_attach(mctx, &manager->mctx);

	isc_refcount_init(&manager->references, 1);

	*managerp = manager;

	return (ISC_R_SUCCESS);
}

void
isc__taskmgr_shutdown(isc_taskmgr_t *manager) {
	isc_task_t *task = NULL;

	REQUIRE(VALID_MANAGER(manager));

	XTHREADTRACE("isc_taskmgr_shutdown");
	/*
	 * Only one non-worker thread may ever call this routine.
	 * If a worker thread wants to initiate shutdown of the
	 * task manager, it should ask some non-worker thread to call
	 * isc_taskmgr_destroy(), e.g. by signalling a condition variable
	 * that the startup thread is sleeping on.
	 */
	LOCK(&manager->lock);
	if (manager->excl != NULL) {
		task = manager->excl;
		manager->excl = NULL;
	}

	/*
	 * Make sure we only get called once.
	 */
	INSIST(manager->exiting == false);
	manager->exiting = true;

	UNLOCK(&manager->lock);

	if (task != NULL) {
		isc_task_detach(&task);
	}
}

void
isc__taskmgr_destroy(isc_taskmgr_t **managerp) {
	REQUIRE(managerp != NULL && VALID_MANAGER(*managerp));
	XTHREADTRACE("isc_taskmgr_destroy");
	int counter = 0;

	while (isc_refcount_current(&(*managerp)->references) > 1 &&
	       counter++ < 1000) {
		uv_sleep(10);
	}

#if TASKMGR_TRACE
	if (isc_refcount_current(&(*managerp)->references) > 1) {
		isc__taskmgr_dump_active(*managerp);
	}
	INSIST(isc_refcount_current(&(*managerp)->references) == 1);
#endif

	while (isc_refcount_current(&(*managerp)->references) > 1) {
		uv_sleep(10);
	}

	isc_taskmgr_detach(managerp);
}

void
isc_taskmgr_setexcltask(isc_taskmgr_t *mgr, isc_task_t *task) {
	REQUIRE(VALID_MANAGER(mgr));
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

	REQUIRE(VALID_MANAGER(mgr));
	REQUIRE(taskp != NULL && *taskp == NULL);

	LOCK(&mgr->lock);
	if (mgr->excl != NULL) {
		isc_task_attach(mgr->excl, taskp);
		result = ISC_R_SUCCESS;
	} else if (mgr->exiting) {
		result = ISC_R_SHUTTINGDOWN;
	} else {
		result = ISC_R_NOTFOUND;
	}
	UNLOCK(&mgr->lock);

	return (result);
}

isc_result_t
isc_task_beginexclusive(isc_task_t *task) {
	isc_taskmgr_t *manager;

	REQUIRE(VALID_TASK(task));

	manager = task->manager;

	REQUIRE(task->state == task_state_running);

	LOCK(&manager->lock);
	REQUIRE(task == manager->excl ||
		(manager->exiting && manager->excl == NULL));
	UNLOCK(&manager->lock);

	if (!atomic_compare_exchange_strong(&manager->exclusive_req,
					    &(bool){ false }, true))
	{
		return (ISC_R_LOCKBUSY);
	}

	if (isc_log_wouldlog(isc_lctx, ISC_LOG_DEBUG(1))) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(1),
			      "exclusive task mode: %s", "starting");
	}

	isc_nm_pause(manager->netmgr);

	if (isc_log_wouldlog(isc_lctx, ISC_LOG_DEBUG(1))) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(1),
			      "exclusive task mode: %s", "started");
	}

	return (ISC_R_SUCCESS);
}

void
isc_task_endexclusive(isc_task_t *task) {
	isc_taskmgr_t *manager = NULL;

	REQUIRE(VALID_TASK(task));
	REQUIRE(task->state == task_state_running);

	manager = task->manager;

	if (isc_log_wouldlog(isc_lctx, ISC_LOG_DEBUG(1))) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(1),
			      "exclusive task mode: %s", "ending");
	}

	isc_nm_resume(manager->netmgr);

	if (isc_log_wouldlog(isc_lctx, ISC_LOG_DEBUG(1))) {
		isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
			      ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(1),
			      "exclusive task mode: %s", "ended");
	}

	atomic_compare_exchange_enforced(&manager->exclusive_req,
					 &(bool){ true }, false);
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

	/*
	 * Write out the thread-model, and some details about each depending
	 * on which type is enabled.
	 */
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "thread-model"));
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "type"));
	TRY0(xmlTextWriterWriteString(writer, ISC_XMLCHAR "threaded"));
	TRY0(xmlTextWriterEndElement(writer)); /* type */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "default-quantum"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%d",
					    mgr->default_quantum));
	TRY0(xmlTextWriterEndElement(writer)); /* default-quantum */

	TRY0(xmlTextWriterEndElement(writer)); /* thread-model */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "tasks"));
	task = ISC_LIST_HEAD(mgr->tasks);
	while (task != NULL) {
		LOCK(&task->lock);
		TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "task"));

		if (task->name[0] != 0) {
			TRY0(xmlTextWriterStartElement(writer,
						       ISC_XMLCHAR "name"));
			TRY0(xmlTextWriterWriteFormatString(writer, "%s",
							    task->name));
			TRY0(xmlTextWriterEndElement(writer)); /* name */
		}

		TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "reference"
								   "s"));
		TRY0(xmlTextWriterWriteFormatString(
			writer, "%" PRIuFAST32,
			isc_refcount_current(&task->references)));
		TRY0(xmlTextWriterEndElement(writer)); /* references */

		TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "id"));
		TRY0(xmlTextWriterWriteFormatString(writer, "%p", task));
		TRY0(xmlTextWriterEndElement(writer)); /* id */

		TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "state"));
		TRY0(xmlTextWriterWriteFormatString(writer, "%s",
						    statenames[task->state]));
		TRY0(xmlTextWriterEndElement(writer)); /* state */

		TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "quantum"));
		TRY0(xmlTextWriterWriteFormatString(writer, "%d",
						    task->quantum));
		TRY0(xmlTextWriterEndElement(writer)); /* quantum */

		TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "events"));
		TRY0(xmlTextWriterWriteFormatString(writer, "%d",
						    task->nevents));
		TRY0(xmlTextWriterEndElement(writer)); /* events */

		TRY0(xmlTextWriterEndElement(writer));

		UNLOCK(&task->lock);
		task = ISC_LIST_NEXT(task, link);
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

	/*
	 * Write out the thread-model, and some details about each depending
	 * on which type is enabled.
	 */
	obj = json_object_new_string("threaded");
	CHECKMEM(obj);
	json_object_object_add(tasks, "thread-model", obj);

	obj = json_object_new_int(mgr->default_quantum);
	CHECKMEM(obj);
	json_object_object_add(tasks, "default-quantum", obj);

	array = json_object_new_array();
	CHECKMEM(array);

	for (task = ISC_LIST_HEAD(mgr->tasks); task != NULL;
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

		obj = json_object_new_int(task->quantum);
		CHECKMEM(obj);
		json_object_object_add(taskobj, "quantum", obj);

		obj = json_object_new_int(task->nevents);
		CHECKMEM(obj);
		json_object_object_add(taskobj, "events", obj);

		UNLOCK(&task->lock);
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

	for (isc_task_t *task = ISC_LIST_HEAD(taskmgr->tasks); task != NULL;
	     task = ISC_LIST_NEXT(task, link))
	{
		task_dump(task);
	}

	UNLOCK(&taskmgr->lock);
}

#endif
