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

/*
 * Principal Author: Bob Halley
 */

/*
 * XXXRTH  Need to document the states a task can be in, and the rules
 * for changing states.
 */

#include <config.h>

#include <isc/assertions.h>
#include <isc/boolean.h>
#include <isc/thread.h>
#include <isc/mutex.h>
#include <isc/condition.h>
#include <isc/error.h>
#include <isc/event.h>
#include <isc/task.h>

#include "util.h"

#ifdef ISC_TASK_TRACE
#define XTRACE(m)		printf("%s task %p thread %lu\n", (m), \
				       task, isc_thread_self())
#define XTHREADTRACE(m)		printf("%s thread %lu\n", (m), \
				       isc_thread_self())
#else
#define XTRACE(m)
#define XTHREADTRACE(m)
#endif

/***
 *** Types.
 ***/

typedef enum {
	task_state_idle, task_state_ready, task_state_running,
	task_state_done
} task_state_t;

#define TASK_MAGIC			0x5441534BU	/* TASK. */
#define VALID_TASK(t)			((t) != NULL && \
					 (t)->magic == TASK_MAGIC)

struct isc_task {
	/* Not locked. */
	unsigned int			magic;
	isc_taskmgr_t *			manager;
	isc_mutex_t			lock;
	isc_mem_t *			mctx;
	/* Locked by task lock. */
	task_state_t			state;
	unsigned int			references;
	isc_eventlist_t			events;
	isc_eventlist_t			on_shutdown;
	unsigned int			quantum;
	unsigned int			flags;
	/* Locked by task manager lock. */
	LINK(isc_task_t)		link;
	LINK(isc_task_t)		ready_link;
};

#define TASK_F_DONEOK			0x01
#define TASK_F_SENDOK			0x02
#define TASK_F_SHUTTINGDOWN		0x04

#define DONE_FLAGS			(TASK_F_DONEOK|TASK_F_SHUTTINGDOWN)
#define TASK_DONE(t)			(((t)->flags & DONE_FLAGS) == \
					 DONE_FLAGS)

#define TASK_MANAGER_MAGIC		0x54534B4DU	/* TSKM. */
#define VALID_MANAGER(m)		((m) != NULL && \
					 (m)->magic == TASK_MANAGER_MAGIC)

struct isc_taskmgr {
	/* Not locked. */
	unsigned int			magic;
	isc_mem_t *			mctx;
	isc_mutex_t			lock;
	unsigned int			workers;
	isc_thread_t *			threads;
	/* Locked by task manager lock. */
	unsigned int			default_quantum;
	LIST(isc_task_t)		tasks;
	LIST(isc_task_t)		ready_tasks;
	isc_condition_t			work_available;
	isc_boolean_t			exiting;
};

#define DEFAULT_DEFAULT_QUANTUM		5
#define FINISHED(m)			((m)->exiting && EMPTY((m)->tasks))


/***
 *** Tasks.
 ***/

static void
task_free(isc_task_t *task) {
	isc_taskmgr_t *manager = task->manager;

	XTRACE("free task");
	REQUIRE(EMPTY(task->events));
	REQUIRE(EMPTY(task->on_shutdown));

	LOCK(&manager->lock);
	UNLINK(manager->tasks, task, link);
	if (FINISHED(manager)) {
		/*
		 * All tasks have completed and the
		 * task manager is exiting.  Wake up
		 * any idle worker threads so they
		 * can exit.
		 */
		BROADCAST(&manager->work_available);
	}
	UNLOCK(&manager->lock);
	(void)isc_mutex_destroy(&task->lock);
	task->magic = 0;
	isc_mem_put(task->mctx, task, sizeof *task);
}

isc_result_t
isc_task_create(isc_taskmgr_t *manager, isc_mem_t *mctx, unsigned int quantum,
		isc_task_t **taskp)
{
	isc_task_t *task;

	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(taskp != NULL && *taskp == NULL);

	if (mctx == NULL)
		mctx = manager->mctx;
	task = isc_mem_get(mctx, sizeof *task);
	if (task == NULL)
		return (ISC_R_NOMEMORY);
	task->manager = manager;
	task->mctx = mctx;
	if (isc_mutex_init(&task->lock) != ISC_R_SUCCESS) {
		isc_mem_put(mctx, task, sizeof *task);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed");
		return (ISC_R_UNEXPECTED);
	}
	task->state = task_state_idle;
	task->references = 1;
	INIT_LIST(task->events);
	INIT_LIST(task->on_shutdown);
	task->quantum = quantum;
	task->flags = (TASK_F_DONEOK|TASK_F_SENDOK);
	INIT_LINK(task, link);
	INIT_LINK(task, ready_link);

	LOCK(&manager->lock);
	/* XXX Should disallow if task manager is exiting. */
	if (task->quantum == 0)
		task->quantum = manager->default_quantum;
	APPEND(manager->tasks, task, link);
	UNLOCK(&manager->lock);

	task->magic = TASK_MAGIC;
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

	LOCK(&source->lock);
	source->references++;
	UNLOCK(&source->lock);

	*targetp = source;
}

void
isc_task_detach(isc_task_t **taskp) {
	isc_boolean_t free_task = ISC_FALSE;
	isc_task_t *task;

	/*
	 * Detach *taskp from its task.
	 */

	REQUIRE(taskp != NULL);
	task = *taskp;
	REQUIRE(VALID_TASK(task));

	XTRACE("isc_task_detach");

	LOCK(&task->lock);
	REQUIRE(task->references > 0);
	task->references--;
	if (task->state == task_state_done && task->references == 0)
		free_task = ISC_TRUE;
	/*
	 * XXXRTH  It is currently possible to detach the last
	 * reference from a task that has not been shutdown.  This
	 * will prevent the task from being shutdown until the
	 * task manager is destroyed.  Should there be an
	 * automatic shutdown on last detach?
	 */
	UNLOCK(&task->lock);

	if (free_task)
		task_free(task);

	*taskp = NULL;
}

isc_mem_t *
isc_task_mem(isc_task_t *task) {

	/*
	 * Get the task's memory context.
	 */

	REQUIRE(VALID_TASK(task));
	
	return (task->mctx);
}

isc_result_t
isc_task_send(isc_task_t *task, isc_event_t **eventp) {
	isc_boolean_t was_idle = ISC_FALSE;
	isc_boolean_t disallowed = ISC_FALSE;
	isc_result_t result = ISC_R_SUCCESS;
	isc_event_t *event;

	/*
	 * Send '*event' to 'task'.
	 */

	REQUIRE(VALID_TASK(task));
	REQUIRE(eventp != NULL);
	event = *eventp;
	REQUIRE(event != NULL);
	REQUIRE(event->sender != NULL);
	REQUIRE(event->type > 0);

	XTRACE("sending");
	/*
	 * We're trying hard to hold locks for as short a time as possible.
	 * We're also trying to hold as few locks as possible.  This is why
	 * some processing is deferred until after a lock is released.
	 */
	LOCK(&task->lock);
	/*
	 * Note: we require that task->state == task_state_done implies
	 * (task->flags & TASK_F_SENDOK) == 0.
	 */
	if ((task->flags & TASK_F_SENDOK) != 0) {
		if (task->state == task_state_idle) {
			was_idle = ISC_TRUE;
			INSIST(EMPTY(task->events));
			task->state = task_state_ready;
		}
		INSIST(task->state == task_state_ready ||
		       task->state == task_state_running);
		ENQUEUE(task->events, event, link);
	} else {
		disallowed = ISC_TRUE;
		if (task->state == task_state_done)
			result = ISC_R_TASKDONE;
		else
			result = ISC_R_TASKNOSEND;
	}
	UNLOCK(&task->lock);

	if (disallowed)
		return (result);

	if (was_idle) {
		isc_taskmgr_t *manager;

		/*
		 * We need to add this task to the ready queue.
		 *
		 * We've waited until now to do it, rather than doing it
		 * while holding the task lock, because we don't want to
		 * block while holding the task lock.
		 *
		 * We've changed the state to ready, so no one else will
		 * be trying to add this task to the ready queue.  The
		 * only way to leave the ready state is by executing the
		 * task.  It thus doesn't matter if events are added,
		 * removed, or shutting_down is started in the interval
		 * between the time we released the task lock, and the time
		 * we add the task to the ready queue.
		 */
		manager = task->manager;
		INSIST(VALID_MANAGER(manager));
		LOCK(&manager->lock);
		ENQUEUE(manager->ready_tasks, task, ready_link);
		SIGNAL(&manager->work_available);
		UNLOCK(&manager->lock);
	}

	*eventp = NULL;

	XTRACE("sent");

	return (ISC_R_SUCCESS);
}

unsigned int
isc_task_purgerange(isc_task_t *task, void *sender, isc_eventtype_t first,
		    isc_eventtype_t last)
{
	isc_event_t *event, *next_event;
	isc_eventlist_t purgeable;
	unsigned int purge_count;

	/*
	 * Purge events from a task's event queue.
	 */

	REQUIRE(VALID_TASK(task));
	REQUIRE(last >= first);

	/*
	 * Events matching 'sender' and whose type is >= first and
	 * <= last will be purged.  sender == NULL means "any sender".
	 *
	 * Purging never changes the state of the task.
	 */

	INIT_LIST(purgeable);
	purge_count = 0;

	LOCK(&task->lock);
	for (event = HEAD(task->events);
	     event != NULL;
	     event = next_event) {
		next_event = NEXT(event, link);
		if ((sender == NULL || event->sender == sender) &&
		    event->type >= first && event->type <= last) {
			DEQUEUE(task->events, event, link);
			ENQUEUE(purgeable, event, link);
		}
	}
	UNLOCK(&task->lock);

	for (event = HEAD(purgeable);
	     event != NULL;
	     event = next_event) {
		next_event = NEXT(event, link);
		isc_event_free(&event);
		purge_count++;
	}

	return (purge_count);
}

unsigned int
isc_task_purge(isc_task_t *task, void *sender, isc_eventtype_t type) {

	/*
	 * Purge events from a task's event queue.
	 */

	return (isc_task_purgerange(task, sender, type, type));
}

isc_result_t
isc_task_allowsend(isc_task_t *task, isc_boolean_t allowed) {
	isc_result_t result = ISC_R_SUCCESS;

	/*
	 * Allow or disallow sending events to 'task'.
	 */

	REQUIRE(VALID_TASK(task));

	LOCK(&task->lock);
	if (task->state == task_state_done)
		result = ISC_R_TASKDONE;
	else {
		if (allowed)
			task->flags |= TASK_F_SENDOK;
		else
			task->flags &= ~TASK_F_SENDOK;
	}
	UNLOCK(&task->lock);

	return (result);
}

isc_result_t
isc_task_allowdone(isc_task_t *task, isc_boolean_t allowed) {
	isc_result_t result = ISC_R_SUCCESS;

	/*
	 * Allow or disallow automatic termination of 'task'.
	 */

	REQUIRE(VALID_TASK(task));

	LOCK(&task->lock);
	if (task->state == task_state_done)
		result = ISC_R_TASKDONE;
	else if (allowed &&
		 (task->flags & TASK_F_SHUTTINGDOWN) != 0 &&
		 task->state == task_state_idle) {
		task->flags &= ~TASK_F_SENDOK;
		task->state = task_state_done;
	} else {
		if (allowed)
			task->flags |= TASK_F_DONEOK;
		else
			task->flags &= ~TASK_F_DONEOK;
	}
	UNLOCK(&task->lock);

	return (result);
}

isc_result_t
isc_task_onshutdown(isc_task_t *task, isc_taskaction_t action, void *arg) {
	isc_boolean_t disallowed = ISC_FALSE;
	isc_result_t result = ISC_R_SUCCESS;
	isc_event_t *event;

	/*
	 * Send a shutdown event with action 'action' and argument 'arg' when
	 * 'task' is shutdown.
	 */

	REQUIRE(VALID_TASK(task));
	REQUIRE(action != NULL);

	event = isc_event_allocate(task->mctx,
				   NULL,
				   ISC_TASKEVENT_SHUTDOWN,
				   action,
				   arg,
				   sizeof *event);
	if (event == NULL)
		return (ISC_R_NOMEMORY);

	LOCK(&task->lock);
	if (task->state == task_state_done) {
		disallowed = ISC_TRUE;
		result = ISC_R_TASKDONE;
	} else if ((task->flags & TASK_F_SHUTTINGDOWN) != 0) {
		disallowed = ISC_TRUE;
		result = ISC_R_TASKSHUTTINGDOWN;
	} else
		ENQUEUE(task->on_shutdown, event, link);
	UNLOCK(&task->lock);

	if (disallowed)
		isc_mem_put(task->mctx, event, sizeof *event);

	return (result);
}

void
isc_task_shutdown(isc_task_t *task) {
	isc_boolean_t was_idle = ISC_FALSE;
	isc_boolean_t queued_something = ISC_FALSE;
	isc_event_t *event, *prev;

	/*
	 * Shutdown 'task'.
	 */

	REQUIRE(VALID_TASK(task));

	/*
	 * This routine is very similar to isc_task_send() above.
	 */

	LOCK(&task->lock);
	if ((task->flags & TASK_F_SHUTTINGDOWN) == 0) {
		XTRACE("shutting down");
		task->flags |= TASK_F_SHUTTINGDOWN;
		if (task->state == task_state_idle) {
			was_idle = ISC_TRUE;
			INSIST(EMPTY(task->events));
			if (EMPTY(task->on_shutdown) && TASK_DONE(task)) {
				task->flags &= ~TASK_F_SENDOK;
				task->state = task_state_done;
			} else
				task->state = task_state_ready;
		}
		INSIST(task->state == task_state_ready ||
		       task->state == task_state_running ||
		       task->state == task_state_done);
		if (task->state != task_state_done) {
			/*
			 * Note that we post shutdown events LIFO.
			 */
			for (event = TAIL(task->on_shutdown);
			     event != NULL;
			     event = prev) {
				prev = PREV(event, link);
				DEQUEUE(task->on_shutdown, event, link);
				ENQUEUE(task->events, event, link);
				queued_something = ISC_TRUE;
			}
		}
	}
	UNLOCK(&task->lock);

	if (was_idle && queued_something) {
		isc_taskmgr_t *manager;

		manager = task->manager;
		INSIST(VALID_MANAGER(manager));
		LOCK(&manager->lock);
		ENQUEUE(manager->ready_tasks, task, ready_link);
		SIGNAL(&manager->work_available);
		UNLOCK(&manager->lock);
	}
}

void
isc_task_destroy(isc_task_t **taskp) {

	/*
	 * Destroy '*taskp'.
	 */

	REQUIRE(taskp != NULL);

	isc_task_shutdown(*taskp);
	isc_task_detach(taskp);
}



/***
 *** Task Manager.
 ***/

static isc_threadresult_t
#ifdef _WIN32
WINAPI
#endif
run(void *uap) {
	isc_taskmgr_t *manager = uap;
	isc_task_t *task;

	XTHREADTRACE("start");

	REQUIRE(VALID_MANAGER(manager));

	/*
	 * Again we're trying to hold the lock for as short a time as possible
	 * and to do as little locking and unlocking as possible.
	 * 
	 * In both while loops, the appropriate lock must be held before the
	 * while body starts.  Code which acquired the lock at the top of
	 * the loop would be more readable, but would result in a lot of
	 * extra locking.  Compare:
	 *
	 * Straightforward:
	 *
	 *	LOCK();
	 *	...
	 *	UNLOCK();
	 *	while (expression) {
	 *		LOCK();
	 *		...
	 *		UNLOCK();
	 *
	 *	       	Unlocked part here...
	 *
	 *		LOCK();
	 *		...
	 *		UNLOCK();
	 *	}
	 *
	 * Note how if the loop continues we unlock and then immediately lock.
	 * For N iterations of the loop, this code does 2N+1 locks and 2N+1
	 * unlocks.  Also note that the lock is not held when the while
	 * condition is tested, which may or may not be important, depending
	 * on the expression.
	 * 
	 * As written:
	 *
	 *	LOCK();
	 *	while (expression) {
	 *		...
	 *		UNLOCK();
	 *
	 *	       	Unlocked part here...
	 *
	 *		LOCK();
	 *		...
	 *	}
	 *	UNLOCK();
	 *
	 * For N iterations of the loop, this code does N+1 locks and N+1
	 * unlocks.  The while expression is always protected by the lock.
	 */

	LOCK(&manager->lock);
	while (!FINISHED(manager)) {
		/*
		 * For reasons similar to those given in the comment in
		 * isc_task_send() above, it is safe for us to dequeue
		 * the task while only holding the manager lock, and then
		 * change the task to running state while only holding the
		 * task lock.
		 */
		while (EMPTY(manager->ready_tasks) && !FINISHED(manager)) {
			XTHREADTRACE("wait");
			WAIT(&manager->work_available, &manager->lock);
			XTHREADTRACE("awake");
		}
		XTHREADTRACE("working");
		
		task = HEAD(manager->ready_tasks);
		if (task != NULL) {
			unsigned int dispatch_count = 0;
			isc_boolean_t done = ISC_FALSE;
			isc_boolean_t requeue = ISC_FALSE;
			isc_boolean_t free_task = ISC_FALSE;
			isc_event_t *event;

			INSIST(VALID_TASK(task));

			/*
			 * Note we only unlock the manager lock if we actually
			 * have a task to do.  We must reacquire the manager 
			 * lock before exiting the 'if (task != NULL)' block.
			 */
			DEQUEUE(manager->ready_tasks, task, ready_link);
			UNLOCK(&manager->lock);

			LOCK(&task->lock);
			INSIST(task->state == task_state_ready);
			if (EMPTY(task->events)) {
				/*
				 * The task became runnable, but all events
				 * in the run queue were subsequently purged.
				 * Put the task to sleep.
				 */
				task->state = task_state_idle;
				done = ISC_TRUE;
				XTRACE("ready but empty");
			} else
				task->state = task_state_running;
			while (!done) {
				INSIST(!EMPTY(task->events));
				event = HEAD(task->events);
				DEQUEUE(task->events, event, link);

				/*
				 * Execute the event action.
				 */
				XTRACE("execute action");
				if (event->action != NULL) {
					UNLOCK(&task->lock);
					(event->action)(task, event);
					LOCK(&task->lock);
				}
				dispatch_count++;
				
				if (EMPTY(task->events)) {
					/*
					 * Nothing else to do for this task
					 * right now.  If it is shutting down,
					 * then it is done, otherwise we just
					 * put it to sleep.
					 */
					XTRACE("empty");
					if (TASK_DONE(task)) {
						XTRACE("done");
						if (task->references == 0)
							free_task = ISC_TRUE;
						task->flags &=
							~TASK_F_SENDOK;
						task->state = task_state_done;
					} else
						task->state = task_state_idle;
					done = ISC_TRUE;
				} else if (dispatch_count >= task->quantum) {
					/*
					 * Our quantum has expired, but
					 * there is more work to be done.
					 * We'll requeue it to the ready
					 * queue later.
					 *
					 * We don't check quantum until
					 * dispatching at least one event,
					 * so the minimum quantum is one.
					 */
					XTRACE("quantum");
					task->state = task_state_ready;
					requeue = ISC_TRUE;
					done = ISC_TRUE;
				}
			}
			UNLOCK(&task->lock);

			if (free_task)
				task_free(task);

			LOCK(&manager->lock);
			if (requeue) {
				/*
				 * We know we're awake, so we don't have
				 * to wakeup any sleeping threads if the
				 * ready queue is empty before we requeue.
				 *
				 * A possible optimization if the queue is
				 * empty is to 'goto' the 'if (task != NULL)'
				 * block, avoiding the ENQUEUE of the task
				 * and the subsequent immediate DEQUEUE
				 * (since it is the only executable task).
				 * We don't do this because then we'd be
				 * skipping the exit_requested check.  The
				 * cost of ENQUEUE is low anyway, especially
				 * when you consider that we'd have to do
				 * an extra EMPTY check to see if we could
				 * do the optimization.  If the ready queue
				 * were usually nonempty, the 'optimization'
				 * might even hurt rather than help.
				 */
				ENQUEUE(manager->ready_tasks, task,
					ready_link);
			}
		}
	}
	UNLOCK(&manager->lock);

	XTHREADTRACE("exit");

	return ((isc_threadresult_t)0);
}

static void
manager_free(isc_taskmgr_t *manager) {
	(void)isc_condition_destroy(&manager->work_available);
	(void)isc_mutex_destroy(&manager->lock);
	isc_mem_put(manager->mctx, manager->threads,
		    manager->workers * sizeof (isc_thread_t));
	manager->magic = 0;
	isc_mem_put(manager->mctx, manager, sizeof *manager);
}

isc_result_t
isc_taskmgr_create(isc_mem_t *mctx, unsigned int workers, 
		   unsigned int default_quantum, isc_taskmgr_t **managerp)
{
	unsigned int i, started = 0;
	isc_taskmgr_t *manager;
	isc_thread_t *threads;

	/*
	 * Create a new task manager.
	 */

	REQUIRE(workers > 0);
	REQUIRE(managerp != NULL && *managerp == NULL);

	manager = isc_mem_get(mctx, sizeof *manager);
	if (manager == NULL)
		return (ISC_R_NOMEMORY);
	manager->magic = TASK_MANAGER_MAGIC;
	manager->mctx = mctx;
	threads = isc_mem_get(mctx, workers * sizeof (isc_thread_t));
	if (threads == NULL) {
		isc_mem_put(mctx, manager, sizeof *manager);
		return (ISC_R_NOMEMORY);
	}
	manager->threads = threads;
	manager->workers = 0;
	if (isc_mutex_init(&manager->lock) != ISC_R_SUCCESS) {
		isc_mem_put(mctx, threads, workers * sizeof (isc_thread_t));
		isc_mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed");
		return (ISC_R_UNEXPECTED);
	}
	if (default_quantum == 0)
		default_quantum = DEFAULT_DEFAULT_QUANTUM;
	manager->default_quantum = default_quantum;
	INIT_LIST(manager->tasks);
	INIT_LIST(manager->ready_tasks);
	if (isc_condition_init(&manager->work_available) != ISC_R_SUCCESS) {
		(void)isc_mutex_destroy(&manager->lock);
		isc_mem_put(mctx, threads, workers * sizeof (isc_thread_t));
		isc_mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_condition_init() failed");
		return (ISC_R_UNEXPECTED);
	}
	manager->exiting = ISC_FALSE;
	manager->workers = 0;

	LOCK(&manager->lock);
	/*
	 * Start workers.
	 */
	for (i = 0; i < workers; i++) {
		if (isc_thread_create(run, manager,
				      &manager->threads[manager->workers]) == 
		    ISC_R_SUCCESS) {
			manager->workers++;
			started++;
		}
	}
	UNLOCK(&manager->lock);

	if (started == 0) {
		manager_free(manager);
		return (ISC_R_NOTHREADS);
	}		

	*managerp = manager;

	return (ISC_R_SUCCESS);
}

void
isc_taskmgr_destroy(isc_taskmgr_t **managerp) {
	isc_taskmgr_t *manager;
	isc_task_t *task;
	isc_event_t *event, *prev;
	unsigned int i;

	/*
	 * Destroy '*managerp'.
	 */

	REQUIRE(managerp != NULL);
	manager = *managerp;
	REQUIRE(VALID_MANAGER(manager));

	XTHREADTRACE("isc_taskmgr_destroy");
	/*
	 * Only one non-worker thread may ever call this routine.
	 * If a worker thread wants to initiate shutdown of the
	 * task manager, it should ask some non-worker thread to call
	 * isc_taskmgr_destroy(), e.g. by signalling a condition variable
	 * that the startup thread is sleeping on.
	 */

	/*
	 * Unlike elsewhere, we're going to hold this lock a long time.
	 * We need to do so, because otherwise the list of tasks could
	 * change while we were traversing it.
	 *
	 * This is also the only function where we will hold both the
	 * task manager lock and a task lock at the same time.
	 */

	LOCK(&manager->lock);

	/*
	 * Make sure we only get called once.
	 */
	INSIST(!manager->exiting);
	manager->exiting = ISC_TRUE;

	/*
	 * Post shutdown event(s) to every task (if they haven't already been
	 * posted).
	 */
	for (task = HEAD(manager->tasks);
	     task != NULL;
	     task = NEXT(task, link)) {
		LOCK(&task->lock);
		if ((task->flags & TASK_F_SHUTTINGDOWN) == 0) {
			task->flags |= TASK_F_SHUTTINGDOWN;
			if (task->state == task_state_idle) {
				INSIST(EMPTY(task->events));
				if (EMPTY(task->on_shutdown) &&
				    TASK_DONE(task)) {
					task->flags &= ~TASK_F_SENDOK;
					task->state = task_state_done;
				} else {
					task->state = task_state_ready;
					ENQUEUE(manager->ready_tasks, task,
						ready_link);
				}
			}
			INSIST(task->state == task_state_ready ||
			       task->state == task_state_running ||
			       task->state == task_state_done);
			if (task->state != task_state_done) {
				/*
				 * Note that we post shutdown events LIFO.
				 */
				for (event = TAIL(task->on_shutdown);
				     event != NULL;
				     event = prev) {
					prev = PREV(event, link);
					DEQUEUE(task->on_shutdown, event,
						link);
					ENQUEUE(task->events, event, link);
				}
			}
		}
		UNLOCK(&task->lock);
	}

	/*
	 * Wake up any sleeping workers.  This ensures we get work done if
	 * there's work left to do, and if there are already no tasks left
	 * it will cause the workers to see manager->exiting.
	 */
	BROADCAST(&manager->work_available);
	UNLOCK(&manager->lock);

	/*
	 * Wait for all the worker threads to exit.
	 */
	for (i = 0; i < manager->workers; i++)
		(void)isc_thread_join(manager->threads[i], NULL);

	manager_free(manager);

	*managerp = NULL;
}
