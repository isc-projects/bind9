
#include "attribute.h"

#include <isc/assertions.h>

#include <isc/thread.h>
#include <isc/task.h>


/***
 *** General Macros.
 ***/

/*
 * We use macros instead of calling the os_ routines directly because
 * the capital letters make the locking stand out.
 *
 * We INSIST that they succeed since there's no way for us to continue
 * if they fail.
 */
#define LOCK(lp)		INSIST(os_mutex_lock((lp)))
#define UNLOCK(lp)		INSIST(os_mutex_unlock((lp)))
#define WAIT(cvp, lp)		INSIST(os_condition_wait((cvp), (lp)))
#define BROADCAST(cvp)		INSIST(os_condition_broadcast((cvp)))

#ifdef DEBUGTRACE
#define XTRACE(m)		printf("%s %p\n", (m), os_thread_self())
#else
#define XTRACE(m)
#endif


/***
 *** Types.
 ***/

typedef enum {
	task_state_idle, task_state_ready, task_state_running,
	task_state_shutdown
} task_state_t;

#define TASK_MAGIC			0x5441534BU	/* TASK. */
#define VALID_TASK(t)			((t) != NULL && \
					 (t)->magic == TASK_MAGIC)

struct task {
	/* Not locked. */
	unsigned int			magic;
	task_manager_t			manager;
	os_mutex_t			lock;
	/* Locked by task lock. */
	task_state_t			state;
	unsigned int			references;
	task_eventlist_t		events;
	unsigned int			quantum;
	boolean_t			enqueue_allowed;
	task_event_t			shutdown_event;
	/* Locked by task manager lock. */
	LINK(struct task)		link;
	LINK(struct task)		ready_link;
};

#define TASK_MANAGER_MAGIC		0x54534B4DU	/* TSKM. */
#define VALID_MANAGER(m)		((m) != NULL && \
					 (m)->magic == TASK_MANAGER_MAGIC)

struct task_manager {
	/* Not locked. */
	unsigned int			magic;
	mem_context_t			mctx;
	os_mutex_t			lock;
	/* Locked by task manager lock. */
	unsigned int			default_quantum;
	LIST(struct task)		tasks;
	LIST(struct task)		ready_tasks;
	os_condition_t			work_available;
	boolean_t			exiting;
	unsigned int			workers;
	os_condition_t			no_workers;
};

#define DEFAULT_DEFAULT_QUANTUM		5
#define FINISHED(m)			((m)->exiting && EMPTY((m)->tasks))


/***
 *** Events.
 ***/

static inline task_event_t
event_allocate(mem_context_t mctx, task_eventtype_t type,
	       task_action_t action, void *arg, size_t size)
{
	task_event_t event;

	event = mem_get(mctx, size);
	if (event == NULL)
		return (NULL);
	event->mctx = mctx;
	event->size = size;
	event->type = type;
	event->action = action;
	event->arg = arg;

	return (event);
}

task_event_t
task_event_allocate(mem_context_t mctx, task_eventtype_t type,
		    task_action_t action, void *arg, size_t size)
{
	if (size < sizeof (struct task_event))
		return (NULL);
	if (type < 0)
		return (NULL);
	if (action == NULL)
		return (NULL);

	return (event_allocate(mctx, type, action, arg, size));
}

void
task_event_free(task_event_t *eventp) {
	task_event_t event;
	
	REQUIRE(eventp != NULL);
	event = *eventp;
	REQUIRE(event != NULL);

	mem_put(event->mctx, event, event->size);

	*eventp = NULL;
}

/***
 *** Tasks.
 ***/

static void
task_free(task_t task) {
	task_manager_t manager = task->manager;

	XTRACE("free task");
	REQUIRE(EMPTY(task->events));

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
	(void)os_mutex_destroy(&task->lock);
	if (task->shutdown_event != NULL)
		task_event_free(&task->shutdown_event);
	task->magic = 0;
	mem_put(manager->mctx, task, sizeof *task);
}

boolean_t
task_create(task_manager_t manager, task_action_t shutdown_action,
	    void *shutdown_arg, unsigned int quantum, task_t *taskp)
{
	task_t task;

	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(taskp != NULL && *taskp == NULL);

	task = mem_get(manager->mctx, sizeof *task);
	if (task == NULL)
		return (FALSE);

	task->magic = TASK_MAGIC;
	task->manager = manager;
	if (!os_mutex_init(&task->lock)) {
		mem_put(manager->mctx, task, sizeof *task);
		return (FALSE);
	}
	task->state = task_state_idle;
	task->references = 1;
	INIT_LIST(task->events);
	task->quantum = quantum;
	task->enqueue_allowed = TRUE;
	task->shutdown_event = event_allocate(manager->mctx,
					      TASK_EVENT_SHUTDOWN,
					      shutdown_action,
					      shutdown_arg,
					      sizeof *task->shutdown_event);
	if (task->shutdown_event == NULL) {
		(void)os_mutex_destroy(&task->lock);
		mem_put(manager->mctx, task, sizeof *task);
		return (FALSE);
	}
	INIT_LINK(task, link);
	INIT_LINK(task, ready_link);

	LOCK(&manager->lock);
	if (task->quantum == 0)
		task->quantum = manager->default_quantum;
	APPEND(manager->tasks, task, link);
	UNLOCK(&manager->lock);

	*taskp = task;

	return (TRUE);
}

void
task_attach(task_t task, task_t *taskp) {

	REQUIRE(VALID_TASK(task));
	REQUIRE(taskp != NULL && *taskp == NULL);

	LOCK(&task->lock);
	task->references++;
	UNLOCK(&task->lock);

	*taskp = task;
}

void
task_detach(task_t *taskp) {
	boolean_t free_task = FALSE;
	task_t task;

	XTRACE("task_detach");

	REQUIRE(taskp != NULL);
	task = *taskp;
	REQUIRE(VALID_TASK(task));

	LOCK(&task->lock);
	REQUIRE(task->references > 0);
	task->references--;
	if (task->state == task_state_shutdown && task->references == 0)
		free_task = TRUE;
	UNLOCK(&task->lock);

	if (free_task)
		task_free(task);

	*taskp = NULL;
}

boolean_t
task_send_event(task_t task, task_event_t *eventp) {
	boolean_t was_idle = FALSE;
	boolean_t discard = FALSE;
	task_event_t event;

	REQUIRE(VALID_TASK(task));
	REQUIRE(eventp != NULL);
	event = *eventp;
	REQUIRE(event != NULL);
	REQUIRE(event->type >= 0);

	XTRACE("sending");
	/*
	 * We're trying hard to hold locks for as short a time as possible.
	 * We're also trying to hold as few locks as possible.  This is why
	 * some processing is deferred until after a lock is released.
	 */
	LOCK(&task->lock);
	if (task->enqueue_allowed) {
		if (task->state == task_state_idle) {
			was_idle = TRUE;
			INSIST(EMPTY(task->events));
			task->state = task_state_ready;
		}
		INSIST(task->state == task_state_ready ||
		       task->state == task_state_running);
		ENQUEUE(task->events, event, link);
	} else
		discard = TRUE;
	UNLOCK(&task->lock);

	if (discard) {
		task_event_free(&event);
		*eventp = NULL;
		return (TRUE);
	}

	if (was_idle) {
		boolean_t need_wakeup = FALSE;
		task_manager_t manager;

		/*
		 * We need to add this task to the ready queue.
		 *
		 * We've waited until now to do it, rather than doing it
		 * while holding the task lock, because we don't want to
		 * block while holding the task lock.
		 *
		 * We've changed the state to ready, so no one else will
		 * be trying to add this task to the ready queue.  It
		 * thus doesn't matter if more events have been added to
		 * the queue after we gave up the task lock.
		 *
		 * Shutting down a task requires posting a shutdown event
		 * to the task's queue and then executing it, so there's
		 * no way the task can disappear.  A task is always on the
		 * task manager's 'tasks' list, so the task manager can
		 * always post a shutdown event to all tasks if it is
		 * requested to shutdown.
		 */
		manager = task->manager;
		INSIST(VALID_MANAGER(manager));
		LOCK(&manager->lock);
		if (EMPTY(manager->ready_tasks))
			need_wakeup = TRUE;
		ENQUEUE(manager->ready_tasks, task, ready_link);
		UNLOCK(&manager->lock);

		/*
		 * If the runnable queue is empty, the worker threads could
		 * either be executing tasks or waiting for something to do.
		 * We wakeup anyone who is sleeping.
		 */
		if (need_wakeup)
			BROADCAST(&manager->work_available);
	}

	*eventp = NULL;

	XTRACE("sent");
	return (TRUE);
}

void
task_shutdown(task_t task) {
	boolean_t was_idle = FALSE;
	boolean_t discard = FALSE;

	REQUIRE(VALID_TASK(task));

	/*
	 * This routine is very similar to task_send_event() above.
	 */

	LOCK(&task->lock);
	if (task->enqueue_allowed) {
		if (task->state == task_state_idle) {
			was_idle = TRUE;
			INSIST(EMPTY(task->events));
			task->state = task_state_ready;
		}
		INSIST(task->state == task_state_ready ||
		       task->state == task_state_running);
		INSIST(task->shutdown_event != NULL);
		ENQUEUE(task->events, task->shutdown_event, link);
		task->shutdown_event = NULL;
		task->enqueue_allowed = FALSE;
	} else
		discard = TRUE;
	UNLOCK(&task->lock);

	if (discard)
		return;

	if (was_idle) {
		boolean_t need_wakeup = FALSE;
		task_manager_t manager;

		manager = task->manager;
		INSIST(VALID_MANAGER(manager));
		LOCK(&manager->lock);
		if (EMPTY(manager->ready_tasks))
			need_wakeup = TRUE;
		ENQUEUE(manager->ready_tasks, task, ready_link);
		UNLOCK(&manager->lock);

		if (need_wakeup)
			BROADCAST(&manager->work_available);
	}
}

void
task_destroy(task_t *taskp) {

	REQUIRE(taskp != NULL);

	task_shutdown(*taskp);
	task_detach(taskp);
}



/***
 *** Task Manager.
 ***/

static
void *task_manager_run(void *uap) {
	task_manager_t manager = uap;
	task_t task;
	boolean_t no_workers = FALSE;

	XTRACE("start");

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
		 * task_send_event() above, it is safe for us to dequeue
		 * the task while only holding the manager lock, and then
		 * change the task to running state while only holding the
		 * task lock.
		 */
		while (EMPTY(manager->ready_tasks) && !FINISHED(manager)) {
			XTRACE("wait");
			WAIT(&manager->work_available, &manager->lock);
			XTRACE("awake");
		}
		XTRACE("working");
		
		task = HEAD(manager->ready_tasks);
		if (task != NULL) {
			unsigned int dispatch_count = 0;
			boolean_t done = FALSE;
			boolean_t requeue = FALSE;
			boolean_t wants_shutdown;
			boolean_t is_shutdown;
			boolean_t free_task = FALSE;
			task_event_t event;
			task_eventlist_t remaining_events;
			boolean_t discard_remaining = FALSE;

			INSIST(VALID_TASK(task));

			/*
			 * Note we only unlock the manager lock if we actually
			 * have a task to do.  We must reacquire the manager 
			 * lock before exiting the 'if (task != NULL)' block.
			 */
			DEQUEUE(manager->ready_tasks, task, ready_link);
			UNLOCK(&manager->lock);

			LOCK(&task->lock);
			task->state = task_state_running;
			while (!done) {
				INSIST(!EMPTY(task->events));
				event = HEAD(task->events);
				DEQUEUE(task->events, event, link);
				UNLOCK(&task->lock);

				if (event->type == TASK_EVENT_SHUTDOWN)
					is_shutdown = TRUE;
				else
					is_shutdown = FALSE;

				/*
				 * Execute the event action.
				 */
				XTRACE("execute action");
				if (event->action != NULL)
					wants_shutdown =
						(event->action)(task, event);
				else
					wants_shutdown = FALSE;
				dispatch_count++;
				
				task_event_free(&event);

				LOCK(&task->lock);
				if (wants_shutdown || is_shutdown) {
					/*
					 * The event action has either
					 * requested shutdown, or the event
					 * we just executed was the shutdown
					 * event.
					 *
					 * Since no more events can be
					 * delivered to the task, we purge
					 * any remaining events (but defer
					 * freeing them until we've released
					 * the lock).
					 */
					XTRACE("wants shutdown");
					if (!EMPTY(task->events)) {
						remaining_events =
							task->events;
						INIT_LIST(task->events);
						discard_remaining = TRUE;
					}
					if (task->references == 0)
						free_task = TRUE;
					task->state = task_state_shutdown;
					task->enqueue_allowed = FALSE;
					done = TRUE;
				} else if (EMPTY(task->events)) {
					/*
					 * Nothing else to do for this task.
					 * Put it to sleep.
					 */
					task->state = task_state_idle;
					done = TRUE;
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
					task->state = task_state_ready;
					requeue = TRUE;
					done = TRUE;
				}
			}
			UNLOCK(&task->lock);

			if (discard_remaining) {
				task_event_t next_event;

				for (event = HEAD(remaining_events);
				     event != NULL;
				     event = next_event) {
					next_event = NEXT(event, link);
					task_event_free(&event);
				}
			}

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
	INSIST(manager->workers > 0);
	manager->workers--;
	if (manager->workers == 0)
		no_workers = TRUE;
	UNLOCK(&manager->lock);

	if (no_workers)
		BROADCAST(&manager->no_workers);

	XTRACE("exit");

	return (NULL);	
}

static void
manager_free(task_manager_t manager) {
	(void)os_condition_destroy(&manager->work_available);
	(void)os_condition_destroy(&manager->no_workers);
	(void)os_mutex_destroy(&manager->lock);
	manager->magic = 0;
	mem_put(manager->mctx, manager, sizeof *manager);
}

unsigned int
task_manager_create(mem_context_t mctx, unsigned int workers, 
		    unsigned int default_quantum, task_manager_t *managerp)
{
	unsigned int i, started = 0;
	task_manager_t manager;
	os_thread_t thread;

	if (workers == 0)
		return (0);
	manager = mem_get(mctx, sizeof *manager);
	if (manager == NULL)
		return (0);
	manager->magic = TASK_MANAGER_MAGIC;
	manager->mctx = mctx;
	if (!os_mutex_init(&manager->lock)) {
		mem_put(mctx, manager, sizeof *manager);
		return (0);
	}
	if (default_quantum == 0)
		default_quantum = DEFAULT_DEFAULT_QUANTUM;
	manager->default_quantum = default_quantum;
	INIT_LIST(manager->tasks);
	INIT_LIST(manager->ready_tasks);
	if (!os_condition_init(&manager->work_available)) {
		(void)os_mutex_destroy(&manager->lock);
		mem_put(mctx, manager, sizeof *manager);
		return (0);
	}
	manager->exiting = FALSE;
	manager->workers = 0;
	if (!os_condition_init(&manager->no_workers)) {
		(void)os_condition_destroy(&manager->work_available);
		(void)os_mutex_destroy(&manager->lock);
		mem_put(mctx, manager, sizeof *manager);
		return (0);
	}

	LOCK(&manager->lock);
	/*
	 * Start workers.
	 */
	for (i = 0; i < workers; i++) {
		if (os_thread_create(task_manager_run, manager, &thread)) {
			manager->workers++;
			started++;
			(void)os_thread_detach(thread);
		}
	}
	UNLOCK(&manager->lock);

	if (started == 0) {
		manager_free(manager);
		return (0);
	}		

	*managerp = manager;

	return (started);
}

void
task_manager_destroy(task_manager_t *managerp) {
	task_manager_t manager;
	task_t task;

	REQUIRE(managerp != NULL);
	manager = *managerp;
	REQUIRE(VALID_MANAGER(manager));

	XTRACE("task_manager_destroy");
	/*
	 * Only one non-worker thread may ever call this routine.
	 * If a worker thread wants to initiate shutdown of the
	 * task manager, it should ask some non-worker thread to call
	 * task_manager_destroy(), e.g. by signalling a condition variable
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
	manager->exiting = TRUE;

	/*
	 * Post the shutdown event to every task (if it hasn't already been
	 * posted).
	 */
	for (task = HEAD(manager->tasks);
	     task != NULL;
	     task = NEXT(task, link)) {
		LOCK(&task->lock);
		if (task->enqueue_allowed) {
			INSIST(task->shutdown_event != NULL);
			ENQUEUE(task->events, task->shutdown_event, link);
			task->shutdown_event = NULL;
			if (task->state == task_state_idle) {
				task->state = task_state_ready;
				ENQUEUE(manager->ready_tasks, task,
					ready_link);
			}
			INSIST(task->state == task_state_ready ||
			       task->state == task_state_running);
			task->enqueue_allowed = FALSE;
		}
		UNLOCK(&task->lock);
	}

	/*
	 * Wake up any sleeping workers.  This ensures we get work done if
	 * there's work left to do, and if there are already no tasks left
	 * it will cause the workers to see manager->exiting.
	 */
	BROADCAST(&manager->work_available);

	/*
	 * Wait for all the worker threads to exit.
	 *
	 * XXX  This will become a timed wait.  If all the workers haven't
	 *      died after we've waited the specified interval, we will
	 *	kill the worker threads.  Should we join with the worker
	 *      threads after killing them or just leave them detached and
	 *      hope they go away?
	 */
	while (manager->workers > 0)
		WAIT(&manager->no_workers, &manager->lock);

	UNLOCK(&manager->lock);

	manager_free(manager);

	*managerp = NULL;
}
