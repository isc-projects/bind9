
#include <stddef.h>
#include <stdlib.h>

#include <isc/assertions.h>
#include <isc/unexpect.h>
#include <isc/thread.h>
#include <isc/mutex.h>
#include <isc/condition.h>
#include <isc/heap.h>
#include <isc/timer.h>

/*
 * We use macros instead of calling the os_ routines directly because
 * the capital letters make the locking stand out.
 *
 * We INSIST that they succeed since there's no way for us to continue
 * if they fail.
 */
#define LOCK(lp)			INSIST(os_mutex_lock((lp)))
#define UNLOCK(lp)			INSIST(os_mutex_unlock((lp)))
#define BROADCAST(cvp)			INSIST(os_condition_broadcast((cvp)))
#define WAIT(cvp, lp)			INSIST(os_condition_wait((cvp), (lp)))
#define WAITUNTIL(cvp, lp, tp, bp)	INSIST(os_condition_waituntil((cvp), \
					       (lp), (tp), (bp)))

#define ZERO(t)				((t).seconds == 0 && \
					 (t).nanoseconds == 0)

#ifdef ISC_TIMER_TRACE
#define XTRACE(s)			printf("%s\n", (s))
#define XTRACEID(s, t)			printf("%s %p\n", (s), (t))
#define XTRACETIME(s, d)		printf("%s %lu.%09lu\n", (s), \
					       (d).seconds, (d).nanoseconds)
#define XTRACETIMER(s, t, d)		printf("%s %p %lu.%09lu\n", (s), (t), \
					       (d).seconds, (d).nanoseconds)
#else
#define XTRACE(s)
#define XTRACEID(s, t)
#define XTRACETIME(s, d)
#define XTRACETIMER(s, t, d)
#endif /* ISC_TIMER_TRACE */

#define TIMER_MAGIC			0x54494D52U	/* TIMR. */
#define VALID_TIMER(t)			((t) != NULL && \
					 (t)->magic == TIMER_MAGIC)
struct isc_timer {
	/* Not locked. */
	unsigned int			magic;
	isc_timermgr_t			manager;
	os_mutex_t			lock;
	/* Locked by timer lock. */
	unsigned int			references;
	os_time_t			idle;
	/* Locked by manager lock. */
	isc_timertype_t			type;
	os_time_t			expires;
	os_time_t			interval;
	task_t				task;
	task_action_t			action;
	void *				arg;
	unsigned int			index;
	os_time_t			due;
	LINK(struct isc_timer)		link;
};

#define TIMER_MANAGER_MAGIC		0x54494D4DU	/* TIMM. */
#define VALID_MANAGER(m)		((m) != NULL && \
					 (m)->magic == TIMER_MANAGER_MAGIC)

struct isc_timermgr {
	/* Not locked. */
	unsigned int			magic;
	mem_context_t			mctx;
	os_mutex_t			lock;
	/* Locked by manager lock. */
	isc_boolean_t			done;
	LIST(struct isc_timer)		timers;
	unsigned int			nscheduled;
	os_time_t			due;
	os_condition_t			wakeup;
	os_thread_t			thread;
	isc_heap_t			heap;
};

static inline isc_result
schedule(isc_timer_t timer, os_time_t *nowp, isc_boolean_t broadcast_ok) {
	isc_result result;
	isc_timermgr_t manager;
	os_time_t due;
	int cmp;

	/* 
	 * Note: the caller must ensure locking.
	 */

	/*
	 * Compute the new due time.
	 */
	if (timer->type == isc_timertype_ticker)
		os_time_add(nowp, &timer->interval, &due);
	else {
		if (ZERO(timer->idle))
			due = timer->expires;
		else if (ZERO(timer->expires))
			due = timer->idle;
		else if (os_time_compare(&timer->idle, &timer->expires) < 0)
			due = timer->idle;
		else
			due = timer->expires;
	}
	
	/*
	 * Schedule the timer.
	 */
	manager = timer->manager;
	if (timer->index > 0) {
		/*
		 * Already scheduled.
		 */
		cmp = os_time_compare(&due, &timer->due);
		timer->due = due;
		switch (cmp) {
		case -1:
			isc_heap_increased(manager->heap, timer->index);
			break;
		case 1:
			isc_heap_decreased(manager->heap, timer->index);
			break;
		case 0:
			/* Nothing to do. */
			break;
		}
	} else {
		timer->due = due;
		result = isc_heap_insert(manager->heap, timer);
		if (result != ISC_R_SUCCESS) {
			INSIST(result == ISC_R_NOMEMORY);
			return (ISC_R_NOMEMORY);
		}
		manager->nscheduled++;
	}

	XTRACETIMER("schedule", timer, due);

	/*
	 * If this timer is at the head of the queue, we wake up the run
	 * thread.  We do this, because we likely have set a more recent
	 * due time than the one the run thread is sleeping on, and we don't
	 * want it to oversleep.
	 */
	if (timer->index == 1 && broadcast_ok) {
		XTRACE("broadcast (schedule)");
		BROADCAST(&manager->wakeup);
	}

	return (ISC_R_SUCCESS);
}

static inline void
deschedule(isc_timer_t timer) {
	isc_boolean_t need_wakeup = ISC_FALSE;
	isc_timermgr_t manager;

	/* 
	 * The caller must ensure locking.
	 */

	manager = timer->manager;
	if (timer->index > 0) {
		if (timer->index == 1)
			need_wakeup = ISC_TRUE;
		isc_heap_delete(manager->heap, timer->index);
		timer->index = 0;
		INSIST(manager->nscheduled > 0);
		manager->nscheduled--;
		if (need_wakeup) {
			XTRACE("broadcast (deschedule)");
			BROADCAST(&manager->wakeup);
		}
	}
}

static void
destroy(isc_timer_t timer) {
	isc_timermgr_t manager = timer->manager;

	/*
	 * The caller must ensure locking.
	 */

	LOCK(&manager->lock);

	task_purge_events(timer->task, timer, TASK_EVENT_ANYEVENT);
	deschedule(timer);
	UNLINK(manager->timers, timer, link);

	UNLOCK(&manager->lock);

	task_detach(&timer->task);
	(void)os_mutex_destroy(&timer->lock);
	timer->magic = 0;
	mem_put(manager->mctx, timer, sizeof *timer);
}

isc_result
isc_timer_create(isc_timermgr_t manager, isc_timertype_t type,
		 os_time_t expires, os_time_t interval,
		 task_t task, task_action_t action, void *arg,
		 isc_timer_t *timerp)
{
	isc_timer_t timer;
	isc_result result;
	os_time_t now;

	/*
	 * Create a new 'type' timer managed by 'manager'.  The timers
	 * parameters are specified by 'expires' and 'interval'.  Events
	 * will be posted to 'task' and when dispatched 'action' will be
	 * called with 'arg' as the arg value.  The new timer is returned
	 * in 'timerp'.
	 */

	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);
	REQUIRE(!(ZERO(expires) && ZERO(interval)));
	REQUIRE(timerp != NULL && *timerp == NULL);

	/*
	 * Get current time.
	 */
	result = os_time_get(&now);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "os_time_get() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	timer = mem_get(manager->mctx, sizeof *timer);
	if (timer == NULL)
		return (ISC_R_NOMEMORY);

	timer->magic = TIMER_MAGIC;
	timer->manager = manager;
	timer->references = 1;
	if (type == isc_timertype_once && !ZERO(interval))
		os_time_add(&now, &interval, &timer->idle);
	else {
		timer->idle.seconds = 0;
		timer->idle.nanoseconds = 0;
	}
	timer->type = type;
	timer->expires = expires;
	timer->interval = interval;
	timer->task = NULL;
	task_attach(task, &timer->task);
	timer->action = action;
	timer->arg = arg;
	timer->index = 0;
	if (!os_mutex_init(&timer->lock)) {
		mem_put(manager->mctx, timer, sizeof *timer);
		UNEXPECTED_ERROR(__FILE__, __LINE__, "os_mutex_init() failed");
		return (ISC_R_UNEXPECTED);
	}

	LOCK(&manager->lock);

	/*
	 * Note we don't have to lock the timer like we normally would because
	 * there are no external references to it yet.
	 */

	APPEND(manager->timers, timer, link);
	result = schedule(timer, &now, ISC_TRUE);

	UNLOCK(&manager->lock);

	if (result == ISC_R_SUCCESS)
		*timerp = timer;

	return (result);
}

isc_result
isc_timer_reset(isc_timer_t timer, isc_timertype_t type,
		os_time_t expires, os_time_t interval, isc_boolean_t purge)
{
	os_time_t now;
	isc_timermgr_t manager;
	isc_result result;

	/*
	 * Change the timer's type, expires, and interval values to the given
	 * values.  If 'purge' is ISC_TRUE, any pending events from this timer
	 * are purged from its task's event queue.
	 */

	REQUIRE(VALID_TIMER(timer));
	manager = timer->manager;
	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(!(ZERO(expires) && ZERO(interval)));

	/*
	 * Get current time.
	 */
	result = os_time_get(&now);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "os_time_get() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	manager = timer->manager;

	LOCK(&manager->lock);
	LOCK(&timer->lock);

	if (purge)
		task_purge_events(timer->task, timer, TASK_EVENT_ANYEVENT);
	timer->type = type;
	timer->expires = expires;
	timer->interval = interval;
	if (type == isc_timertype_once && !ZERO(interval))
		os_time_add(&now, &interval, &timer->idle);
	else {
		timer->idle.seconds = 0;
		timer->idle.nanoseconds = 0;
	}
	result = schedule(timer, &now, ISC_TRUE);

	UNLOCK(&timer->lock);
	UNLOCK(&manager->lock);

	return (result);
}

isc_result
isc_timer_touch(isc_timer_t timer) {
	isc_result result;
	os_time_t now;

	/*
	 * Set the last-touched time of 'timer' to the current time.
	 */

	REQUIRE(VALID_TIMER(timer));

	LOCK(&timer->lock);

	INSIST(timer->type == isc_timertype_once);

	result = os_time_get(&now);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "os_time_get() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}
	os_time_add(&now, &timer->interval, &timer->idle);

	UNLOCK(&timer->lock);

	return (ISC_R_SUCCESS);
}

void
isc_timer_attach(isc_timer_t timer, isc_timer_t *timerp) {
	/*
	 * Attach *timerp to timer.
	 */

	REQUIRE(VALID_TIMER(timer));
	REQUIRE(timerp != NULL && *timerp == NULL);

	LOCK(&timer->lock);
	timer->references++;
	UNLOCK(&timer->lock);
	
	*timerp = timer;
}

void 
isc_timer_detach(isc_timer_t *timerp) {
	isc_timer_t timer;
	isc_boolean_t free_timer = ISC_FALSE;

	/*
	 * Detach *timerp from its timer.
	 */

	REQUIRE(timerp != NULL);
	timer = *timerp;
	REQUIRE(VALID_TIMER(timer));

	LOCK(&timer->lock);
	REQUIRE(timer->references > 0);
	timer->references--;
	if (timer->references == 0)
		free_timer = ISC_TRUE;
	UNLOCK(&timer->lock);
	
	if (free_timer)
		destroy(timer);

	*timerp = NULL;
}

static void
dispatch(isc_timermgr_t manager, os_time_t *nowp) {
	isc_boolean_t done = ISC_FALSE, post_event, need_schedule;
	task_event_t event;
	task_eventtype_t type = 0;
	isc_timer_t timer;
	isc_result result;

	while (manager->nscheduled > 0 && !done) {
		timer = isc_heap_element(manager->heap, 1);
		if (os_time_compare(nowp, &timer->due) >= 0) {
			if (timer->type == isc_timertype_ticker) {
				type = ISC_TIMEREVENT_TICK;
				post_event = ISC_TRUE;
				need_schedule = ISC_TRUE;
			} else if (!ZERO(timer->expires) &&
				   os_time_compare(nowp,
						   &timer->expires) >= 0) {
				type = ISC_TIMEREVENT_LIFE;
				post_event = ISC_TRUE;
				need_schedule = ISC_FALSE;
			} else if (!ZERO(timer->idle) &&
				   os_time_compare(nowp,
						   &timer->idle) >= 0) {
				type = ISC_TIMEREVENT_IDLE;
				post_event = ISC_TRUE;
				need_schedule = ISC_FALSE;
			} else {
				/*
				 * Idle timer has been touched; reschedule.
				 */
				XTRACEID("idle reschedule", timer);
				post_event = ISC_FALSE;
				need_schedule = ISC_TRUE;
			}

			if (post_event) {
				XTRACEID("posting", timer);
				event = task_event_allocate(manager->mctx,
							    timer,
							    type,
							    timer->action,
							    timer->arg,
							    sizeof *event);

				if (event != NULL)
					INSIST(task_send_event(timer->task,
							       &event));
				else
					UNEXPECTED_ERROR(__FILE__, __LINE__,
						 "couldn't allocate event");
			}
					
			timer->index = 0;
			isc_heap_delete(manager->heap, 1);
			manager->nscheduled--;

			if (need_schedule) {
				result = schedule(timer, nowp, ISC_FALSE);
				if (result != ISC_R_SUCCESS)
					UNEXPECTED_ERROR(__FILE__, __LINE__,
						"couldn't schedule timer: %s",
							 result);
			}
		} else {
			manager->due = timer->due;
			done = ISC_TRUE;
		}
	} 
}

static void *
run(void *uap) {
	isc_timermgr_t manager = uap;
	isc_boolean_t timeout;
	os_time_t now;

	LOCK(&manager->lock);
	while (!manager->done) {
		INSIST(os_time_get(&now) == ISC_R_SUCCESS);

		XTRACETIME("running", now);

		dispatch(manager, &now);

		if (manager->nscheduled > 0) {
			XTRACETIME("waituntil", manager->due);
			WAITUNTIL(&manager->wakeup, &manager->lock,
				  &manager->due, &timeout);
		} else {
			XTRACE("wait");
			WAIT(&manager->wakeup, &manager->lock);
		}
		XTRACE("wakeup");
	}
	UNLOCK(&manager->lock);

	return (NULL);
}

static isc_boolean_t
sooner(void *v1, void *v2) {
	isc_timer_t t1, t2;

	t1 = v1;
	t2 = v2;
	REQUIRE(VALID_TIMER(t1));
	REQUIRE(VALID_TIMER(t2));

	if (os_time_compare(&t1->due, &t2->due) < 0)
		return (ISC_TRUE);
	return (ISC_FALSE);
}

static void
set_index(void *what, unsigned int index) {
	isc_timer_t timer;

	timer = what;
	REQUIRE(VALID_TIMER(timer));

	timer->index = index;
}

isc_result
isc_timermgr_create(mem_context_t mctx, isc_timermgr_t *managerp) {
	isc_timermgr_t manager;
	isc_result result;

	/*
	 * Create a timer manager.
	 */

	REQUIRE(managerp != NULL && *managerp == NULL);

	manager = mem_get(mctx, sizeof *manager);
	if (manager == NULL)
		return (ISC_R_NOMEMORY);
	
	manager->magic = TIMER_MANAGER_MAGIC;
	manager->mctx = mctx;
	manager->done = ISC_FALSE;
	INIT_LIST(manager->timers);
	manager->nscheduled = 0;
	manager->due.seconds = 0;
	manager->due.nanoseconds = 0;
	manager->heap = NULL;
	result = isc_heap_create(mctx, sooner, set_index, 0, &manager->heap);
	if (result != ISC_R_SUCCESS) {
		INSIST(result == ISC_R_NOMEMORY);
		mem_put(mctx, manager, sizeof *manager);
		return (ISC_R_NOMEMORY);
	}
	if (!os_mutex_init(&manager->lock)) {
		isc_heap_destroy(&manager->heap);
		mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__, "os_mutex_init() failed");
		return (ISC_R_UNEXPECTED);
	}
	if (!os_condition_init(&manager->wakeup)) {
		(void)os_mutex_destroy(&manager->lock);
		isc_heap_destroy(&manager->heap);
		mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "os_condition_init() failed");
		return (ISC_R_UNEXPECTED);
	}
	if (!os_thread_create(run, manager, &manager->thread)) {
		(void)os_condition_destroy(&manager->wakeup);
		(void)os_mutex_destroy(&manager->lock);
		isc_heap_destroy(&manager->heap);
		mem_put(mctx, manager, sizeof *manager);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "os_thread_create() failed");
		return (ISC_R_UNEXPECTED);
	}

	*managerp = manager;

	return (ISC_R_SUCCESS);
}

void
isc_timermgr_destroy(isc_timermgr_t *managerp) {
	isc_timermgr_t manager;

	/*
	 * Destroy a timer manager.
	 */

	REQUIRE(managerp != NULL);
	manager = *managerp;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&manager->lock);

	REQUIRE(EMPTY(manager->timers));
	manager->done = ISC_TRUE;

	UNLOCK(&manager->lock);

	XTRACE("broadcast (destroy)");
	BROADCAST(&manager->wakeup);

	/*
	 * Wait for thread to exit.
	 */
	if (!os_thread_join(manager->thread))
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "os_thread_join() failed");

	/*
	 * Clean up.
	 */
	(void)os_condition_destroy(&manager->wakeup);
	(void)os_mutex_destroy(&manager->lock);
	isc_heap_destroy(&manager->heap);
	manager->magic = 0;
	mem_put(manager->mctx, manager, sizeof *manager);

	*managerp = NULL;
}
