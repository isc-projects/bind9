
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

#define TIMER_MAGIC			0x54494D52U	/* TIMR. */
#define VALID_TIMER(t)			((t) != NULL && \
					 (t)->magic == TIMER_MAGIC)
struct timer_t {
	/* Not locked. */
	unsigned int			magic;
	timer_manager_t			manager;
	os_mutex_t			lock;
	/* Locked by timer lock. */
	unsigned int			references;
	os_time_t			touched;
	/* Locked by manager lock. */
	timer_type_t			type;
	os_time_t			absolute;
	os_time_t			interval;
	task_t				task;
	task_action_t			action;
	void *				arg;
	unsigned int			index;
	os_time_t			next_time;
	LINK(struct timer_t)		link;
};

#define TIMER_MANAGER_MAGIC		0x54494D4DU	/* TIMM. */
#define VALID_MANAGER(m)		((m) != NULL && \
					 (m)->magic == TIMER_MANAGER_MAGIC)

struct timer_manager_t {
	/* Not locked. */
	unsigned int			magic;
	mem_context_t			mctx;
	os_mutex_t			lock;
	/* Locked by manager lock. */
	boolean_t			done;
	LIST(struct timer_t)		timers;
	unsigned int			nscheduled;
	os_time_t			next_time;
	os_condition_t			wakeup;
	os_thread_t			thread;
	heap_t				heap;
};


static boolean_t
sooner(void *v1, void *v2) {
	timer_t t1, t2;

	t1 = v1;
	t2 = v2;
	REQUIRE(VALID_TIMER(t1));
	REQUIRE(VALID_TIMER(t2));

	if (os_time_compare(&t1->next_time, &t2->next_time) < 0)
		return (TRUE);
	return (FALSE);
}

static void
set_index(void *what, unsigned int index) {
	timer_t timer;

	timer = what;
	REQUIRE(VALID_TIMER(timer));

	timer->index = index;
}

static inline void
nexttime(timer_t timer, os_time_t *nowp, boolean_t first_time) {
	/* 
	 * The caller must ensure locking.
	 */

	if (timer->type == timer_type_ticker) {
		if (first_time) {
			if (timer->absolute.seconds == 0 &&
			    timer->absolute.nanoseconds == 0)
				timer->next_time = *nowp;
			else
				timer->next_time = timer->absolute;
		} else
			os_time_add(nowp, &timer->interval, &timer->next_time);
	} else {
		/* Idle timer. */
		if (os_time_compare(&timer->touched, nowp) <= 0) {
			os_time_t idle, remaining;

			os_time_subtract(nowp, &timer->touched, &idle);
			if (os_time_compare(&idle, &timer->interval) >= 0) {
				os_time_add(nowp, &timer->interval,
					    &timer->next_time);
			} else {
				
			}
		} else {
			/*
			 * Time touched is in the future!  Make it now.
			 */
			timer->touched = *nowp;
			os_time_add(nowp, &timer->interval, &timer->next_time);
		}
	}
}

static inline isc_result
schedule(timer_t timer, os_time_t *new_nextimep) {
	isc_result result;
	timer_manager_t manager;

	/* 
	 * The caller must ensure locking.
	 */
	
	manager = timer->manager;
	if (timer->index > 0) {
		/*
		 * Already scheduled.
		 */
		switch (os_time_compare(new_nextimep, &timer->next_time)) {
		case -1:
			heap_increased(manager->heap, timer->index);
			break;
		case 1:
			heap_decreased(manager->heap, timer->index);
			break;
		case 0:
			/* Nothing to do. */
			break;
		}
	} else {
		result = heap_insert(manager->heap, timer);
		if (result != ISC_R_SUCCESS) {
			INSIST(result == ISC_R_NOMEMORY);
			return (ISC_R_NOMEMORY);
		}
		manager->nscheduled++;
	}
	timer->next_time = *new_nextimep;

	/*
	 * If this timer is at the head of the queue, we must wake up the
	 * run thread so it doesn't sleep too long.
	 */
	if (timer->index == 1)
		BROADCAST(&manager->wakeup);

	return (ISC_R_SUCCESS);
}

static inline void
deschedule(timer_t timer) {
	boolean_t need_wakeup = FALSE;
	timer_manager_t manager;

	/* 
	 * The caller must ensure locking.
	 */

	manager = timer->manager;
	if (timer->index > 0) {
		if (timer->index == 1)
			need_wakeup = TRUE;
		heap_delete(manager->heap, timer->index);
		timer->index = 0;
		INSIST(manager->nscheduled > 0);
		manager->nscheduled--;
		if (need_wakeup)
			BROADCAST(&manager->wakeup);
	}
}

static void
destroy(timer_t timer) {
	timer_manager_t manager = timer->manager;

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
timer_create(timer_manager_t manager, timer_type_t type,
	     os_time_t absolute, os_time_t interval,
	     task_t task, task_action_t action, void *arg, timer_t *timerp)
{
	timer_t timer;
	isc_result result;
	os_time_t now, next_time;

	/*
	 * Create a new 'type' timer managed by 'manager'.  The timers
	 * parameters are specified by 'absolute' and 'interval'.  Events
	 * will be posted to 'task' and when dispatched 'action' will be
	 * called with 'arg' as the arg value.  The new timer is returned
	 * in 'timerp'.
	 */

	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(task != NULL);
	REQUIRE(action != NULL);
	REQUIRE(!(absolute.seconds == 0 && absolute.nanoseconds == 0 &&
		  interval.seconds == 0 && interval.nanoseconds == 0));
	REQUIRE(timerp != NULL && *timerp == NULL);

	/*
	 * Get current time.
	 */
	result = os_time_get(&now);
	if (result != ISC_R_SUCCESS) {
		unexpected_error(__FILE__, __LINE__,
				 "os_time_get() failed: %s",
				 isc_result_to_text(result));
		return (ISC_R_UNEXPECTED);
	}

	timer = mem_get(manager->mctx, sizeof *timer);
	if (timer == NULL)
		return (ISC_R_NOMEMORY);

	timer->magic = TIMER_MAGIC;
	timer->manager = manager;
	timer->references = 1;
	timer->touched = now;
	timer->type = type;
	timer->absolute = absolute;
	timer->interval = interval;
	timer->task = NULL;
	task_attach(task, &timer->task);
	timer->action = action;
	timer->arg = arg;
	timer->index = 0;
	if (!os_mutex_init(&timer->lock)) {
		mem_put(manager->mctx, timer, sizeof *timer);
		unexpected_error(__FILE__, __LINE__, "os_mutex_init() failed");
		return (ISC_R_UNEXPECTED);
	}

	LOCK(&manager->lock);

	/*
	 * Note we don't have to lock the timer like we normally would because
	 * there are no external references to it yet.
	 */

	APPEND(manager->timers, timer, link);

	/* XXX */
	os_time_add(&now, &timer->interval, &next_time);

	result = schedule(timer, &next_time);

	UNLOCK(&manager->lock);

	if (result == ISC_R_SUCCESS)
		*timerp = timer;

	return (result);
}

isc_result
timer_reset(timer_t timer, timer_type_t type,
	    os_time_t absolute, os_time_t interval)
{
	os_time_t now, next_time;
	timer_manager_t manager;
	isc_result result;

	/*
	 * Change the timer's type, absolute, and interval values to the
	 * given values.
	 */

	REQUIRE(VALID_TIMER(timer));
	manager = timer->manager;
	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(!(absolute.seconds == 0 && absolute.nanoseconds == 0 &&
		  interval.seconds == 0 && interval.nanoseconds == 0));

	/*
	 * Get current time.
	 */
	result = os_time_get(&now);
	if (result != ISC_R_SUCCESS) {
		unexpected_error(__FILE__, __LINE__,
				 "os_time_get() failed: %s",
				 isc_result_to_text(result));
		return (ISC_R_UNEXPECTED);
	}

	manager = timer->manager;

	LOCK(&manager->lock);
	LOCK(&timer->lock);

	timer->type = type;
	timer->absolute = absolute;
	timer->interval = interval;
	timer->touched = now;

	result = schedule(timer, &next_time);

	UNLOCK(&timer->lock);
	UNLOCK(&manager->lock);

	return (result);
}

isc_result
timer_shutdown(timer_t timer) {
	timer_manager_t manager;

	/*
	 * Make 'timer' inactive, and purge any pending timer events for
	 * this timer in the timer's task's event queue.
	 */

	REQUIRE(VALID_TIMER(timer));
	manager = timer->manager;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&manager->lock);
	LOCK(&timer->lock);

	task_purge_events(timer->task, timer, TASK_EVENT_ANYEVENT);
	deschedule(timer);
	
	UNLOCK(&timer->lock);
	UNLOCK(&manager->lock);

	return (ISC_R_SUCCESS);
}

isc_result
timer_touch(timer_t timer) {
	isc_result result;

	/*
	 * Set the last-touched time of 'timer' to the current time.
	 */

	REQUIRE(VALID_TIMER(timer));

	LOCK(&timer->lock);

	INSIST(timer->type == timer_type_idle);

	result = os_time_get(&timer->touched);
	if (result != ISC_R_SUCCESS) {
		unexpected_error(__FILE__, __LINE__,
				 "os_time_get() failed: %s",
				 isc_result_to_text(result));
		return (ISC_R_UNEXPECTED);
	}

	UNLOCK(&timer->lock);

	return (ISC_R_SUCCESS);
}

void
timer_attach(timer_t timer, timer_t *timerp) {
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
timer_detach(timer_t *timerp) {
	timer_t timer;
	boolean_t free_timer = FALSE;

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
		free_timer = TRUE;
	UNLOCK(&timer->lock);
	
	if (free_timer)
		destroy(timer);

	*timerp = NULL;
}

static void
dispatch(timer_manager_t manager, os_time_t *nowp) {
	boolean_t done = FALSE, post_event, need_schedule;
	task_event_t event;
	task_eventtype_t type;
	timer_t timer;
	os_time_t next_time;
	isc_result result;

	while (manager->nscheduled > 0 && !done) {
		timer = heap_element(manager->heap, 1);
		printf("next_time = %d.%09d\n", timer->next_time.seconds,
		       timer->next_time.nanoseconds);
		if (os_time_compare(nowp, &timer->next_time) >= 0) {
			post_event = FALSE;

			if (timer->type == timer_type_ticker) {
				type = TIMER_EVENT_TICK;
				post_event = TRUE;
				os_time_add(nowp, &timer->interval,
					    &next_time);
				need_schedule = TRUE;
			} else if (os_time_compare(nowp,
						   &timer->absolute) >= 0) {
				type = TIMER_EVENT_LIFE;
				post_event = TRUE;
				need_schedule = FALSE;
			} else {
				/*
				 * Check if idle too long.
				 */
				/* XXX */
				post_event = FALSE;
				need_schedule = FALSE;
			}

			if (post_event) {
				printf("dispatch to %p\n", timer->task);
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
					unexpected_error(__FILE__, __LINE__,
						 "couldn't allocate event");
			}
					
			timer->index = 0;
			heap_delete(manager->heap, 1);
			manager->nscheduled--;

			if (need_schedule) {
				result = schedule(timer, &next_time);
				if (result != ISC_R_SUCCESS)
					unexpected_error(__FILE__, __LINE__,
						"couldn't schedule timer: %s",
							 result);
			}
		} else {
			manager->next_time = timer->next_time;
			done = TRUE;
		}
	} 
}

static void *
run(void *uap) {
	timer_manager_t manager = uap;
	struct timespec ts;
	boolean_t timeout;
	os_time_t now;

	LOCK(&manager->lock);
	while (!manager->done) {
		INSIST(os_time_get(&now) == ISC_R_SUCCESS);

		printf("timer run thread awake\n");

		dispatch(manager, &now);

		if (manager->nscheduled > 0) {
			ts.tv_sec = manager->next_time.seconds;
			ts.tv_nsec = manager->next_time.nanoseconds;
			WAITUNTIL(&manager->wakeup, &manager->lock, &ts,
				  &timeout);
		} else
			WAIT(&manager->wakeup, &manager->lock);
	}
	UNLOCK(&manager->lock);

	return (NULL);
}

isc_result
timer_manager_create(mem_context_t mctx, timer_manager_t *managerp) {
	timer_manager_t manager;
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
	manager->done = FALSE;
	INIT_LIST(manager->timers);
	manager->nscheduled = 0;
	manager->next_time.seconds = 0;
	manager->next_time.nanoseconds = 0;
	manager->heap = NULL;
	result = heap_create(mctx, sooner, set_index, 0, &manager->heap);
	if (result != ISC_R_SUCCESS) {
		INSIST(result == ISC_R_NOMEMORY);
		mem_put(mctx, manager, sizeof *manager);
		return (ISC_R_NOMEMORY);
	}
	if (!os_mutex_init(&manager->lock)) {
		heap_destroy(&manager->heap);
		mem_put(mctx, manager, sizeof *manager);
		unexpected_error(__FILE__, __LINE__, "os_mutex_init() failed");
		return (ISC_R_UNEXPECTED);
	}
	if (!os_condition_init(&manager->wakeup)) {
		(void)os_mutex_destroy(&manager->lock);
		heap_destroy(&manager->heap);
		mem_put(mctx, manager, sizeof *manager);
		unexpected_error(__FILE__, __LINE__,
				 "os_condition_init() failed");
		return (ISC_R_UNEXPECTED);
	}
	if (!os_thread_create(run, manager, &manager->thread)) {
		(void)os_condition_destroy(&manager->wakeup);
		(void)os_mutex_destroy(&manager->lock);
		heap_destroy(&manager->heap);
		mem_put(mctx, manager, sizeof *manager);
		unexpected_error(__FILE__, __LINE__,
				 "os_thread_create() failed");
		return (ISC_R_UNEXPECTED);
	}

	*managerp = manager;

	return (ISC_R_SUCCESS);
}

void
timer_manager_destroy(timer_manager_t *managerp) {
	timer_manager_t manager;

	/*
	 * Destroy a timer manager.
	 */

	REQUIRE(managerp != NULL);
	manager = *managerp;
	REQUIRE(VALID_MANAGER(manager));

	LOCK(&manager->lock);

	REQUIRE(EMPTY(manager->timers));
	manager->done = TRUE;

	UNLOCK(&manager->lock);

	BROADCAST(&manager->wakeup);

	/*
	 * Wait for thread to exit.
	 */
	if (!os_thread_join(manager->thread))
		unexpected_error(__FILE__, __LINE__,
				 "os_thread_join() failed");

	/*
	 * Clean up.
	 */
	(void)os_condition_destroy(&manager->wakeup);
	(void)os_mutex_destroy(&manager->lock);
	heap_destroy(&manager->heap);
	manager->magic = 0;
	mem_put(manager->mctx, manager, sizeof *manager);

	*managerp = NULL;
}
