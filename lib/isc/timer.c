
#include <stddef.h>
#include <stdlib.h>

#include <isc/assertions.h>
#include <isc/timer.h>

/*
 * We use macros instead of calling the os_ routines directly because
 * the capital letters make the locking stand out.
 *
 * We INSIST that they succeed since there's no way for us to continue
 * if they fail.
 */
#define LOCK(lp)		INSIST(os_mutex_lock((lp)))
#define UNLOCK(lp)		INSIST(os_mutex_unlock((lp)))
#define BROADCAST(cvp)		INSIST(os_condition_broadcast((cvp)))


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
	void *				arg;
	int				index;
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
	LIST(struct timer_t)		timers;
	os_time_t			next_time;
	os_thread_t			thread;
	heap_context			heap;
};

static inline void
schedule(timer_t timer, os_time_t *now, boolean_t first_time) {
	/* 
	 * The caller must ensure locking.
	 */

	if (timer->type == timer_type_ticker) {
		if (first_time) {
			if (timer->absolute.seconds == 0 &&
			    timer->absolute.nanoseconds == 0)
				timer->next_time = now;
			else
				timer->next_time = timer->absolute;
		} else
			os_time_add(&now, &timer->interval, &timer->next_time);
	} else {
		/* Idle timer. */
		if (os_time_compare(&timer->touched, &now) <= 0) {
			os_time_t idle, remaining;

			os_time_subtract(&now, &timer->touched, &idle);
			if (os_time_compare(&idle, &timer->interval) >= 0) {
				os_time_add(&now, &timer->interval,
					    &timer->next_time);
			} else {
				
			}
		} else {
			/*
			 * Time touched is in the future!  Make it now.
			 */
			timer->touched = now;
			os_time_add(&now, &timer->interval, &timer->next_time);
		}
	}
}

static inline void
deschedule(timer_t) {
	/* 
	 * The caller must ensure locking.
	 */

}

static void
destroy(timer_t timer) {
	timer_manager_t manager = timer->manager;
	isc_result result;

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
	     task_t task, void *arg, timer_t *timerp)
{
	timer_t timer;
	isc_result result;
	os_time_t now;

	/*
	 * Create a new 'type' timer managed by 'manager'.  The timers
	 * parameters are specified by 'absolute' and 'interval'.  Events
	 * will be posted to 'task' and will use 'arg' as the arg value.
	 * The new timer is returned in 'timerp'.
	 */

	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(task != NULL);
	REQUIRE(!(absolute->seconds == 0 && absolute->nanoseconds == 0 &&
		  interval->seconds == 0 && interval->nanoseconds == 0));
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
	timer->type = type;
	timer->absolute = absolute;
	timer->interval = interval;
	timer->task = NULL;
	task_attach(task, &timer->task);
	timer->arg = arg;
	timer->touched = now;
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
	result = schedule(timer, &now, TRUE);

	UNLOCK(&manager->lock);

	if (result == ISC_R_SUCCESS)
		*timerp = timer;

	return (result);
}

isc_result
timer_reset(timer_t timer, timer_type_t type,
	    os_time_t absolute, os_time_t interval)
{
	os_time_t now;
	timer_manager_t manager;
	isc_result result;

	/*
	 * Change the timer's type, absolute, and interval values to the
	 * given values.
	 */

	REQUIRE(VALID_TIMER(timer));
	manager = timer->manager;
	REQUIRE(VALID_MANAGER(manager));
	REQUIRE(!(absolute->seconds == 0 && absolute->nanoseconds == 0 &&
		  interval->seconds == 0 && interval->nanoseconds == 0));

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

	result = schedule(timer, &now, FALSE);

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

	REQUIRE(VALID_TIMER(timer));
	REQUIRE(timerp != NULL && *timerp == NULL);

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

isc_result
timer_manager_create(mem_context_t mctx, timer_manager_t *managerp);
/*
 * Create a timer manager.
 *
 * Notes:
 *
 *	All memory will be allocated in memory context 'mctx'.
 *
 * Requires:
 *
 *	'mctx' is a valid memory context.
 *
 *	'managerp' points to a NULL timer_manager_t.
 *
 * Ensures:
 *
 *	'*managerp' is a valid timer_manager_t.
 *
 * Returns:
 *
 *	Success
 *	No memory
 *	Unexpected error
 */

void
timer_manager_destroy(timer_manager_t *);
/*
 * Destroy a timer manager.
 *
 * Notes:
 *	
 *	This routine blocks until there are no timers left in the manager,
 *	so if the caller holds any timer references using the manager, it
 *	must detach them before calling timer_manager_destroy() or it will
 *	block forever.
 *
 * Requires:
 *
 *	'*managerp' is a valid timer_manager_t.
 *
 * Ensures:
 *
 *	*managerp == NULL
 *
 *	All resources used by the manager have been freed.
 */

#endif /* ISC_TIMER_H */
