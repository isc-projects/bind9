
#ifndef ISC_TIMER_H
#define ISC_TIMER_H 1

/*****
 ***** Module Info
 *****/

/*
 * Timers
 *
 * Provides timers which are event sources in the task system.
 *
 * Two kinds of timer are supported.
 *
 *	'ticker' timers generate a periodic tick event.
 *
 *	'idle' timers generate an idle timeout event if they are idle for too
 *	long, and generate a life timeout event if their lifetime expires.
 *	They are used to implement both expiring idle timers and 'one-shot'
 *	timers.
 *
 * Note: unlike in eventlib, a timer's resources are never reclaimed merely
 * because it generated an event.  A timer reference will remain valid until
 * it is explicitly detached.
 *
 * MP:
 *	The module ensures appropriate synchronization of data structures it
 *	creates and manipulates.
 *
 *	Clients of this module must not be holding a timer's task's lock when
 *	making a call that affects that timer.  Failure to follow this rule
 *	can result in deadlock.
 *
 *	The caller must ensure that timer_manager_destroy() is called only
 *	once for a given manager.
 *
 * Reliability:
 *	No anticipated impact.
 *
 * Resources:
 *	<TBS>
 *
 * Security:
 *	No anticipated impact.
 *
 * Standards:
 *	None.
 */


/***
 *** Imports
 ***/

#include <isc/result.h>
#include <isc/time.h>
#include <isc/task.h>
#include <isc/event.h>


/***
 *** Types
 ***/

typedef struct timer_t		*timer_t;
typedef struct timer_manager_t	*timer_manager_t;

typedef enum {
	timer_type_ticker = 0, timer_type_idle
} timer_type_t;

typedef struct timer_event {
	struct task_event	common;
	/* XXX Anything else? XXX */
} *timer_event_t;

#define TIMER_EVENT_TICK	(EVENT_CLASS_TIMER + 1)
#define TIMER_EVENT_IDLE	(EVENT_CLASS_TIMER + 2)
#define TIMER_EVENT_LIFE	(EVENT_CLASS_TIMER + 3)


/***
 *** Timer and Timer Manager Functions
 ***
 *** Note: all Ensures conditions apply only if the result is success for
 *** those functions which return an isc_result.
 ***/

isc_result
timer_create(timer_manager_t manager,
	     timer_type_t type,
	     os_time_t expires,
	     os_time_t interval,
	     task_t task,
	     task_action_t action,
	     void *arg,
	     timer_t *timerp);
/*
 * Create a new 'type' timer managed by 'manager'.  The timers parameters
 * are specified by 'expires' and 'interval'.  Events will be posted to
 * 'task' and when dispatched 'action' will be called with 'arg' as the
 * arg value.  The new timer is returned in 'timerp'.
 *
 * Notes:
 *
 *	For ticker timers, the timer will generate a 'tick' event every
 *	'interval' seconds.  The value of 'expires' is ignored.
 *
 *	For idle timers, 'expires' specifies the time when a life timeout
 *	event should be generated.  If 'expires' is 0, then no life
 *	timeout will be generated.  'interval' specifies how long the timer
 *	can be idle before it generates an idle timeout.  If 0, then no
 *	idle timeout will be generated.
 *
 * Requires:
 *
 *	'manager' is a valid manager
 *
 *	'task' is a valid task
 *
 *	'action' is a valid action
 *
 *	'expires' and 'interval' may not both be 0
 *
 *	'timerp' is a valid pointer, and *timerp == NULL
 *
 * Ensures:
 *
 *	'*timerp' is attached to the newly created timer
 *
 *	The timer is attached to the task
 *
 *	If 'type' is idle, then the last-touched time is set to the
 *	current time.
 *
 * Returns:
 *
 *	Success
 *	No memory
 *	Unexpected error
 */

isc_result
timer_reset(timer_t timer,
	    timer_type_t type,
	    os_time_t expires,
	    os_time_t interval);
/*
 * Change the timer's type, expires, and interval values to the given
 * values.
 *	
 * Requires:
 *
 *	'timer' is a valid timer
 *
 *	The same requirements that timer_create() imposes on 'type',
 *	'expires' and 'interval' apply.
 *
 * Ensures:
 *
 *	If 'type' is idle, then the last-touched time is set to the
 *	current time.
 *
 * Returns:
 *
 *	Success
 *	No memory
 *	Unexpected error
 */

isc_result
timer_shutdown(timer_t timer);
/*
 * Make 'timer' inactive, and purge any pending timer events for this timer
 * in the timer's task's event queue.
 *
 * Requires:
 *
 *	'timer' is a valid timer
 *
 * Ensures:
 *
 *	No events for this timer remain in its task's event queue.
 *
 * Returns:
 *
 *	Success
 *	Unexpected error
 */

isc_result
timer_touch(timer_t timer);
/*
 * Set the last-touched time of 'timer' to the current time.
 *
 * Requires:
 *
 *	'timer' is a valid idle timer.
 *
 * Ensures:
 *
 *	An idle timeout will not be generated until at least Now + the
 *	timer's interval if 'timer' is an idle timer.
 *
 * Returns:
 *
 *	Success
 *	Unexpected error
 */

void
timer_attach(timer_t timer, timer_t *timerp);
/*
 * Attach *timerp to timer.
 *
 * Requires:
 *
 *	'timer' is a valid timer.
 *
 *	'timerp' points to a NULL timer.
 *
 * Ensures:
 *
 *	*timerp is attached to timer.
 */

void 
timer_detach(timer_t *timerp);
/*
 * Detach *timerp from its timer.
 *
 * Requires:
 *
 *	'timerp' points to a valid timer.
 *
 * Ensures:
 *
 *	*timerp is NULL.
 *
 *	If '*timerp' is the last reference to the timer,
 *	then:
 *
 *		The timer will be shutdown
 *
 *		The timer will detach from its task
 *
 *		All resources used by the timer have been freed
 */

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
