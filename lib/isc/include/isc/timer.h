
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
 *	'once' timers generate an idle timeout event if they are idle for too
 *	long, and generate a life timeout event if their lifetime expires.
 *	They are used to implement both (possibly expiring) idle timers and
 *	'one-shot' timers.
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
 *	The caller must ensure that isc_timermgr_destroy() is called only
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
#include <isc/boolean.h>
#include <isc/time.h>
#include <isc/task.h>
#include <isc/event.h>


/***
 *** Types
 ***/

typedef struct isc_timer	*isc_timer_t;
typedef struct isc_timermgr	*isc_timermgr_t;

typedef enum {
	isc_timertype_ticker = 0, isc_timertype_once
} isc_timertype_t;

typedef struct isc_timerevent {
	struct isc_event	common;
	/* XXX Anything else? XXX */
} *isc_timerevent_t;

#define ISC_TIMEREVENT_TICK	(ISC_EVENTCLASS_TIMER + 1)
#define ISC_TIMEREVENT_IDLE	(ISC_EVENTCLASS_TIMER + 2)
#define ISC_TIMEREVENT_LIFE	(ISC_EVENTCLASS_TIMER + 3)


/***
 *** Timer and Timer Manager Functions
 ***
 *** Note: all Ensures conditions apply only if the result is success for
 *** those functions which return an isc_result_t.
 ***/

isc_result_t
isc_timer_create(isc_timermgr_t manager,
		 isc_timertype_t type,
		 os_time_t expires,
		 os_time_t interval,
		 isc_task_t task,
		 isc_taskaction_t action,
		 void *arg,
		 isc_timer_t *timerp);
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
 *	For once timers, 'expires' specifies the time when a life timeout
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
 *	An idle timeout will not be generated until at least Now + the
 *	timer's interval if 'timer' is a once timer with a non-zero
 *	interval.
 *
 * Returns:
 *
 *	Success
 *	No memory
 *	Unexpected error
 */

isc_result_t
isc_timer_reset(isc_timer_t timer,
		isc_timertype_t type,
		os_time_t expires,
		os_time_t interval,
		isc_boolean_t purge);
/*
 * Change the timer's type, expires, and interval values to the given
 * values.  If 'purge' is TRUE, any pending events from this timer
 * are purged from its task's event queue.
 *	
 * Requires:
 *
 *	'timer' is a valid timer
 *
 *	The same requirements that isc_timer_create() imposes on 'type',
 *	'expires' and 'interval' apply.
 *
 * Ensures:
 *
 *	An idle timeout will not be generated until at least Now + the
 *	timer's interval if 'timer' is a once timer with a non-zero
 *	interval.
 *
 * Returns:
 *
 *	Success
 *	No memory
 *	Unexpected error
 */

isc_result_t
isc_timer_touch(isc_timer_t timer);
/*
 * Set the last-touched time of 'timer' to the current time.
 *
 * Requires:
 *
 *	'timer' is a valid once timer.
 *
 * Ensures:
 *
 *	An idle timeout will not be generated until at least Now + the
 *	timer's interval if 'timer' is a once timer with a non-zero
 *	interval.
 *
 * Returns:
 *
 *	Success
 *	Unexpected error
 */

void
isc_timer_attach(isc_timer_t timer, isc_timer_t *timerp);
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
isc_timer_detach(isc_timer_t *timerp);
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

isc_result_t
isc_timermgr_create(isc_memctx_t mctx, isc_timermgr_t *managerp);
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
 *	'managerp' points to a NULL isc_timermgr_t.
 *
 * Ensures:
 *
 *	'*managerp' is a valid isc_timermgr_t.
 *
 * Returns:
 *
 *	Success
 *	No memory
 *	Unexpected error
 */

void
isc_timermgr_destroy(isc_timermgr_t *);
/*
 * Destroy a timer manager.
 *
 * Notes:
 *	
 *	This routine blocks until there are no timers left in the manager,
 *	so if the caller holds any timer references using the manager, it
 *	must detach them before calling isc_timermgr_destroy() or it will
 *	block forever.
 *
 * Requires:
 *
 *	'*managerp' is a valid isc_timermgr_t.
 *
 * Ensures:
 *
 *	*managerp == NULL
 *
 *	All resources used by the manager have been freed.
 */

#endif /* ISC_TIMER_H */
