/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#include <config.h>

#include <pthread.h>

#include <sys/types.h>

#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include <isc/app.h>
#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/boolean.h>
#include <isc/mutex.h>
#include <isc/event.h>
#include <isc/util.h>

static isc_eventlist_t		on_run;
static isc_mutex_t		lock;
static isc_boolean_t		shutdown_requested = ISC_FALSE;
static isc_boolean_t		running = ISC_FALSE;
/*
 * We assume that 'want_reload' can be read and written atomically.
 */
static isc_boolean_t		want_reload = ISC_FALSE;

#ifdef HAVE_LINUXTHREADS
static pthread_t		main_thread;
#endif

#ifndef HAVE_SIGWAIT
static void
no_action(int arg) {
        (void)arg;
}

static void
reload_action(int arg) {
        (void)arg;
	want_reload = ISC_TRUE;
}
#endif

static isc_result_t
handle_signal(int sig, void (*handler)(int)) {
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler;

	if (sigfillset(&sa.sa_mask) != 0 ||
	    sigaction(sig, &sa, NULL) < 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "handle_signal() %d setup: %s", sig,
				 strerror(errno));
		return (ISC_R_UNEXPECTED);
	}
	
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_app_start(void) {
	isc_result_t result;
	int presult;
	sigset_t sset;

	/*
	 * Start an ISC library application.
	 */

#ifdef NEED_PTHREAD_INIT
	/*
	 * BSDI 3.1 seg faults in pthread_sigmask() if we don't do this.
	 */
	presult = pthread_init();
	if (presult != 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_start() pthread_init: %s", 
				 strerror(presult));
		return (ISC_R_UNEXPECTED);
	}
#endif

#ifdef HAVE_LINUXTHREADS
	main_thread = pthread_self();
#endif

	result = isc_mutex_init(&lock);
	if (result != ISC_R_SUCCESS)
		return (result);

#ifndef HAVE_SIGWAIT
	/*
	 * Install do-nothing handlers for SIGINT and SIGTERM.
	 *
	 * We install them now because BSDI 3.1 won't block
	 * the default actions, regardless of what we do with
	 * pthread_sigmask().
	 */
	result = handle_signal(SIGINT, no_action);
	if (result != ISC_R_SUCCESS)
		return (result);
	result = handle_signal(SIGTERM, no_action);
	if (result != ISC_R_SUCCESS)
		return (result);
#endif

	/*
	 * Always ignore SIGPIPE.
	 */
	result = handle_signal(SIGPIPE, SIG_IGN);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Block SIGHUP, SIGINT, SIGTERM.
	 *
	 * If isc_app_start() is called from the main thread before any other
	 * threads have been created, then the pthread_sigmask() call below
	 * will result in all threads having SIGHUP, SIGINT and SIGTERM
	 * blocked by default.
	 */
	if (sigemptyset(&sset) != 0 ||
	    sigaddset(&sset, SIGHUP) != 0 ||
	    sigaddset(&sset, SIGINT) != 0 ||
	    sigaddset(&sset, SIGTERM) != 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_start() sigsetops: %s", 
				 strerror(errno));
		return (ISC_R_UNEXPECTED);
	}
	presult = pthread_sigmask(SIG_BLOCK, &sset, NULL);
	if (presult != 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_start() pthread_sigmask: %s", 
				 strerror(presult));
		return (ISC_R_UNEXPECTED);
	}

	ISC_LIST_INIT(on_run);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_app_onrun(isc_mem_t *mctx, isc_task_t *task, isc_taskaction_t action,
	      void *arg)
{
	isc_event_t *event;
	isc_task_t *cloned_task = NULL;
	isc_result_t result;

	/*
	 * Request delivery of an event when the application is run.
	 */

	LOCK(&lock);

	if (running) {
		result = ISC_R_ALREADYRUNNING;
		goto unlock;
	}

	/*
	 * Note that we store the task to which we're going to send the event
	 * in the event's "sender" field.
	 */
	isc_task_attach(task, &cloned_task);
	event = isc_event_allocate(mctx, cloned_task, ISC_APPEVENT_SHUTDOWN,
				   action, arg, sizeof *event);
	if (event == NULL) {
		result = ISC_R_NOMEMORY;
		goto unlock;
	}
	
	ISC_LIST_APPEND(on_run, event, link);

	result = ISC_R_SUCCESS;

 unlock:
	UNLOCK(&lock);

	return (result);
}

isc_result_t
isc_app_run(void) {
	int result;
	sigset_t sset;
	isc_event_t *event, *next_event;
	isc_task_t *task;
#ifdef HAVE_SIGWAIT
	int sig;
#endif

	/*
	 * Run an ISC library application.
	 */

#ifdef HAVE_LINUXTHREADS
	REQUIRE(main_thread == pthread_self());
#endif

	LOCK(&lock);

	if (!running) {
		running = ISC_TRUE;

		/*
		 * Post any on-run events (in FIFO order).
		 */
		for (event = ISC_LIST_HEAD(on_run);
		     event != NULL;
		     event = next_event) {
			next_event = ISC_LIST_NEXT(event, link);
			ISC_LIST_UNLINK(on_run, event, link);
			task = event->sender;
			event->sender = (void *)&running;
			isc_task_sendanddetach(&task, &event);
		}

	}
	
	UNLOCK(&lock);

#ifndef HAVE_SIGWAIT
	/*
	 * Catch SIGHUP.
	 *
	 * We do this here to ensure that the signal handler is installed
	 * (i.e. that it wasn't a "one-shot" handler).
	 */
	result = handle_signal(SIGHUP, reload_action);
	if (result != ISC_R_SUCCESS)
		return (ISC_R_SUCCESS);
#endif

	/*
	 * There is no danger if isc_app_shutdown() is called before we wait
	 * for signals.  Signals are blocked, so any such signal will simply
	 * be made pending and we will get it when we call sigwait().
	 */

#ifdef HAVE_SIGWAIT
	/*
	 * Wait for SIGHUP, SIGINT, or SIGTERM.
	 */
	if (sigemptyset(&sset) != 0 ||
#ifdef HAVE_LINUXTHREADS
	    sigaddset(&sset, SIGABRT) != 0 ||
#endif
	    sigaddset(&sset, SIGHUP) != 0 ||
	    sigaddset(&sset, SIGINT) != 0 ||
	    sigaddset(&sset, SIGTERM) != 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_run() sigsetops: %s", 
				 strerror(errno));
		return (ISC_R_UNEXPECTED);
	}
	result = sigwait(&sset, &sig);
	/*
	 * sigwait() prevents signal handlers from running, so we have
	 * to check if it was SIGHUP ourselves.
	 */
	if (result == 0 && sig == SIGHUP)
		want_reload = ISC_TRUE;
#else
	/*
	 * Block all signals except for SIGHUP, SIGINT, and SIGTERM, and then
	 * wait for one of them to occur.
	 */
	if (sigfillset(&sset) != 0 ||
	    sigdelset(&sset, SIGHUP) != 0 ||
	    sigdelset(&sset, SIGINT) != 0 ||
	    sigdelset(&sset, SIGTERM) != 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_run() sigsetops: %s", 
				 strerror(errno));
		return (ISC_R_UNEXPECTED);
	}
	result = sigsuspend(&sset);
#endif

	if (want_reload) {
		/*
		 * SIGHUP is blocked now (it's only unblocked when we're
		 * calling sigsuspend()/sigwait()), so there's no race with
		 * the reload_action signal handler when we clear want_reload.
		 */
		want_reload = ISC_FALSE;
		return (ISC_R_RELOAD);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_app_shutdown(void) {
	isc_boolean_t want_kill = ISC_TRUE;

	/*
	 * Request application shutdown.
	 */

	LOCK(&lock);
	
	REQUIRE(running);

	if (shutdown_requested)
		want_kill = ISC_FALSE;
	else
		shutdown_requested = ISC_TRUE;

	UNLOCK(&lock);

	if (want_kill) {
#ifdef HAVE_LINUXTHREADS
		int result;
		
		result = pthread_kill(main_thread, SIGTERM);
		if (result != 0) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_app_shutdown() pthread_kill: %s",
					 strerror(result));
			return (ISC_R_UNEXPECTED);
		}
#else
		if (kill(getpid(), SIGTERM) < 0) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_app_shutdown() kill: %s",
					 strerror(errno));
			return (ISC_R_UNEXPECTED);
		}
#endif
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_app_reload(void) {
	isc_boolean_t want_kill = ISC_TRUE;

	/*
	 * Request application reload.
	 */

	LOCK(&lock);
	
	REQUIRE(running);

	/*
	 * Don't send the reload signal if we're shutting down.
	 */
	if (shutdown_requested)
		want_kill = ISC_FALSE;

	UNLOCK(&lock);

	if (want_kill) {
#ifdef HAVE_LINUXTHREADS
		int result;
		
		result = pthread_kill(main_thread, SIGHUP);
		if (result != 0) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_app_shutdown() pthread_kill: %s",
					 strerror(result));
			return (ISC_R_UNEXPECTED);
		}
#else
		if (kill(getpid(), SIGHUP) < 0) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_app_shutdown() kill: %s",
					 strerror(errno));
			return (ISC_R_UNEXPECTED);
		}
#endif
	}

	return (ISC_R_SUCCESS);
}

void
isc_app_finish(void) {
	/*
	 * Finish an ISC library application.
	 */

	(void)isc_mutex_destroy(&lock);
}
