/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include <isc/app.h>
#include <isc/boolean.h>
#include <isc/mutex.h>
#include <isc/event.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/util.h>

static isc_eventlist_t		on_run;
static isc_mutex_t		lock;
static isc_boolean_t		shutdown_requested = ISC_FALSE;
static isc_boolean_t		running = ISC_FALSE;
/*
 * We assume that 'want_shutdown' can be read and written atomically.
 */
static isc_boolean_t		want_shutdown = ISC_FALSE;
/*
 * We assume that 'want_reload' can be read and written atomically.
 */
static isc_boolean_t		want_reload = ISC_FALSE;

#ifdef HAVE_LINUXTHREADS
/*
 * Linux has sigwait(), but it appears to prevent signal handlers from
 * running, even if they're not in the set being waited for.  This makes
 * it impossible to get the default actions for SIGILL, SIGSEGV, etc.
 * Instead of messing with it, we just use sigsuspend() instead.
 */
#undef HAVE_SIGWAIT
/*
 * We need to remember which thread is the main thread...
 */
static pthread_t		main_thread;
#endif

#ifndef HAVE_SIGWAIT
static void
exit_action(int arg) {
        UNUSED(arg);
	want_shutdown = ISC_TRUE;
}

static void
reload_action(int arg) {
        UNUSED(arg);
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
	result = handle_signal(SIGINT, exit_action);
	if (result != ISC_R_SUCCESS)
		return (result);
	result = handle_signal(SIGTERM, exit_action);
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
	 * blocked by default, ensuring that only the thread that calls
	 * sigwait() for them will get those signals.
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
	
	ISC_LIST_APPEND(on_run, event, ev_link);

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
			next_event = ISC_LIST_NEXT(event, ev_link);
			ISC_LIST_UNLINK(on_run, event, ev_link);
			task = event->ev_sender;
			event->ev_sender = (void *)&running;
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

	while (!want_shutdown) {
#ifdef HAVE_SIGWAIT
		/*
		 * Wait for SIGHUP, SIGINT, or SIGTERM.
		 */
		if (sigemptyset(&sset) != 0 ||
		    sigaddset(&sset, SIGHUP) != 0 ||
		    sigaddset(&sset, SIGINT) != 0 ||
		    sigaddset(&sset, SIGTERM) != 0) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_app_run() sigsetops: %s", 
					 strerror(errno));
			return (ISC_R_UNEXPECTED);
		}

#ifndef HAVE_UNIXWARE_SIGWAIT
		result = sigwait(&sset, &sig);
		if (result == 0) {
			if (sig == SIGINT ||
			    sig == SIGTERM)
				want_shutdown = ISC_TRUE;
			else if (sig == SIGHUP)
				want_reload = ISC_TRUE;
		}

#else /* Using UnixWare sigwait semantics. */
		sig = sigwait(&sset);
		if (sig >= 0) {
			if (sig == SIGINT ||
			    sig == SIGTERM)
				want_shutdown = ISC_TRUE;
			else if (sig == SIGHUP)
				want_reload = ISC_TRUE;
		}

#endif /* HAVE_UNIXWARE_SIGWAIT */
#else  /* Don't have sigwait(). */
		/*
		 * Listen for all signals.
		 */
		if (sigemptyset(&sset) != 0) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_app_run() sigsetops: %s", 
					 strerror(errno));
			return (ISC_R_UNEXPECTED);
		}
		result = sigsuspend(&sset);
#endif /* HAVE_SIGWAIT */

		if (want_reload) {
			want_reload = ISC_FALSE;
			return (ISC_R_RELOAD);
		}
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
