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
#include <isc/task.h>
#include <isc/event.h>
#include <isc/boolean.h>
#include <isc/mutex.h>

#include "../util.h"	/* XXX */

static isc_eventlist_t		on_run;
static isc_mutex_t		lock;
static isc_boolean_t		shutdown_requested = ISC_FALSE;

#ifdef HAVE_LINUXTHREADS
static pthread_t		main_thread;
#endif

#ifndef HAVE_SIGWAIT
static void
empty_action(int arg) {
	(void)arg;
}
#endif

isc_result_t
isc_app_start(void) {
	isc_result_t result;
	int presult;
	sigset_t sset;
#ifndef HAVE_SIGWAIT
	struct sigaction sa;
#endif

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
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = empty_action;
	if (sigfillset(&sa.sa_mask) != 0 ||
	    sigaction(SIGINT, &sa, NULL) < 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_run() SIGINT setup: %s", 
				 strerror(errno));
		return (ISC_R_UNEXPECTED);
	}
	if (sigfillset(&sa.sa_mask) != 0 ||
	    sigaction(SIGTERM, &sa, NULL) < 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_run() SIGTERM setup: %s", 
				 strerror(errno));
		return (ISC_R_UNEXPECTED);
	}
#endif

	/*
	 * Block SIGINT and SIGTERM.
	 *
	 * If isc_app_start() is called from the main thread before any other
	 * threads have been created, then the pthread_sigmask() call below
	 * will result in all threads having SIGINT and SIGTERM blocked by
	 * default.
	 */
	if (sigemptyset(&sset) != 0 ||
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
isc_app_run(void) {
	int result;
	sigset_t sset;
#if 0
	isc_event_t *event, *next_event;
#endif
#ifdef HAVE_SIGWAIT
	int sig;
#endif

	/*
	 * Run an ISC library application.
	 */

#ifdef HAVE_LINUXTHREADS
	REQUIRE(main_thread == pthread_self());
#endif

#if 0
	/*
	 * Post any on-run events (in LIFO order).
	 */
	for (event = ISC_LIST_HEAD(on_run);
	     event != NULL;
	     event = next_event) {
		next_event = ISC_LIST_NEXT(event, link);
		ISC_LIST_DEQUEUE(task->on_run, event, link);
		isc_task_send(task, &event);
		isc_task_detach(&task);
	}
#endif

#ifdef HAVE_SIGWAIT
	/*
	 * Wait for SIGINT or SIGTERM.
	 */
	if (sigemptyset(&sset) != 0 ||
	    sigaddset(&sset, SIGINT) != 0 ||
	    sigaddset(&sset, SIGTERM) != 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_run() sigsetops: %s", 
				 strerror(errno));
		return (ISC_R_UNEXPECTED);
	}
	result = sigwait(&sset, &sig);
#else
	/*
	 * Block all signals except for SIGINT and SIGTERM, and then
	 * wait for one of them to occur.
	 */
	if (sigfillset(&sset) != 0 ||
	    sigdelset(&sset, SIGINT) != 0 ||
	    sigdelset(&sset, SIGTERM) != 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_run() sigsetops: %s", 
				 strerror(errno));
		return (ISC_R_UNEXPECTED);
	}
	result = sigsuspend(&sset);
#endif

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_app_shutdown(void) {
	isc_boolean_t want_kill = ISC_TRUE;

	/*
	 * Request application shutdown.
	 */

	LOCK(&lock);
	
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

void
isc_app_finish(void) {
	/*
	 * Finish an ISC library application.
	 */

	(void)isc_mutex_destroy(&lock);
}
