/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <config.h>

#include <sys/param.h>	/* Openserver 5.0.6A and FD_SETSIZE */
#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#endif

#include <isc/app.h>
#include <isc/condition.h>
#include <isc/mem.h>
#include <isc/msgs.h>
#include <isc/mutex.h>
#include <isc/event.h>
#include <isc/platform.h>
#include <isc/strerror.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/time.h>
#include <isc/util.h>

#include <pthread.h>

/*%
 * For BIND9 internal applications built with threads, we use a single app
 * context and let multiple worker, I/O, timer threads do actual jobs.
 * For other cases (including BIND9 built without threads) an app context acts
 * as an event loop dispatching various events.
 */
static pthread_t		blockedthread;

/*%
 * The following are intended for internal use (indicated by "isc__"
 * prefix) but are not declared as static, allowing direct access from
 * unit tests etc.
 */
isc_result_t isc__app_start(void);
isc_result_t isc__app_ctxstart(isc_appctx_t *ctx);
isc_result_t isc__app_onrun(isc_mem_t *mctx, isc_task_t *task,
			    isc_taskaction_t action, void *arg);
isc_result_t isc__app_ctxrun(isc_appctx_t *ctx);
isc_result_t isc__app_run(void);
isc_result_t isc__app_ctxshutdown(isc_appctx_t *ctx);
isc_result_t isc__app_shutdown(void);
isc_result_t isc__app_reload(void);
isc_result_t isc__app_ctxsuspend(isc_appctx_t *ctx);
void isc__app_ctxfinish(isc_appctx_t *ctx);
void isc__app_finish(void);
void isc__app_block(void);
void isc__app_unblock(void);
isc_result_t isc__appctx_create(isc_mem_t *mctx, isc_appctx_t **ctxp);
void isc__appctx_destroy(isc_appctx_t **ctxp);
void isc__appctx_settaskmgr(isc_appctx_t *ctx, isc_taskmgr_t *taskmgr);
void isc__appctx_setsocketmgr(isc_appctx_t *ctx, isc_socketmgr_t *socketmgr);
void isc__appctx_settimermgr(isc_appctx_t *ctx, isc_timermgr_t *timermgr);
isc_result_t isc__app_ctxonrun(isc_appctx_t *ctx, isc_mem_t *mctx,
			       isc_task_t *task, isc_taskaction_t action,
			       void *arg);

/*
 * The application context of this module.  This implementation actually
 * doesn't use it. (This may change in the future).
 */
#define APPCTX_MAGIC		ISC_MAGIC('A', 'p', 'c', 'x')
#define VALID_APPCTX(c)		ISC_MAGIC_VALID(c, APPCTX_MAGIC)

typedef struct isc__appctx {
	isc_appctx_t		common;
	isc_mem_t		*mctx;
	isc_mutex_t		lock;
	isc_eventlist_t		on_run;
	bool		shutdown_requested;
	bool		running;

	/*!
	 * We assume that 'want_shutdown' can be read and written atomically.
	 */
	bool		want_shutdown;
	/*
	 * We assume that 'want_reload' can be read and written atomically.
	 */
	bool		want_reload;

	bool		blocked;

	isc_taskmgr_t		*taskmgr;
	isc_socketmgr_t		*socketmgr;
	isc_timermgr_t		*timermgr;
	isc_mutex_t		readylock;
	isc_condition_t		ready;
} isc__appctx_t;

static isc__appctx_t isc_g_appctx;

#ifdef HAVE_LINUXTHREADS
/*!
 * Linux has sigwait(), but it appears to prevent signal handlers from
 * running, even if they're not in the set being waited for.  This makes
 * it impossible to get the default actions for SIGILL, SIGSEGV, etc.
 * Instead of messing with it, we just use sigsuspend() instead.
 */
#undef HAVE_SIGWAIT
/*!
 * We need to remember which thread is the main thread...
 */
static pthread_t		main_thread;
#endif

#ifndef HAVE_SIGWAIT
static void
exit_action(int arg) {
	UNUSED(arg);
	isc_g_appctx.want_shutdown = true;
}

static void
reload_action(int arg) {
	UNUSED(arg);
	isc_g_appctx.want_reload = true;
}
#endif

static isc_result_t
handle_signal(int sig, void (*handler)(int)) {
	struct sigaction sa;
	char strbuf[ISC_STRERRORSIZE];

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handler;

	if (sigfillset(&sa.sa_mask) != 0 ||
	    sigaction(sig, &sa, NULL) < 0) {
		isc__strerror(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 isc_msgcat_get(isc_msgcat, ISC_MSGSET_APP,
					       ISC_MSG_SIGNALSETUP,
					       "handle_signal() %d setup: %s"),
				 sig, strbuf);
		return (ISC_R_UNEXPECTED);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc__app_ctxstart(isc_appctx_t *ctx0) {
	isc__appctx_t *ctx = (isc__appctx_t *)ctx0;
	isc_result_t result;
	int presult;
	sigset_t sset;
	char strbuf[ISC_STRERRORSIZE];

	REQUIRE(VALID_APPCTX(ctx));

	/*
	 * Start an ISC library application.
	 */

#ifdef NEED_PTHREAD_INIT
	/*
	 * BSDI 3.1 seg faults in pthread_sigmask() if we don't do this.
	 */
	presult = pthread_init();
	if (presult != 0) {
		isc__strerror(presult, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_start() pthread_init: %s", strbuf);
		return (ISC_R_UNEXPECTED);
	}
#endif

#ifdef HAVE_LINUXTHREADS
	main_thread = pthread_self();
#endif /* HAVE_LINUXTHREADS */

	result = isc_mutex_init(&ctx->readylock);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = isc_condition_init(&ctx->ready);
	if (result != ISC_R_SUCCESS)
		goto cleanup_rlock;

	result = isc_mutex_init(&ctx->lock);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	ISC_LIST_INIT(ctx->on_run);

	ctx->shutdown_requested = false;
	ctx->running = false;
	ctx->want_shutdown = false;
	ctx->want_reload = false;
	ctx->blocked = false;

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
		goto cleanup;
	result = handle_signal(SIGTERM, exit_action);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
#endif

	/*
	 * Always ignore SIGPIPE.
	 */
	result = handle_signal(SIGPIPE, SIG_IGN);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	/*
	 * On Solaris 2, delivery of a signal whose action is SIG_IGN
	 * will not cause sigwait() to return. We may have inherited
	 * unexpected actions for SIGHUP, SIGINT, and SIGTERM from our parent
	 * process (e.g, Solaris cron).  Set an action of SIG_DFL to make
	 * sure sigwait() works as expected.  Only do this for SIGTERM and
	 * SIGINT if we don't have sigwait(), since a different handler is
	 * installed above.
	 */
	result = handle_signal(SIGHUP, SIG_DFL);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

#ifdef HAVE_SIGWAIT
	result = handle_signal(SIGTERM, SIG_DFL);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = handle_signal(SIGINT, SIG_DFL);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
#endif

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
		isc__strerror(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_start() sigsetops: %s", strbuf);
		result = ISC_R_UNEXPECTED;
		goto cleanup;
	}
	presult = pthread_sigmask(SIG_BLOCK, &sset, NULL);
	if (presult != 0) {
		isc__strerror(presult, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_start() pthread_sigmask: %s",
				 strbuf);
		result = ISC_R_UNEXPECTED;
		goto cleanup;
	}

	return (ISC_R_SUCCESS);

 cleanup:
	(void)isc_condition_destroy(&ctx->ready);

 cleanup_rlock:
	(void)isc_mutex_destroy(&ctx->readylock);
	return (result);
}

isc_result_t
isc__app_start(void) {
	isc_g_appctx.common.impmagic = APPCTX_MAGIC;
	isc_g_appctx.common.magic = ISCAPI_APPCTX_MAGIC;
	isc_g_appctx.mctx = NULL;
	/* The remaining members will be initialized in ctxstart() */

	return (isc__app_ctxstart((isc_appctx_t *)&isc_g_appctx));
}

isc_result_t
isc__app_onrun(isc_mem_t *mctx, isc_task_t *task, isc_taskaction_t action,
	      void *arg)
{
	return (isc__app_ctxonrun((isc_appctx_t *)&isc_g_appctx, mctx,
				  task, action, arg));
}

isc_result_t
isc__app_ctxonrun(isc_appctx_t *ctx0, isc_mem_t *mctx, isc_task_t *task,
		  isc_taskaction_t action, void *arg)
{
	isc__appctx_t *ctx = (isc__appctx_t *)ctx0;
	isc_event_t *event;
	isc_task_t *cloned_task = NULL;
	isc_result_t result;

	LOCK(&ctx->lock);

	if (ctx->running) {
		result = ISC_R_ALREADYRUNNING;
		goto unlock;
	}

	/*
	 * Note that we store the task to which we're going to send the event
	 * in the event's "sender" field.
	 */
	isc_task_attach(task, &cloned_task);
	event = isc_event_allocate(mctx, cloned_task, ISC_APPEVENT_SHUTDOWN,
				   action, arg, sizeof(*event));
	if (event == NULL) {
		isc_task_detach(&cloned_task);
		result = ISC_R_NOMEMORY;
		goto unlock;
	}

	ISC_LIST_APPEND(ctx->on_run, event, ev_link);

	result = ISC_R_SUCCESS;

 unlock:
	UNLOCK(&ctx->lock);

	return (result);
}

isc_result_t
isc__app_ctxrun(isc_appctx_t *ctx0) {
	isc__appctx_t *ctx = (isc__appctx_t *)ctx0;
	int result;
	isc_event_t *event, *next_event;
	isc_task_t *task;
	sigset_t sset;
	char strbuf[ISC_STRERRORSIZE];
#ifdef HAVE_SIGWAIT
	int sig;
#endif /* HAVE_SIGWAIT */

	REQUIRE(VALID_APPCTX(ctx));

#ifdef HAVE_LINUXTHREADS
	REQUIRE(main_thread == pthread_self());
#endif

	LOCK(&ctx->lock);

	if (!ctx->running) {
		ctx->running = true;

		/*
		 * Post any on-run events (in FIFO order).
		 */
		for (event = ISC_LIST_HEAD(ctx->on_run);
		     event != NULL;
		     event = next_event) {
			next_event = ISC_LIST_NEXT(event, ev_link);
			ISC_LIST_UNLINK(ctx->on_run, event, ev_link);
			task = event->ev_sender;
			event->ev_sender = NULL;
			isc_task_sendanddetach(&task, &event);
		}

	}

	UNLOCK(&ctx->lock);

	/*
	 * BIND9 internal tools using multiple contexts do not
	 * rely on signal.
	 */
	if (isc_bind9 && ctx != &isc_g_appctx)
		return (ISC_R_SUCCESS);

	/*
	 * There is no danger if isc_app_shutdown() is called before we
	 * wait for signals.  Signals are blocked, so any such signal will
	 * simply be made pending and we will get it when we call
	 * sigwait().
	 */
	while (!ctx->want_shutdown) {
#ifdef HAVE_SIGWAIT
		if (isc_bind9) {
			/*
			 * BIND9 internal; single context:
			 * Wait for SIGHUP, SIGINT, or SIGTERM.
			 */
			if (sigemptyset(&sset) != 0 ||
			    sigaddset(&sset, SIGHUP) != 0 ||
			    sigaddset(&sset, SIGINT) != 0 ||
			    sigaddset(&sset, SIGTERM) != 0) {
				isc__strerror(errno, strbuf, sizeof(strbuf));
				UNEXPECTED_ERROR(__FILE__, __LINE__,
						 "isc_app_run() sigsetops: %s",
						 strbuf);
				return (ISC_R_UNEXPECTED);
			}

#ifndef HAVE_UNIXWARE_SIGWAIT
			result = sigwait(&sset, &sig);
			if (result == 0) {
				if (sig == SIGINT || sig == SIGTERM)
					ctx->want_shutdown = true;
				else if (sig == SIGHUP)
					ctx->want_reload = true;
			}

#else /* Using UnixWare sigwait semantics. */
			sig = sigwait(&sset);
			if (sig >= 0) {
				if (sig == SIGINT || sig == SIGTERM)
					ctx->want_shutdown = true;
				else if (sig == SIGHUP)
					ctx->want_reload = true;
			}
#endif /* HAVE_UNIXWARE_SIGWAIT */
		} else {
			/*
			 * External, or BIND9 using multiple contexts:
			 * wait until woken up.
			 */
			LOCK(&ctx->readylock);
			if (ctx->want_shutdown) {
				/* shutdown() won the race. */
				UNLOCK(&ctx->readylock);
				break;
			}
			if (!ctx->want_reload)
				WAIT(&ctx->ready, &ctx->readylock);
			UNLOCK(&ctx->readylock);
		}
#else  /* Don't have sigwait(). */
		if (isc_bind9) {
			/*
			 * BIND9 internal; single context:
			 * Install a signal handler for SIGHUP, then wait for
			 * all signals.
			 */
			result = handle_signal(SIGHUP, reload_action);
			if (result != ISC_R_SUCCESS)
				return (ISC_R_SUCCESS);

			if (sigemptyset(&sset) != 0) {
				isc__strerror(errno, strbuf, sizeof(strbuf));
				UNEXPECTED_ERROR(__FILE__, __LINE__,
						 "isc_app_run() sigsetops: %s",
						 strbuf);
				return (ISC_R_UNEXPECTED);
			}
#ifdef HAVE_GPERFTOOLS_PROFILER
			if (sigaddset(&sset, SIGALRM) != 0) {
				isc__strerror(errno, strbuf, sizeof(strbuf));
				UNEXPECTED_ERROR(__FILE__, __LINE__,
						 "isc_app_run() sigsetops: %s",
						 strbuf);
				return (ISC_R_UNEXPECTED);
			}
#endif
			(void)sigsuspend(&sset);
		} else {
			/*
			 * External, or BIND9 using multiple contexts:
			 * wait until woken up.
			 */
			LOCK(&ctx->readylock);
			if (ctx->want_shutdown) {
				/* shutdown() won the race. */
				UNLOCK(&ctx->readylock);
				break;
			}
			if (!ctx->want_reload)
				WAIT(&ctx->ready, &ctx->readylock);
			UNLOCK(&ctx->readylock);
		}
#endif /* HAVE_SIGWAIT */

		if (ctx->want_reload) {
			ctx->want_reload = false;
			return (ISC_R_RELOAD);
		}

		if (ctx->want_shutdown && ctx->blocked)
			exit(1);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc__app_run(void) {
	return (isc__app_ctxrun((isc_appctx_t *)&isc_g_appctx));
}

isc_result_t
isc__app_ctxshutdown(isc_appctx_t *ctx0) {
	isc__appctx_t *ctx = (isc__appctx_t *)ctx0;
	bool want_kill = true;
	char strbuf[ISC_STRERRORSIZE];

	REQUIRE(VALID_APPCTX(ctx));

	LOCK(&ctx->lock);

	REQUIRE(ctx->running);

	if (ctx->shutdown_requested)
		want_kill = false;
	else
		ctx->shutdown_requested = true;

	UNLOCK(&ctx->lock);

	if (want_kill) {
		if (isc_bind9 && ctx != &isc_g_appctx)
			/* BIND9 internal, but using multiple contexts */
			ctx->want_shutdown = true;
		else {
#ifdef HAVE_LINUXTHREADS
			if (isc_bind9) {
				/* BIND9 internal, single context */
				int result;

				result = pthread_kill(main_thread, SIGTERM);
				if (result != 0) {
					isc__strerror(result,
						      strbuf, sizeof(strbuf));
					UNEXPECTED_ERROR(__FILE__, __LINE__,
							 "isc_app_shutdown() "
							 "pthread_kill: %s",
							 strbuf);
					return (ISC_R_UNEXPECTED);
				}
			}
#else
			if (isc_bind9) {
				/* BIND9 internal, single context */
				if (kill(getpid(), SIGTERM) < 0) {
					isc__strerror(errno,
						      strbuf, sizeof(strbuf));
					UNEXPECTED_ERROR(__FILE__, __LINE__,
							 "isc_app_shutdown() "
							 "kill: %s", strbuf);
					return (ISC_R_UNEXPECTED);
				}
			}
#endif /* HAVE_LINUXTHREADS */
			else {
				/* External, multiple contexts */
				LOCK(&ctx->readylock);
				ctx->want_shutdown = true;
				UNLOCK(&ctx->readylock);
				SIGNAL(&ctx->ready);
			}
		}
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc__app_shutdown(void) {
	return (isc__app_ctxshutdown((isc_appctx_t *)&isc_g_appctx));
}

isc_result_t
isc__app_ctxsuspend(isc_appctx_t *ctx0) {
	isc__appctx_t *ctx = (isc__appctx_t *)ctx0;
	bool want_kill = true;
	char strbuf[ISC_STRERRORSIZE];

	REQUIRE(VALID_APPCTX(ctx));

	LOCK(&ctx->lock);

	REQUIRE(ctx->running);

	/*
	 * Don't send the reload signal if we're shutting down.
	 */
	if (ctx->shutdown_requested)
		want_kill = false;

	UNLOCK(&ctx->lock);

	if (want_kill) {
		if (isc_bind9 && ctx != &isc_g_appctx)
			/* BIND9 internal, but using multiple contexts */
			ctx->want_reload = true;
		else {
			ctx->want_reload = true;
			if (isc_bind9) {
				/* BIND9 internal, single context */
				int result;

				result = pthread_kill(main_thread, SIGHUP);
				if (result != 0) {
					isc__strerror(result,
						      strbuf, sizeof(strbuf));
					UNEXPECTED_ERROR(__FILE__, __LINE__,
							 "isc_app_reload() "
							 "pthread_kill: %s",
							 strbuf);
					return (ISC_R_UNEXPECTED);
				}
			}
#else
			if (isc_bind9) {
				/* BIND9 internal, single context */
				if (kill(getpid(), SIGHUP) < 0) {
					isc__strerror(errno,
						      strbuf, sizeof(strbuf));
					UNEXPECTED_ERROR(__FILE__, __LINE__,
							 "isc_app_reload() "
							 "kill: %s", strbuf);
					return (ISC_R_UNEXPECTED);
				}
			}
#endif /* HAVE_LINUXTHREADS */
			else {
				/* External, multiple contexts */
				LOCK(&ctx->readylock);
				ctx->want_reload = true;
				UNLOCK(&ctx->readylock);
				SIGNAL(&ctx->ready);
			}
		}
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc__app_reload(void) {
	return (isc__app_ctxsuspend((isc_appctx_t *)&isc_g_appctx));
}

void
isc__app_ctxfinish(isc_appctx_t *ctx0) {
	isc__appctx_t *ctx = (isc__appctx_t *)ctx0;

	REQUIRE(VALID_APPCTX(ctx));

	DESTROYLOCK(&ctx->lock);
}

void
isc__app_finish(void) {
	isc__app_ctxfinish((isc_appctx_t *)&isc_g_appctx);
}

void
isc__app_block(void) {
	sigset_t sset;
	REQUIRE(isc_g_appctx.running);
	REQUIRE(!isc_g_appctx.blocked);

	isc_g_appctx.blocked = true;
	blockedthread = pthread_self();
	RUNTIME_CHECK(sigemptyset(&sset) == 0 &&
		      sigaddset(&sset, SIGINT) == 0 &&
		      sigaddset(&sset, SIGTERM) == 0);
	RUNTIME_CHECK(pthread_sigmask(SIG_UNBLOCK, &sset, NULL) == 0);
}

void
isc__app_unblock(void) {
	sigset_t sset;

	REQUIRE(isc_g_appctx.running);
	REQUIRE(isc_g_appctx.blocked);

	isc_g_appctx.blocked = false;

	REQUIRE(blockedthread == pthread_self());

	RUNTIME_CHECK(sigemptyset(&sset) == 0 &&
		      sigaddset(&sset, SIGINT) == 0 &&
		      sigaddset(&sset, SIGTERM) == 0);
	RUNTIME_CHECK(pthread_sigmask(SIG_BLOCK, &sset, NULL) == 0);
}

isc_result_t
isc__appctx_create(isc_mem_t *mctx, isc_appctx_t **ctxp) {
	isc__appctx_t *ctx;

	REQUIRE(mctx != NULL);
	REQUIRE(ctxp != NULL && *ctxp == NULL);

	ctx = isc_mem_get(mctx, sizeof(*ctx));
	if (ctx == NULL)
		return (ISC_R_NOMEMORY);

	ctx->common.impmagic = APPCTX_MAGIC;
	ctx->common.magic = ISCAPI_APPCTX_MAGIC;

	ctx->mctx = NULL;
	isc_mem_attach(mctx, &ctx->mctx);

	ctx->taskmgr = NULL;
	ctx->socketmgr = NULL;
	ctx->timermgr = NULL;

	*ctxp = (isc_appctx_t *)ctx;

	return (ISC_R_SUCCESS);
}

void
isc__appctx_destroy(isc_appctx_t **ctxp) {
	isc__appctx_t *ctx;

	REQUIRE(ctxp != NULL);
	ctx = (isc__appctx_t *)*ctxp;
	REQUIRE(VALID_APPCTX(ctx));

	isc_mem_putanddetach(&ctx->mctx, ctx, sizeof(*ctx));

	*ctxp = NULL;
}

void
isc__appctx_settaskmgr(isc_appctx_t *ctx0, isc_taskmgr_t *taskmgr) {
	isc__appctx_t *ctx = (isc__appctx_t *)ctx0;

	REQUIRE(VALID_APPCTX(ctx));

	ctx->taskmgr = taskmgr;
}

void
isc__appctx_setsocketmgr(isc_appctx_t *ctx0, isc_socketmgr_t *socketmgr) {
	isc__appctx_t *ctx = (isc__appctx_t *)ctx0;

	REQUIRE(VALID_APPCTX(ctx));

	ctx->socketmgr = socketmgr;
}

void
isc__appctx_settimermgr(isc_appctx_t *ctx0, isc_timermgr_t *timermgr) {
	isc__appctx_t *ctx = (isc__appctx_t *)ctx0;

	REQUIRE(VALID_APPCTX(ctx));

	ctx->timermgr = timermgr;
}

#include "../app_api.c"
