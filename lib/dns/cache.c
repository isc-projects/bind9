/*
 * Copyright (C) 1999 Internet Software Consortium.
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

 /* $Id: cache.c,v 1.3 1999/12/02 23:53:08 gson Exp $ */

#include <config.h>
#include <limits.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mutex.h>

#include <dns/cache.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/events.h>
#include <dns/log.h>
#include <dns/rdata.h>
#include <dns/types.h>

#define LOCK(lp) \
	RUNTIME_CHECK(isc_mutex_lock((lp)) == ISC_R_SUCCESS)
#define UNLOCK(lp) \
	RUNTIME_CHECK(isc_mutex_unlock((lp)) == ISC_R_SUCCESS)

#define CACHE_MAGIC	0x24242424U 	/* $$$$. */
#define VALID_CACHE(cache) ((cache) != NULL && (cache)->magic == CACHE_MAGIC)

/***
 ***	Types
 ***/

/*
 * A cache_cleaner_t encapsulsates the state of the periodic
 * cache cleaning. 
 */

typedef struct cache_cleaner cache_cleaner_t;

typedef enum {
	cleaner_s_idle,	/* Waiting for cleaning-interval to expire. */
	cleaner_s_busy	/* Currently cleaning. */
} cleaner_state_t;
	     
struct cache_cleaner {
	dns_cache_t	*cache;
	isc_task_t 	*task;
	int		cleaning_interval; /* The cleaning-interval from
					      named.conf, in seconds. */
	isc_timer_t 	*cleaning_timer;
	isc_event_t	*resched_event;	/* Sent by cleaner task to 
					   itself to reschedule */

	dns_dbiterator_t *iterator;
	int 		 increment;	/* Number of names to 
					   clean in one increment */
	cleaner_state_t  state;		/* Idle/Busy. */
};

/*
 * The actual cache object. 
 */

struct dns_cache {
	/* Unlocked */
	unsigned int		magic;
	isc_mutex_t		lock;
	isc_mutex_t		filelock;
	isc_mem_t		*mctx;

	/* Locked by 'lock'. */
	unsigned int		references;
	unsigned int		live_tasks;	
	dns_rdataclass_t	rdclass;
	dns_db_t		*db;
	cache_cleaner_t		cleaner;

	/* Locked by 'filelock'. */	
	char *			filename;
	/* Access to the on-disk cache file is also locked by 'filelock'. */
};

/***
 ***	Functions
 ***/

static dns_result_t
cache_cleaner_init(dns_cache_t *cache,
		   isc_taskmgr_t *taskmgr, isc_timermgr_t *timermgr,
		   cache_cleaner_t *cleaner);

static void
cleaning_timer_action(isc_task_t *task, isc_event_t *event);

static void
incremental_cleaning_action(isc_task_t *task, isc_event_t *event);

static void
cleaner_shutdown_action(isc_task_t *task, isc_event_t *event);

dns_result_t 
dns_cache_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		 isc_timermgr_t *timermgr, dns_rdataclass_t rdclass,
		 char *db_type, unsigned int db_argc, char **db_argv,
		 dns_cache_t **cachep)
{
	isc_result_t iresult;
	dns_result_t dresult;
	dns_cache_t *cache;

	REQUIRE(cachep != NULL);
	REQUIRE(*cachep == NULL);
	REQUIRE(mctx != NULL);

	cache = isc_mem_get(mctx, sizeof *cache);
	if (cache == NULL)
		return (ISC_R_NOMEMORY);

	cache->mctx = mctx;
	iresult = isc_mutex_init(&cache->lock);
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed: %s",
				 isc_result_totext(iresult));
		dresult = ISC_R_UNEXPECTED;
		goto fail;
	}

	cache->references = 1;
	cache->live_tasks = 0;
	cache->rdclass = rdclass;

	cache->db = NULL;
	dresult = dns_db_create(cache->mctx, db_type, dns_rootname, ISC_TRUE,
				rdclass, db_argc, db_argv, &cache->db);
	if (dresult != ISC_R_SUCCESS)
		goto fail;

	cache->filename = NULL;	
	
	cache->magic = CACHE_MAGIC;

	dresult = cache_cleaner_init(cache, taskmgr, timermgr,
				     &cache->cleaner);
	RUNTIME_CHECK(dresult == ISC_R_SUCCESS);

	*cachep = cache;
	return (ISC_R_SUCCESS);
 fail:
	isc_mem_put(cache->mctx, cache, sizeof *cache);
	return (dresult);
}

static void 
cache_free(dns_cache_t *cache) {
	REQUIRE(VALID_CACHE(cache));
	REQUIRE(cache->references == 0);

	if (cache->cleaner.resched_event != NULL)
		isc_event_free(&cache->cleaner.resched_event);

	dns_dbiterator_destroy(&cache->cleaner.iterator);

	if (cache->filename) {
		isc_mem_free(cache->mctx, cache->filename);
		cache->filename = NULL;
	}

	if (cache->db) {	
		dns_db_detach(&cache->db);
	}

	isc_mutex_destroy(&cache->lock);
	cache->magic = 0;	
	isc_mem_put(cache->mctx, cache, sizeof *cache);	
}	


void
dns_cache_attach(dns_cache_t *cache, dns_cache_t **targetp) {

	REQUIRE(VALID_CACHE(cache));
	REQUIRE(targetp != NULL && *targetp == NULL);

	LOCK(&cache->lock);
	cache->references++;
	UNLOCK(&cache->lock);

	*targetp = cache;
}

void
dns_cache_detach(dns_cache_t **cachep) {
	dns_cache_t *cache;
	isc_boolean_t free_cache = ISC_FALSE;

	REQUIRE(cachep != NULL);
	cache = *cachep;
	REQUIRE(VALID_CACHE(cache));

	LOCK(&cache->lock);
	
	REQUIRE(cache->references > 0);
	cache->references--;
	if (cache->references == 0) {
		if (cache->live_tasks == 0)
			free_cache = ISC_TRUE;
		if (cache->cleaner.cleaning_timer != NULL)
			isc_timer_detach(&cache->cleaner.cleaning_timer);
		if (cache->cleaner.task != NULL)
			isc_task_destroy(&cache->cleaner.task);
	}
	UNLOCK(&cache->lock);

	if (free_cache)
		cache_free(cache);

	*cachep = NULL;
}

void
dns_cache_attachdb(dns_cache_t *cache, dns_db_t **dbp) {
	REQUIRE(VALID_CACHE(cache));
	REQUIRE(dbp != NULL && *dbp == NULL);
	REQUIRE(cache->db != NULL);
	LOCK(&cache->lock);
	dns_db_attach(cache->db, dbp);
	UNLOCK(&cache->lock);
}

#ifdef NOTYET

dns_result_t
dns_cache_setfilename(dns_cache_t *cahce, char *filename) /* ARGSUSED */
{
	char *newname = isc_mem_strdup(filename);
	if (newname == NULL)
		return (ISC_R_NOMEMORY);
	LOCK(&cache->filelock);	
	if (cache->filename)
		isc_mem_free(cache->mctx, cache->filename);
	cache->filename = newname;
	UNLOCK(&cache->filelock);	
	return (ISC_R_SUCCESS);
}

dns_result_t
dns_cache_load(dns_cache_t *cache) {
	dns_result_t dresult;
	if (cache->filename == NULL)
		return (ISC_R_SUCCESS);
	LOCK(&cache->filelock);
	/* XXX handle TTLs in a way appropriate for the cache */
	dresult = dns_db_load(cache->db, cache->filename);
	UNLOCK(&cache->filelock);	
	return (dresult);
}

dns_result_t
dns_cache_dump(dns_cache_t *cache) {
	/* XXX to be written */
	return (ISC_R_NOTIMPLEMENTED);
}

#endif

/*
 * Initialize the cache cleaner object at *cleaner.  
 * Space for the object must be allocated by the caller.
 */

static dns_result_t
cache_cleaner_init(dns_cache_t *cache, isc_taskmgr_t *taskmgr, 
		   isc_timermgr_t *timermgr, cache_cleaner_t *cleaner)
{
        isc_result_t iresult;
	dns_result_t dresult;

	cleaner->increment = 10; /* XXX debugging value; 100 realistic? */
	cleaner->state = cleaner_s_idle;
	cleaner->cache = cache;

	cleaner->iterator = NULL;
	dresult = dns_db_createiterator(cache->db,
					ISC_FALSE, &cleaner->iterator);
	if (dresult != ISC_R_SUCCESS)
		goto fail;

	cleaner->task = NULL;
	cleaner->cleaning_timer = NULL;
	cleaner->resched_event = NULL;
	
	if (taskmgr != NULL && timermgr != NULL) {
		isc_interval_t interval;

		iresult = isc_task_create(taskmgr, cache->mctx,
					  1, &cleaner->task);
		if (iresult != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_task_create() failed: %s",
					 isc_result_totext(iresult));
			dresult = ISC_R_UNEXPECTED;
			goto cleanup_dbiterator;
		}
		cleaner->cache->live_tasks++;

		iresult = isc_task_onshutdown(cleaner->task,
					      cleaner_shutdown_action, cache);
		RUNTIME_CHECK(iresult == ISC_R_SUCCESS);

		/* XXX get this from the configuration file */
		cleaner->cleaning_interval = 2 * 3600; /* seconds */
		isc_interval_set(&interval, cleaner->cleaning_interval, 0);
		iresult = isc_timer_create(timermgr, isc_timertype_ticker,
					   NULL, &interval,
					   cleaner->task,
					   cleaning_timer_action, cleaner,
					   &cleaner->cleaning_timer);
		if (iresult != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_timer_create() failed: %s",
					 isc_result_totext(iresult));
			dresult = ISC_R_UNEXPECTED;
			goto cleanup_task;
		}

		cleaner->resched_event =
			isc_event_allocate(cache->mctx, cleaner,
					   DNS_EVENT_CACHECLEAN,
					   incremental_cleaning_action,
					   cleaner, sizeof(isc_event_t));
		if (cleaner->resched_event == NULL) {
			dresult = ISC_R_NOMEMORY;
			goto cleanup_timer;
		}
	}

	return (ISC_R_SUCCESS);

    cleanup_timer:
	isc_timer_detach(&cleaner->cleaning_timer);
    cleanup_task:
	isc_task_detach(&cleaner->task);
    cleanup_dbiterator:
	dns_dbiterator_destroy(&cleaner->iterator);
    fail:
	return (dresult);
}

/*
 * Try to clean the next n_names domain names.
 */
static dns_result_t
do_some_cleaning(cache_cleaner_t *cleaner, isc_stdtime_t now, int n_names) {
	dns_result_t dresult; 
	dns_result_t return_result; 

	REQUIRE(DNS_DBITERATOR_VALID(cleaner->iterator));

	/*
	 * When starting or restarting from the idle state,
	 * position the iterator at the beginning of the cache. 
	 */
	if (cleaner->state == cleaner_s_idle) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
			      "begin cache cleaning");
		dresult = dns_dbiterator_first(cleaner->iterator);
		if (dresult == ISC_R_NOMORE) {
			/*
			 * We have an empty database, but that's OK.
			 */
			return_result = ISC_R_SUCCESS;
			goto idle;
		}
		if (dresult != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "cache cleaner: dns_dbiterator_first() "
				 "failed: %s", dns_result_totext(dresult));
			return_result = ISC_R_UNEXPECTED;
			goto idle;
		}
		cleaner->state = cleaner_s_busy;
	}
	
	while (n_names-- > 0) {
		dns_dbnode_t *node = NULL;
		dresult = dns_dbiterator_current(cleaner->iterator, &node,
						 (dns_name_t *) NULL);
		if (dresult != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "cache cleaner: dns_dbiterator_current() "
				 "failed: %s", dns_result_totext(dresult));
			return_result = ISC_R_UNEXPECTED;
			goto idle;
		}
		INSIST(node != NULL);

		/* Check TTLs, mark expired rdatasets stale. */
		dresult = dns_db_expirenode(cleaner->cache->db, node, now);
		RUNTIME_CHECK(dresult == ISC_R_SUCCESS);

		/* This is where the actual freeing takes place. */ 
		dns_db_detachnode(cleaner->cache->db, &node);
		
		/* Step to the next node */
		dresult = dns_dbiterator_next(cleaner->iterator);
		if (dresult == ISC_R_NOMORE) {
			/* We have successfully cleaned the whole cache. */
			return_result = ISC_R_SUCCESS;
			goto idle;
		}
		if (dresult != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "cache cleaner: dns_dbiterator_next() "
				 "failed: %s", dns_result_totext(dresult));
			return_result = ISC_R_UNEXPECTED;
			goto idle;
		}
	}

	/* We have successfully performed a cleaning increment. */
	return_result = ISC_R_SUCCESS;
	goto done;

 idle:
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
		      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
		      "end cache cleaning");
	cleaner->state = cleaner_s_idle;

 done:
	dresult = dns_dbiterator_pause(cleaner->iterator);
	if (dresult != ISC_R_SUCCESS && dresult != ISC_R_NOMORE) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "cache cleaner: dns_dbiterator_pause() "
				 "failed: %s", dns_result_totext(dresult));
		return (ISC_R_UNEXPECTED);
	}
	return (return_result);
}

/*
 * This is run once for every cache-cleaning-interval as defined in named.conf.
 */
static void
cleaning_timer_action(isc_task_t *task, isc_event_t *event) {
	cache_cleaner_t *cleaner = event->arg;
	INSIST(event->type == ISC_TIMEREVENT_TICK);
	if (cleaner->state == cleaner_s_idle) {
		INSIST(cleaner->resched_event != NULL);
		isc_task_send(task, &cleaner->resched_event);
	} else {
		INSIST(cleaner->resched_event == NULL);
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_CACHE, ISC_LOG_WARNING,
			      "cache cleaner did not finish "
			      "in one cleaning-interval");
	}
	isc_event_free(&event);
}

/*
 * Do incremental cleaning.
 */
static void
incremental_cleaning_action(isc_task_t *task, isc_event_t *event) {
	cache_cleaner_t *cleaner = event->arg;
	isc_stdtime_t now;
	INSIST(event->type == DNS_EVENT_CACHECLEAN);
	RUNTIME_CHECK(isc_stdtime_get(&now) == ISC_R_SUCCESS);
	/*
	 * The return value from do_some_cleaning() is ignored because it
	 * does its own error reporting.
	 */
	(void) do_some_cleaning(cleaner, now, cleaner->increment);
	if (cleaner->state == cleaner_s_idle) {
	  	/* Went idle.  Save the event for later reuse. */
		INSIST(cleaner->resched_event == NULL);
		cleaner->resched_event = event;
		event = NULL;
	} else {
		/* Still busy.  Reschedule. */
		isc_task_send(task, &event);
	}
}

/*
 * Do immediate cleaning. 
 */
dns_result_t
dns_cache_clean(dns_cache_t *cache, isc_stdtime_t now) {
	dns_result_t dresult;
	dns_dbiterator_t *iterator = NULL;

	dresult = dns_db_createiterator(cache->db, ISC_FALSE, &iterator);
	if (dresult != ISC_R_SUCCESS)
		return dresult;
	
	dresult = dns_dbiterator_first(iterator);

	while (dresult == ISC_R_SUCCESS) {
		dns_dbnode_t *node = NULL;
		dresult = dns_dbiterator_current(iterator, &node,
						 (dns_name_t *) NULL);
		if (dresult != ISC_R_SUCCESS)
			break;

		/* Check TTLs, mark expired rdatasets stale. */
		dresult = dns_db_expirenode(cache->db, node, now);
		RUNTIME_CHECK(dresult == ISC_R_SUCCESS);

		/* This is where the actual freeing takes place. */ 
		dns_db_detachnode(cache->db, &node);

		dresult = dns_dbiterator_next(iterator);
	}

	dns_dbiterator_destroy(&iterator);

	if (dresult == ISC_R_NOMORE)
		dresult = ISC_R_SUCCESS;
	
	return dresult;
}

/*
 * The cleaner task is shutting down; do the necessary cleanup.
 */
static void
cleaner_shutdown_action(isc_task_t *task, isc_event_t *event) {
	dns_cache_t *cache = event->arg;
	isc_boolean_t should_free = ISC_FALSE;
	INSIST(event->type == ISC_TASKEVENT_SHUTDOWN);
	task = task; /* Unused. */
	LOCK(&cache->lock);
	cache->live_tasks--;
	if (cache->references == 0 && cache->live_tasks == 0)
		should_free = ISC_TRUE;
	UNLOCK(&cache->lock);
	if (should_free)
		cache_free(cache);
	isc_event_free(&event);
}
