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

/* $Id: zone.c,v 1.145 2000/06/09 06:16:18 marka Exp $ */

#include <config.h>

#include <isc/file.h>
#include <isc/print.h>
#include <isc/ratelimiter.h>
#include <isc/serial.h>
#include <isc/string.h>
#include <isc/taskpool.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/acl.h>
#include <dns/adb.h>
#include <dns/db.h>
#include <dns/events.h>
#include <dns/journal.h>
#include <dns/log.h>
#include <dns/masterdump.h>
#include <dns/message.h>
#include <dns/peer.h>
#include <dns/rcode.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/request.h>
#include <dns/resolver.h>
#include <dns/result.h>
#include <dns/ssu.h>
#include <dns/tsig.h>
#include <dns/xfrin.h>
#include <dns/zone.h>

#define ZONE_MAGIC 0x5a4f4e45U		/* ZONE */
#define NOTIFY_MAGIC 0x4e746679U	/* Ntfy */
#define STUB_MAGIC 0x53747562U		/* Stub */
#define ZONEMGR_MAGIC 0x5a6d6772U	/* Zmgr */

#define DNS_ZONE_VALID(zone) \
	ISC_MAGIC_VALID(zone, ZONE_MAGIC)
#define DNS_NOTIFY_VALID(notify) \
	ISC_MAGIC_VALID(notify, NOTIFY_MAGIC)
#define DNS_STUB_VALID(stub) \
	ISC_MAGIC_VALID(stub, STUB_MAGIC)
#define DNS_ZONEMGR_VALID(stub) \
	ISC_MAGIC_VALID(stub, ZONEMGR_MAGIC)

#define RANGE(a, b, c) (((a) < (b)) ? (b) : ((a) < (c) ? (a) : (c)))

/*
 * Implementation limits.
 */
#define DNS_MIN_REFRESH 2		/* 2 seconds */
#define DNS_MAX_REFRESH 2419200		/* 4 weeks */
#define DNS_MIN_RETRY	1		/* 1 second */
#define DNS_MAX_RETRY	1209600		/* 2 weeks */
#define DNS_MAX_EXPIRE	14515200	/* 24 weeks */

/*
 * Default values.
 */
#define DNS_DEFAULT_IDLEIN 3600		/* 1 hour */
#define DNS_DEFAULT_IDLEOUT 3600	/* 1 hour */
#define DEFAULT_REFRESH	900		/* 15 minutes */
#define DEFAULT_RETRY 300		/* 5 minutes */
#define MAX_XFER_TIME (2*3600)		/* Documented default is 2 hours */


typedef struct dns_notify dns_notify_t;
typedef struct dns_stub dns_stub_t;

struct dns_zone {
	/* Unlocked */
	unsigned int		magic;
	isc_mutex_t		lock;
	isc_mem_t		*mctx;

	/* Locked */
	dns_db_t		*db;
	dns_zonemgr_t		*zmgr;
	ISC_LINK(dns_zone_t)	link;		/* Used by zmgr. */
	isc_timer_t		*timer;
	unsigned int		erefs;
	unsigned int		irefs;
	dns_name_t		origin;
	char 			*dbname;
	char			*journal;
	isc_int32_t		journalsize;
	dns_rdataclass_t	rdclass;
	dns_zonetype_t		type;
	unsigned int		flags;
	unsigned int		options;
	char			*db_type;
	unsigned int		db_argc;
	char			**db_argv;
	isc_stdtime_t		expiretime;
	isc_stdtime_t		refreshtime;
	isc_stdtime_t		dumptime;
	isc_time_t		loadtime;
	isc_uint32_t		serial;
	isc_uint32_t		refresh;
	isc_uint32_t		retry;
	isc_uint32_t		expire;
	isc_uint32_t		minimum;
	isc_sockaddr_t		*masters;
	unsigned int		masterscnt;
	unsigned int		curmaster;
	isc_sockaddr_t		masteraddr;
	isc_sockaddr_t		*notify;
	unsigned int		notifycnt;
	isc_sockaddr_t		notifyfrom;
	isc_task_t		*task;
	isc_sockaddr_t	 	xfrsource4;
	isc_sockaddr_t	 	xfrsource6;
	dns_xfrin_ctx_t		*xfr;
	/* Access Control Lists */
	dns_acl_t		*update_acl;
	dns_acl_t		*query_acl;
	dns_acl_t		*xfr_acl;
	dns_severity_t		check_names;
	ISC_LIST(dns_notify_t)	notifies;
	dns_request_t		*request;
	isc_uint32_t		maxxfrin;
	isc_uint32_t		maxxfrout;
	isc_uint32_t		idlein;
	isc_uint32_t		idleout;
	isc_boolean_t		diff_on_reload;
	isc_event_t		ctlevent;
	dns_ssutable_t		*ssutable;
	isc_uint32_t		sigvalidityinterval;
	dns_view_t		*view;
	/*
	 * Zones in certain states such as "waiting for zone transfer" 
	 * or "zone transfer in progress" are kept on per-state linked lists
	 * in the zone manager using the 'statelink' field.  The 'statelist'
	 * field points at the list the zone is currently on.  It the zone
	 * is not on any such list, statelist is NULL.
	 */
	ISC_LINK(dns_zone_t)	statelink;	
	dns_zonelist_t	        *statelist;
	
};

#define DNS_ZONE_FLAG(z,f) (((z)->flags & (f)) != 0)
	/* XXX MPA these may need to go back into zone.h */
#define DNS_ZONEFLG_REFRESH      0x00000001U     /* refresh check in progress */
#define DNS_ZONEFLG_NEEDDUMP     0x00000002U     /* zone need consolidation */
#define DNS_ZONEFLG_USEVC	0x00000004U	/* use tcp for refresh query */
/* #define DNS_ZONEFLG_UNUSED	0x00000008U */	/* unused */
/* #define DNS_ZONEFLG_UNUSED	0x00000010U */	/* unused */
#define DNS_ZONEFLG_LOADED       0x00000020U     /* database has loaded */
#define DNS_ZONEFLG_EXITING      0x00000040U     /* zone is being destroyed */
#define DNS_ZONEFLG_EXPIRED      0x00000080U     /* zone has expired */
#define DNS_ZONEFLG_NEEDREFRESH	0x00000100U	/* refresh check needed */
#define DNS_ZONEFLG_UPTODATE	0x00000200U	/* zone contents are 
						 * uptodate */
#define DNS_ZONEFLG_NEEDNOTIFY	0x00000400U	/* need to send out notify
						 * messages */
#define DNS_ZONEFLG_DIFFONRELOAD 0x00000800U	/* generate a journal diff on
						 * reload */
#define DNS_ZONEFLG_NOMASTERS	0x00001000U	/* an attempt to refresh a
						 * zone with no masters
						 * occured */

#define DNS_ZONE_OPTION(z,o) (((z)->options & (o)) != 0)

struct dns_zonemgr {
	unsigned int		magic;
	isc_mem_t *		mctx;
	int			refs;
	isc_taskmgr_t *		taskmgr;
	isc_timermgr_t *	timermgr;
	isc_socketmgr_t *	socketmgr;
	isc_taskpool_t *	zonetasks;
	isc_task_t *		task;
	isc_ratelimiter_t *	rl;
	isc_rwlock_t		rwlock;
	isc_rwlock_t		conflock;
	/* Locked by rwlock. */
	dns_zonelist_t		zones;
	dns_zonelist_t		waiting_for_xfrin;
	dns_zonelist_t		xfrin_in_progress;
	
	/* Locked by conflock. */
	int			transfersin;
	int			transfersperns;
};

/*
 * Hold notify state.
 */
struct dns_notify {
	isc_int32_t		magic;
	isc_mem_t		*mctx;
	dns_zone_t		*zone;
	dns_adbfind_t		*find;
	dns_request_t		*request;
	dns_name_t		ns;
	isc_sockaddr_t		dst;
	ISC_LINK(dns_notify_t)	link;
};

/*
 *	dns_stub holds state while performing a 'stub' transfer.
 *	'db' is the zone's 'db' or a new one if this is the initial
 *	transfer.
 */

struct dns_stub {
	isc_int32_t             magic;
	isc_mem_t               *mctx;
	dns_zone_t		*zone;
	dns_db_t		*db;
	dns_dbversion_t		*version;
};

static isc_result_t zone_settimer(dns_zone_t *, isc_stdtime_t);
static void cancel_refresh(dns_zone_t *);

static void zone_log(dns_zone_t *zone, const char *, int, const char *msg,
		     ...);
static void queue_xfrin(dns_zone_t *zone);
static isc_result_t dns_zone_tostr(dns_zone_t *zone, isc_mem_t *mctx,
				   char **s);
static void zone_unload(dns_zone_t *zone);
static void zone_expire(dns_zone_t *zone);
static isc_result_t zone_replacedb(dns_zone_t *zone, dns_db_t *db,
			           isc_boolean_t dump);
static isc_result_t default_journal(dns_zone_t *zone);
static void zone_xfrdone(dns_zone_t *zone, isc_result_t result);
static void zone_shutdown(isc_task_t *, isc_event_t *);

#if 0
/* ondestroy example */
static void dns_zonemgr_dbdestroyed(isc_task_t *task, isc_event_t *event);
#endif

static void refresh_callback(isc_task_t *, isc_event_t *);
static void stub_callback(isc_task_t *, isc_event_t *);
static void queue_soa_query(dns_zone_t *zone);
static void soa_query(isc_task_t *, isc_event_t *);
static void ns_query(dns_zone_t *zone, dns_rdataset_t *soardataset,
		     dns_stub_t *stub);
static int message_count(dns_message_t *msg, dns_section_t section,
			 dns_rdatatype_t type);
static void notify_find_address(dns_notify_t *notify);
static void notify_send(dns_notify_t *notify);
static isc_result_t notify_createmessage(dns_zone_t *zone,
					 dns_message_t **messagep);
static void notify_done(isc_task_t *task, isc_event_t *event);
static void notify_send_toaddr(isc_task_t *task, isc_event_t *event);
static isc_result_t zone_dump(dns_zone_t *);
static void got_transfer_quota(isc_task_t *task, isc_event_t *event);
static isc_result_t zmgr_start_xfrin_ifquota(dns_zonemgr_t *zmgr,
					     dns_zone_t *zone);
static void zmgr_resume_xfrs(dns_zonemgr_t *zmgr);
static void zonemgr_free(dns_zonemgr_t *zmgr);

static isc_result_t
zone_get_from_db(dns_db_t *db, dns_name_t *origin, unsigned int *nscount,
		 unsigned int *soacount, isc_uint32_t *serial,
		 isc_uint32_t *refresh, isc_uint32_t *retry,
		 isc_uint32_t *expire, isc_uint32_t *minimum);

#define PRINT_ZONE_REF(zone) \
	do { \
		char *s = NULL; \
		isc_result_t r; \
		r = dns_zone_tostr(zone, zone->mctx, &s); \
		if (r == ISC_R_SUCCESS) { \
			printf("%p: %s: erefs=%d irefs=%d\n", zone, s, \
			       zone->erefs, zone->irefs); \
			isc_mem_free(zone->mctx, s); \
		} \
	} while (0)

#define ZONE_LOG(x,y) zone_log(zone, me, ISC_LOG_DEBUG(x), y)
#define DNS_ENTER zone_log(zone, me, ISC_LOG_DEBUG(1), "enter")
#define DNS_LEAVE zone_log(zone, me, ISC_LOG_DEBUG(1), "leave")

/***
 ***	Public functions.
 ***/

isc_result_t
dns_zone_create(dns_zone_t **zonep, isc_mem_t *mctx) {
	isc_result_t result;
	dns_zone_t *zone;
	
	REQUIRE(zonep != NULL && *zonep == NULL);
	REQUIRE(mctx != NULL);

	zone = isc_mem_get(mctx, sizeof *zone);
	if (zone == NULL)
		return (ISC_R_NOMEMORY);

	result = isc_mutex_init(&zone->lock);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, zone, sizeof *zone);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	/* XXX MPA check that all elements are initialised */
	zone->mctx = NULL;
	isc_mem_attach(mctx, &zone->mctx);
	zone->db = NULL;
	zone->zmgr = NULL;
	ISC_LINK_INIT(zone, link);
	zone->erefs = 1;		/* Implicit attach. */
	zone->irefs = 0;
	dns_name_init(&zone->origin, NULL);
	zone->dbname = NULL;
	zone->journalsize = -1;
	zone->journal = NULL;
	zone->rdclass = dns_rdataclass_none;
	zone->type = dns_zone_none;
	zone->flags = 0;
	zone->options = 0;
	zone->db_type = NULL;
	zone->db_argc = 0;
	zone->db_argv = NULL;
	zone->expiretime = 0;
	zone->refreshtime = 0;
	zone->dumptime = 0;
	isc_time_settoepoch(&zone->loadtime);
	zone->serial = 0;
	zone->refresh = DEFAULT_REFRESH;
	zone->retry = DEFAULT_RETRY;
	zone->expire = 0;
	zone->minimum = 0;
	zone->masters = NULL;
	zone->masterscnt = 0;
	zone->curmaster = 0;
	zone->notify = NULL;
	zone->notifycnt = 0;
	zone->task = NULL;
	zone->update_acl = NULL;
	zone->query_acl = NULL;
	zone->xfr_acl = NULL;
	zone->check_names = dns_severity_ignore;
	zone->request = NULL;
	zone->timer = NULL;
	zone->idlein = DNS_DEFAULT_IDLEIN;
	zone->idleout = DNS_DEFAULT_IDLEOUT;
	ISC_LIST_INIT(zone->notifies);
	isc_sockaddr_any(&zone->xfrsource4);
	isc_sockaddr_any6(&zone->xfrsource6);
	zone->xfr = NULL;
	zone->maxxfrin = MAX_XFER_TIME;
	zone->maxxfrout = MAX_XFER_TIME;
	zone->diff_on_reload = ISC_FALSE;
	zone->ssutable = NULL;
	zone->sigvalidityinterval = 30 * 24 * 3600;
	zone->view = NULL;
	ISC_LINK_INIT(zone, statelink);
	zone->statelist = NULL;
	
	zone->magic = ZONE_MAGIC;
	ISC_EVENT_INIT(&zone->ctlevent, sizeof(zone->ctlevent), 0, NULL,
		       DNS_EVENT_ZONECONTROL, zone_shutdown, zone, zone,
		       NULL, NULL);
	*zonep = zone;
	return (ISC_R_SUCCESS);
}

/*
 * Free a zone.  Because we require that there be no more
 * outstanding events or references, no locking is necessary.
 */
static void
zone_free(dns_zone_t *zone) {
	isc_mem_t *mctx = NULL;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(zone->erefs == 0);
	REQUIRE(zone->irefs == 0);

	/*
	 * Managed objects.  Order is important.
	 */
	if (zone->timer != NULL)
		isc_timer_detach(&zone->timer);
	if (zone->request != NULL)
		dns_request_destroy(&zone->request); /* XXXMPA */

	INSIST(zone->statelist == NULL);
	
	if (zone->task != NULL)
		isc_task_detach(&zone->task);
	if (zone->zmgr)
		dns_zonemgr_releasezone(zone->zmgr, zone);
	
	/* Unmanaged objects */
	if (zone->dbname != NULL)
		isc_mem_free(zone->mctx, zone->dbname);
	zone->dbname = NULL;
	zone->journalsize = -1;
	if (zone->journal != NULL)
		isc_mem_free(zone->mctx, zone->journal);
	zone->journal = NULL;
	if (zone->db_type != NULL)
		isc_mem_free(zone->mctx, zone->db_type);
	zone->db_type = NULL;
	if (zone->db != NULL)
		dns_db_detach(&zone->db);
	dns_zone_cleardbargs(zone);
	dns_zone_setmasters(zone, NULL, 0);
	dns_zone_setalsonotify(zone, NULL, 0);
	zone->check_names = dns_severity_ignore;
	if (zone->update_acl != NULL)
		dns_acl_detach(&zone->update_acl);
	if (zone->query_acl != NULL)
		dns_acl_detach(&zone->query_acl);
	if (zone->xfr_acl != NULL)
		dns_acl_detach(&zone->xfr_acl);
	if (dns_name_dynamic(&zone->origin))
		dns_name_free(&zone->origin, zone->mctx);
	if (zone->ssutable != NULL)
		dns_ssutable_detach(&zone->ssutable);

	/* last stuff */
	isc_mutex_destroy(&zone->lock);
	zone->magic = 0;
	mctx = zone->mctx;
	isc_mem_put(mctx, zone, sizeof *zone);
	isc_mem_detach(&mctx);
}

/*
 *	Single shot.
 */
void
dns_zone_setclass(dns_zone_t *zone, dns_rdataclass_t rdclass) {

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(rdclass != dns_rdataclass_none);

	/*
	 * Test and set.
	 */
	LOCK(&zone->lock);
	REQUIRE(zone->rdclass == dns_rdataclass_none ||
		zone->rdclass == rdclass);
	zone->rdclass = rdclass;
	UNLOCK(&zone->lock);
}

dns_rdataclass_t
dns_zone_getclass(dns_zone_t *zone){
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->rdclass);
}

/*
 *	Single shot.
 */
void
dns_zone_settype(dns_zone_t *zone, dns_zonetype_t type) {

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(type != dns_zone_none);

	/*
	 * Test and set.
	 */
	LOCK(&zone->lock);
	REQUIRE(zone->type == dns_zone_none || zone->type == type);
	zone->type = type;
	UNLOCK(&zone->lock);
}

isc_result_t
dns_zone_setdbtype(dns_zone_t *zone, const char *db_type) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->db_type != NULL)
		isc_mem_free(zone->mctx, zone->db_type);
	zone->db_type = isc_mem_strdup(zone->mctx, db_type);
	if (zone->db_type == NULL)
		result = ISC_R_NOMEMORY;
	UNLOCK(&zone->lock);
	return (result);
}

void
dns_zone_setview(dns_zone_t *zone, dns_view_t *view) {
	if (zone->view != NULL)
		dns_view_weakdetach(&zone->view);
	dns_view_weakattach(view, &zone->view);
}
     

dns_view_t *
dns_zone_getview(dns_zone_t *zone) {
	return (zone->view);
}
     

isc_result_t
dns_zone_setorigin(dns_zone_t *zone, dns_name_t *origin) {
	isc_result_t result;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(origin != NULL);

	LOCK(&zone->lock);
	if (dns_name_dynamic(&zone->origin)) {
		dns_name_free(&zone->origin, zone->mctx);
		dns_name_init(&zone->origin, NULL);
	}
	result = dns_name_dup(origin, zone->mctx, &zone->origin);
	UNLOCK(&zone->lock);
	return (result);
}

isc_result_t
dns_zone_setdatabase(dns_zone_t *zone, const char *dbname) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(dbname != NULL);

	LOCK(&zone->lock);
	if (zone->dbname != NULL)
		isc_mem_free(zone->mctx, zone->dbname);
	zone->dbname = isc_mem_strdup(zone->mctx, dbname);
	if (zone->dbname == NULL)
		result = ISC_R_NOMEMORY;
	else
		result = default_journal(zone);
	UNLOCK(&zone->lock);
	return (result);
}

static isc_result_t
default_journal(dns_zone_t *zone) {
	int len;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(zone->dbname != NULL);

	if (zone->journal != NULL) 
		isc_mem_free(zone->mctx, zone->journal);
	len = strlen(zone->dbname) + sizeof ".jnl"; 	/* includes '\0' */
	zone->journal = isc_mem_allocate(zone->mctx, len);
	if (zone->journal == NULL)
		return (ISC_R_NOMEMORY);
	strcpy(zone->journal, zone->dbname);
	strcat(zone->journal, ".jnl");
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_zone_setjournal(dns_zone_t *zone, const char *journal) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(journal != NULL);

	LOCK(&zone->lock);
	if (zone->journal != NULL)
		isc_mem_free(zone->mctx, zone->journal);
	zone->journal = isc_mem_strdup(zone->mctx, journal);
	if (zone->journal == NULL)
		result = ISC_R_NOMEMORY;
	UNLOCK(&zone->lock);
	return (result);
}

char *
dns_zone_getjournal(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->journal);
}

isc_result_t
dns_zone_load(dns_zone_t *zone) {
	const char me[] = "dns_zone_load";
	unsigned int soacount = 0;
	unsigned int nscount = 0;
	isc_uint32_t serial, refresh, retry, expire, minimum;
	isc_result_t result;
	isc_stdtime_t now;
	isc_time_t loadtime, filetime;
	dns_db_t *db = NULL;

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	isc_stdtime_get(&now);

	INSIST(zone->type != dns_zone_none);

	if (zone->dbname == NULL) {
		/*
		 * The zone has no master file (maybe it is the built-in
		 * version.bind. CH zone).  Do nothing.
		 */
		result = ISC_R_SUCCESS;
		goto cleanup;
	}

	zone_log(zone, me, ISC_LOG_DEBUG(1), "start");

	/*
	 * Don't do the load if the file that stores the zone is older
	 * than the last time the zone was loaded.  If the zone has not
	 * been loaded yet, zone->loadtime will be the epoch.
	 */
	result = isc_file_getmodtime(zone->dbname, &filetime);
	if (result == ISC_R_SUCCESS && ! isc_time_isepoch(&zone->loadtime) &&
	    isc_time_compare(&filetime, &zone->loadtime) < 0) {
		zone_log(zone, me, ISC_LOG_DEBUG(1),
			 "skipping: database file older than last load");
		result = ISC_R_SUCCESS;
		goto cleanup;
	}

	/*
	 * Store the current time before the zone is loaded, so that if the
	 * file changes between the time of the load and the time that
	 * zone->loadtime is set, then the file will still be reloaded
	 * the next time dns_zone_load is called.
	 */
	result = isc_time_now(&loadtime);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = dns_db_create(zone->mctx, zone->db_type,
			       &zone->origin, (zone->type == dns_zone_stub) ?
			       dns_dbtype_stub : dns_dbtype_zone,
			       zone->rdclass, zone->db_argc, zone->db_argv,
			       &db);

	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = dns_db_load(db, zone->dbname);

	/*
	 * Initiate zone transfer?  We may need a error code that
	 * indicates that the "permanent" form does not exist.
	 * XXX better error feedback to log.
	 */
	if (result != ISC_R_SUCCESS) {
		if (zone->type == dns_zone_slave ||
		    zone->type == dns_zone_stub) {
			zone_log(zone, me, ISC_LOG_INFO,
				 "no database file");
			/* Mark the zone for immediate refresh. */
			zone->refreshtime = now;
			result = ISC_R_SUCCESS;
		} else {
			zone_log(zone, me, ISC_LOG_ERROR,
				 "database %s: dns_db_load failed: %s",
				 zone->dbname, dns_result_totext(result));
		}
		goto cleanup;
	}

	zone->loadtime = loadtime;

	zone_log(zone, me, ISC_LOG_DEBUG(1), "loaded");

	/*
	 * Apply update log, if any.
	 */
	if (zone->journal != NULL) {
		result = dns_journal_rollforward(zone->mctx, db,
						 zone->journal);
		if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND &&
		    result != DNS_R_UPTODATE && result != DNS_R_NOJOURNAL)
			goto cleanup;
		if (result == ISC_R_NOTFOUND) {
			zone_log(zone, me, ISC_LOG_ERROR,
				 "journal out of sync with zone");
			goto cleanup;
		}
		zone_log(zone, me, ISC_LOG_DEBUG(1),
			 "dns_journal_rollforward: %s",
			 dns_result_totext(result));
		if (result == ISC_R_SUCCESS)
			zone->flags |= DNS_ZONEFLG_NEEDDUMP;
	}

	/*
	 * Obtain ns and soa counts for top of zone.
	 */
	nscount = 0;
	soacount = 0;
	INSIST(db != NULL);
	result = zone_get_from_db(db, &zone->origin, &nscount,
				  &soacount, &serial, &refresh, &retry,
				  &expire, &minimum);
	if (result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_ERROR,
			 "could not find NS and/or SOA records");
	}

	/*
	 * Master / Slave / Stub zones require both NS and SOA records at
	 * the top of the zone.
	 */

	switch (zone->type) {
	case dns_zone_master:
	case dns_zone_slave:
	case dns_zone_stub:
		if (soacount != 1 || nscount == 0) {
			if (soacount != 1)
				zone_log(zone, me, ISC_LOG_ERROR,
					 "has %d SOA record%s", soacount,
					 (soacount != 0) ? "s" : "");
			if (nscount == 0)
				zone_log(zone, me, ISC_LOG_ERROR,
					 "no NS records");
			result = DNS_R_BADZONE;
			goto cleanup;
		}
		if (zone->db != NULL) {
			if (!isc_serial_ge(serial, zone->serial)) {
				zone_log(zone, me, ISC_LOG_ERROR,
					"zone serial has gone backwards");
			}
		}
		zone->serial = serial;
		zone->refresh = RANGE(refresh, DNS_MIN_REFRESH,
				      DNS_MAX_REFRESH);
		zone->retry = RANGE(retry, DNS_MIN_REFRESH, DNS_MAX_REFRESH);
		zone->expire = RANGE(expire, zone->refresh + zone->retry,
				     DNS_MAX_EXPIRE);
		zone->minimum = minimum;
		if (zone->type == dns_zone_slave ||
		    zone->type == dns_zone_stub) {
			isc_time_t t;

			result = isc_file_getmodtime(zone->dbname, &t);
						     
			if (result == ISC_R_SUCCESS)
				zone->expiretime = isc_time_seconds(&t) +
						   zone->expire;
			else
				zone->expiretime = now + zone->retry;
			zone->refreshtime = now;
		}
		break;
	default:
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "unexpected zone type %d", zone->type);
		result = ISC_R_UNEXPECTED;
		goto cleanup;
	}


#if 0
	/* destroy notification example. */
	{
		isc_event_t *e = isc_event_allocate(zone->mctx, NULL,
						    DNS_EVENT_DBDESTROYED,
						    dns_zonemgr_dbdestroyed,
						    zone,
						    sizeof(isc_event_t));
		dns_db_ondestroy(db, zone->task, &e);
	}
#endif	

	if (zone->db != NULL) {
		result = zone_replacedb(zone, db, ISC_FALSE);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
	} else {
		dns_db_attach(db, &zone->db);
		zone->flags |= DNS_ZONEFLG_LOADED|DNS_ZONEFLG_NEEDNOTIFY;
	}
	result = ISC_R_SUCCESS; 

 cleanup:
	UNLOCK(&zone->lock);
	if (db != NULL)
		dns_db_detach(&db);
	return (result);
}

static void
exit_check(dns_zone_t *zone) {
	if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_EXITING) &&
	    zone->irefs == 0)
	{
		/*
		 * DNS_ZONEFLG_EXITING can only be set if erefs == 0.
		 */
		INSIST(zone->erefs == 0);
		zone_free(zone);
	}
}

static isc_result_t
zone_count_ns_rr(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		 unsigned int *nscount)
{
	isc_result_t result;
	unsigned int count;
	dns_rdataset_t rdataset;

	REQUIRE(nscount != NULL);

	dns_rdataset_init(&rdataset);
	result = dns_db_findrdataset(db, node, version, dns_rdatatype_ns,
				     dns_rdatatype_none, 0, &rdataset, NULL);
	if (result != ISC_R_SUCCESS)
		goto invalidate_rdataset;

	count = 0;
	result = dns_rdataset_first(&rdataset);
	while (result == ISC_R_SUCCESS) {
		count++;
		result = dns_rdataset_next(&rdataset);
	}
	dns_rdataset_disassociate(&rdataset);

	*nscount = count;
	result = ISC_R_SUCCESS;

 invalidate_rdataset:
	dns_rdataset_invalidate(&rdataset);

	return (result);
}

static isc_result_t
zone_load_soa_rr(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		 unsigned int *soacount,
		 isc_uint32_t *serial, isc_uint32_t *refresh,
		 isc_uint32_t *retry, isc_uint32_t *expire,
		 isc_uint32_t *minimum)
{
	isc_result_t result;
	unsigned int count;
	dns_rdataset_t rdataset;
	dns_rdata_t rdata;
	dns_rdata_soa_t soa;

	dns_rdataset_init(&rdataset);
	result = dns_db_findrdataset(db, node, version, dns_rdatatype_soa,
				     dns_rdatatype_none, 0, &rdataset, NULL);
	if (result != ISC_R_SUCCESS)
		goto invalidate_rdataset;

	count = 0;
	result = dns_rdataset_first(&rdataset);
	while (result == ISC_R_SUCCESS) {
		dns_rdataset_current(&rdataset, &rdata);
		count++;
		if (count == 1)
			dns_rdata_tostruct(&rdata, &soa, NULL);

		result = dns_rdataset_next(&rdataset);
	}
	dns_rdataset_disassociate(&rdataset);

	if (soacount != NULL)
		*soacount = count;

	if (count > 0) {
		if (serial != NULL)
			*serial = soa.serial;
		if (refresh != NULL)
			*refresh = soa.refresh;
		if (retry != NULL)
			*retry = soa.retry;
		if (expire != NULL)
			*expire = soa.expire;
		if (minimum != NULL)
			*minimum = soa.minimum;
	}

	result = ISC_R_SUCCESS;

 invalidate_rdataset:
	dns_rdataset_invalidate(&rdataset);

	return (result);
}

/*
 * zone must be locked.
 */
static isc_result_t
zone_get_from_db(dns_db_t *db, dns_name_t *origin, unsigned int *nscount,
		 unsigned int *soacount, isc_uint32_t *serial,
		 isc_uint32_t *refresh, isc_uint32_t *retry,
		 isc_uint32_t *expire, isc_uint32_t *minimum)
{
	dns_dbversion_t *version = NULL;
	isc_result_t result;
	dns_dbnode_t *node;

	REQUIRE(db != NULL);
	REQUIRE(origin != NULL);

	version = NULL;
	dns_db_currentversion(db, &version);

	node = NULL;
	result = dns_db_findnode(db, origin, ISC_FALSE, &node);
	if (result != ISC_R_SUCCESS)
		goto closeversion;

	if (nscount != NULL) {
		result = zone_count_ns_rr(db, node, version, nscount);
		if (result != ISC_R_SUCCESS)
			goto detachnode;
	}

	if (soacount != NULL || serial != NULL || refresh != NULL
	    || retry != NULL || expire != NULL || minimum != NULL) {
		result = zone_load_soa_rr(db, node, version, soacount,
					  serial, refresh, retry, expire,
					  minimum);
		if (result != ISC_R_SUCCESS)
			goto detachnode;
	}

 detachnode:
	dns_db_detachnode(db, &node);
 closeversion:
	dns_db_closeversion(db, &version, ISC_FALSE);

	return (result);
}

void
dns_zone_attach(dns_zone_t *source, dns_zone_t **target) {
	REQUIRE(DNS_ZONE_VALID(source));
	REQUIRE(target != NULL && *target == NULL);
	LOCK(&source->lock);
	REQUIRE(source->erefs > 0);
	source->erefs++;
	INSIST(source->erefs != 0);
	UNLOCK(&source->lock);
	*target = source;
}

void
dns_zone_detach(dns_zone_t **zonep) {
	dns_zone_t *zone;
	isc_boolean_t free_now = ISC_FALSE;
	
	REQUIRE(zonep != NULL && DNS_ZONE_VALID(*zonep));

	zone = *zonep;
	LOCK(&zone->lock);
	
	REQUIRE(zone->erefs > 0);
	zone->erefs--;
	if (zone->erefs == 0) {
		/*
		 * We just detached the last external reference.
		 */
		if (zone->task != NULL) {	
			/*
			 * This zone is being managed.  Post
			 * its control event and let it clean
			 * up synchronously in the context of
			 * its task.
			 */
			isc_event_t *ev = &zone->ctlevent;
			isc_task_send(zone->task, &ev);
		} else {
			/*
			 * This zone is not being managed; it has
			 * no task and can have no outstanding
			 * events.  Free it immediately.
			 */
			/*
			 * Unmanaged zones should not have non-null views;
			 * we have no way of detaching from the view here
			 * without causing deadlock because this code is called
			 * with the view already locked.
			 */
			INSIST(zone->view == NULL);
			free_now = ISC_TRUE;
		}
	}
	UNLOCK(&zone->lock);
	*zonep = NULL;
	if (free_now)
		zone_free(zone);
}

void
dns_zone_iattach(dns_zone_t *source, dns_zone_t **target) {
	REQUIRE(DNS_ZONE_VALID(source));
	REQUIRE(target != NULL && *target == NULL);
	source->irefs++;
	INSIST(source->irefs != 0);
	*target = source;
}

void
dns_zone_idetach(dns_zone_t **zonep) {
	dns_zone_t *zone;

	REQUIRE(zonep != NULL && DNS_ZONE_VALID(*zonep));
	zone = *zonep;
	REQUIRE(zone->irefs > 0);
	zone->irefs--;
	*zonep = NULL;
	exit_check(zone);
}

void
dns_zone_print(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	PRINT_ZONE_REF(zone);
}

isc_mem_t *
dns_zone_getmctx(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->mctx);
}

dns_zonemgr_t *
dns_zone_getmgr(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->zmgr);
}

static isc_result_t
dns_zone_tostr(dns_zone_t *zone, isc_mem_t *mctx, char **s) {
	isc_buffer_t tbuf;
	char outbuf[1024];
	isc_result_t result;

	REQUIRE(s != NULL && *s == NULL);
	REQUIRE(DNS_ZONE_VALID(zone));

	isc_buffer_init(&tbuf, outbuf, sizeof(outbuf) - 1);
	if (dns_name_countlabels(&zone->origin) > 0) {
		result = dns_name_totext(&zone->origin, ISC_FALSE, &tbuf);
		if (result == ISC_R_SUCCESS)
			outbuf[tbuf.used] = '\0';
		else {
			strncpy(outbuf, "<name conversion failed>",
				sizeof outbuf - 1);
			outbuf[sizeof outbuf - 1] = '\0';
		}
	} else {
		strncpy(outbuf, "<unnamed zone>", sizeof outbuf - 1);
		outbuf[sizeof outbuf - 1] = '\0';
	}
	*s = isc_mem_strdup(mctx, outbuf);
	return ((*s == NULL) ? ISC_R_NOMEMORY : ISC_R_SUCCESS);
}

void
dns_zone_setflag(dns_zone_t *zone, unsigned int flags, isc_boolean_t value) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (value)
		zone->flags |= flags;
	else
		zone->flags &= ~flags;
	UNLOCK(&zone->lock);
}

void
dns_zone_setoption(dns_zone_t *zone, unsigned int option, isc_boolean_t value)
{
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (value)
		zone->options |= option;
	else
		zone->options &= ~option;
	UNLOCK(&zone->lock);
}

unsigned int
dns_zone_getoptions(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->options);
}

isc_result_t
dns_zone_adddbarg(dns_zone_t *zone, char *arg) {
	char **new = NULL;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(arg != NULL);

	/*
	 * Allocate new 'db_argv' and set last to be copy of 'arg'.
	 */
	LOCK(&zone->lock);
	new = isc_mem_get(zone->mctx, (zone->db_argc + 1) * sizeof *new);
	if (new == NULL)
		goto cleanup;
	new[zone->db_argc] = isc_mem_strdup(zone->mctx, arg);
	if (new[zone->db_argc] == NULL)
		goto cleanup;

	/*
	 * Copy old 'db_argv' if required the free it.
	 */
	if (zone->db_argc != 0) {
		memcpy(new, zone->db_argv, zone->db_argc * sizeof *new);
		isc_mem_put(zone->mctx, zone->db_argv,
			    zone->db_argc * sizeof *new);
	}

	zone->db_argv = new;
	zone->db_argc++;
	UNLOCK(&zone->lock);
	return (ISC_R_SUCCESS);

 cleanup:
	if (new != NULL)
		isc_mem_put(zone->mctx, new,
			    (zone->db_argc + 1) * sizeof *new);
	UNLOCK(&zone->lock);
	return (ISC_R_NOMEMORY);
}

void
dns_zone_cleardbargs(dns_zone_t *zone) {
	unsigned int i;

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->db_argc) {
		for (i = 0 ; i < zone->db_argc; i++)
			isc_mem_free(zone->mctx, zone->db_argv[i]);
		isc_mem_put(zone->mctx, zone->db_argv,
			    zone->db_argc * sizeof *zone->db_argv);
		zone->db_argc = 0;
		zone->db_argv = NULL;
	}
	UNLOCK(&zone->lock);
}

isc_result_t
dns_zone_setxfrsource4(dns_zone_t *zone, isc_sockaddr_t *xfrsource) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	zone->xfrsource4 = *xfrsource;
	UNLOCK(&zone->lock);

	return (ISC_R_SUCCESS);
}

isc_sockaddr_t *
dns_zone_getxfrsource4(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return (&zone->xfrsource4);
}

isc_result_t
dns_zone_setxfrsource6(dns_zone_t *zone, isc_sockaddr_t *xfrsource) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	zone->xfrsource6 = *xfrsource;
	UNLOCK(&zone->lock);

	return (ISC_R_SUCCESS);
}

isc_sockaddr_t *
dns_zone_getxfrsource6(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return (&zone->xfrsource6);
}

isc_result_t
dns_zone_setalsonotify(dns_zone_t *zone, isc_sockaddr_t *notify,
		       isc_uint32_t count)
{
	isc_sockaddr_t *new;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE((notify == NULL && count == 0) ||
		(notify != NULL && count != 0));
	
	LOCK(&zone->lock);
	if (zone->notify != NULL) {
		isc_mem_put(zone->mctx, zone->notify,
			    zone->notifycnt * sizeof *new);
		zone->notify = NULL;
		zone->notifycnt = 0;
	}
	if (notify == NULL)
		goto unlock;

	new = isc_mem_get(zone->mctx, count * sizeof *new);
	if (new == NULL) {
		UNLOCK(&zone->lock);
		return (ISC_R_NOMEMORY);
	}
	memcpy(new, notify, count * sizeof *new);
	zone->notify = new;
	zone->notifycnt = count;

 unlock:
	UNLOCK(&zone->lock);
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_zone_setmasters(dns_zone_t *zone, isc_sockaddr_t *masters,
		    isc_uint32_t count)
{
	isc_sockaddr_t *new;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE((masters == NULL && count == 0) ||
		(masters != NULL && count != 0));
	
	LOCK(&zone->lock);
	if (zone->masters != NULL) {
		isc_mem_put(zone->mctx, zone->masters,
			    zone->masterscnt * sizeof *new);
		zone->masters = NULL;
		zone->masterscnt = 0;
	}
	if (masters == NULL)
		goto unlock;

	new = isc_mem_get(zone->mctx, count * sizeof *new);
	if (new == NULL) {
		UNLOCK(&zone->lock);
		return (ISC_R_NOMEMORY);
	}
	memcpy(new, masters, count * sizeof *new);
	zone->masters = new;
	zone->masterscnt = count;
	zone->flags &= ~DNS_ZONEFLG_NOMASTERS;

 unlock:
	UNLOCK(&zone->lock);
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_zone_getdb(dns_zone_t *zone, dns_db_t **dpb) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->db == NULL)
		result = DNS_R_NOTLOADED;
	else
		dns_db_attach(zone->db, dpb);
	UNLOCK(&zone->lock);

	return (result);
}

/*
 * Co-ordinates the starting of routine jobs.
 */
 
void
dns_zone_maintenance(dns_zone_t *zone) {
	const char me[] = "dns_zone_maintenance";
	isc_stdtime_t now;
	isc_result_t result;

	REQUIRE(DNS_ZONE_VALID(zone));
	DNS_ENTER;

	isc_stdtime_get(&now);

	/*
	 * Expire check.
	 */
	switch (zone->type) {
	case dns_zone_slave:
	case dns_zone_stub:
		LOCK(&zone->lock);
		if (now >= zone->expiretime && 
		    DNS_ZONE_FLAG(zone, DNS_ZONEFLG_LOADED)) {
			zone_expire(zone);
			zone->refreshtime = now;
		}
		UNLOCK(&zone->lock);
		break;
	default:
		break;
	}

	/*
	 * Up to date check.
	 */
	switch (zone->type) {
	case dns_zone_slave:
	case dns_zone_stub:
		if (now >= zone->refreshtime)
			dns_zone_refresh(zone);
		break;
	default:
		break;
	}

	/*
	 * Do we need to consolidate the backing store?
	 */
	switch (zone->type) {
	case dns_zone_master:
		LOCK(&zone->lock);
		if (zone->dbname != NULL &&
		    now >= zone->dumptime &&
		    DNS_ZONE_FLAG(zone, DNS_ZONEFLG_LOADED) &&
		    DNS_ZONE_FLAG(zone, DNS_ZONEFLG_NEEDDUMP)) {
			result = zone_dump(zone);
			if (result != ISC_R_SUCCESS)
				zone_log(zone, "zone_dump", ISC_LOG_WARNING,
					 "failed: %s",
					 dns_result_totext(result));
		}
		UNLOCK(&zone->lock);
		break;
	default:
		break;
	}

	/*
	 * Do we need to send out notify messages?
	 */
	switch (zone->type) {
	case dns_zone_master:
	case dns_zone_slave:
		if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_LOADED) &&
		    DNS_ZONE_FLAG(zone, DNS_ZONEFLG_NEEDNOTIFY)) {
			dns_zone_notify(zone);
		}
	default:
		break;
	}
	if (!DNS_ZONE_FLAG(zone, DNS_ZONEFLG_EXITING))
		(void) zone_settimer(zone, now);
}

void
dns_zone_expire(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	zone_expire(zone);
	UNLOCK(&zone->lock);
}

static void
zone_expire(dns_zone_t *zone) {
	isc_result_t result;

	/*
	 * 'zone' locked by caller.
	 */
	if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_NEEDDUMP)) {
		result = zone_dump(zone);
		if (result != ISC_R_SUCCESS)
			zone_log(zone, "zone_dump", ISC_LOG_WARNING,
				 "failure: %s", dns_result_totext(result));
	}
	zone->flags |= DNS_ZONEFLG_EXPIRED;
	dns_zone_setrefresh(zone, DEFAULT_REFRESH, DEFAULT_RETRY);
	zone_unload(zone);
}

void
dns_zone_refresh(dns_zone_t *zone) {
	isc_stdtime_t now;
	isc_uint32_t oldflags;

	REQUIRE(DNS_ZONE_VALID(zone));

	if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_EXITING))
		return;

	isc_stdtime_get(&now);

	/*
	 * Set DNS_ZONEFLG_REFRESH so that there is only one refresh operation
	 * in progress at a time.
	 */

	LOCK(&zone->lock);
	oldflags = zone->flags;
	if (zone->masterscnt == 0) {
		zone->flags |= DNS_ZONEFLG_NOMASTERS;
		if ((oldflags & DNS_ZONEFLG_NOMASTERS) == 0)
			zone_log(zone, "dns_zone_refresh", ISC_LOG_ERROR,
				 "no masters");
		UNLOCK(&zone->lock);
		return;
	}
	zone->flags |= DNS_ZONEFLG_REFRESH;
	UNLOCK(&zone->lock);
	if ((oldflags & DNS_ZONEFLG_REFRESH) != 0)
		return;

	/*
	 * Set the next refresh time as if refresh check has failed.
	 * If we are successful it will be reset using zone->refresh.
	 */

	zone->refreshtime = now + zone->retry;
	zone->curmaster = 0;
	/* initiate soa query */
	queue_soa_query(zone);
}

isc_result_t
dns_zone_dump(dns_zone_t *zone) {
	isc_result_t result;

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	result = zone_dump(zone);
	UNLOCK(&zone->lock);

	return (result);
}

static isc_result_t
zone_dump(dns_zone_t *zone) {
	isc_result_t result;
	dns_dbversion_t *version = NULL;
	dns_db_t *db = NULL;
	char *buf;
	int buflen;
	FILE *f = NULL;
	int n;
	
	/*
	 * 'zone' locked by caller.
	 */
	REQUIRE(DNS_ZONE_VALID(zone));

	buflen = strlen(zone->dbname) + 20;
	buf = isc_mem_get(zone->mctx, buflen);
	if (buf == NULL)
	    return (ISC_R_NOMEMORY);

	result = isc_file_mktemplate(zone->dbname, buf, buflen);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = isc_file_openunique(buf, &f);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	dns_db_attach(zone->db, &db);
	dns_db_currentversion(db, &version);
	result = dns_master_dumptostream(zone->mctx, db, version,
					 &dns_master_style_default, f);
	dns_db_closeversion(db, &version, ISC_FALSE);
	dns_db_detach(&db);
	n = fflush(f);
	if (n != 0 && result == ISC_R_SUCCESS)
		result = ISC_R_UNEXPECTED;
	n = ferror(f);
	if (n != 0 && result == ISC_R_SUCCESS)
		result = ISC_R_UNEXPECTED;
	n = fclose(f);
	if (n != 0 && result == ISC_R_SUCCESS)
		result = ISC_R_UNEXPECTED;
	if (result == ISC_R_SUCCESS) {
		n = rename(buf, zone->dbname);
		if (n == -1) {
			(void)remove(buf);
			result = ISC_R_UNEXPECTED;
		} else {
			zone->flags &= ~DNS_ZONEFLG_NEEDDUMP;
		}
	} else
		(void)remove(buf);
 cleanup:
	isc_mem_put(zone->mctx, buf, buflen);
	return (result);
}

isc_result_t
dns_zone_dumptostream(dns_zone_t *zone, FILE *fd) {
	isc_result_t result;
	dns_dbversion_t *version = NULL;
	dns_db_t *db = NULL;

	REQUIRE(DNS_ZONE_VALID(zone));

	dns_db_attach(zone->db, &db);
	dns_db_currentversion(db, &version);
	result = dns_master_dumptostream(zone->mctx, db, version,
					 &dns_master_style_default, fd);
	dns_db_closeversion(db, &version, ISC_FALSE);
	dns_db_detach(&db);
	return (result);
}

void
dns_zone_unload(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	zone_unload(zone);
	UNLOCK(&zone->lock);
}

static void
zone_unload(dns_zone_t *zone) {
	/* caller to lock */
	dns_db_detach(&zone->db);
	zone->flags &= ~DNS_ZONEFLG_LOADED;
}

void
dns_zone_setrefresh(dns_zone_t *zone, isc_uint32_t refresh,
		    isc_uint32_t retry)
{
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->refresh = refresh;
	zone->retry = retry;
}

static isc_boolean_t
notify_isqueued(dns_zone_t *zone, dns_name_t *name, isc_sockaddr_t *addr) {
	dns_notify_t *notify;

	for (notify = ISC_LIST_HEAD(zone->notifies);
	     notify != NULL;
	     notify = ISC_LIST_NEXT(notify, link)) {
		if (notify->request != NULL)
			continue;
		if (name != NULL && dns_name_dynamic(&notify->ns) &&
		    dns_name_equal(name, &notify->ns))
			return (ISC_TRUE);
		if (addr != NULL && isc_sockaddr_equal(addr, &notify->dst))
			return (ISC_TRUE);
	}
	return (ISC_FALSE);
}

static void
notify_destroy(dns_notify_t *notify) {
	isc_mem_t *mctx;

	/*
	 * Caller holds zone lock.
	 */
	REQUIRE(DNS_NOTIFY_VALID(notify));

	if (notify->zone != NULL) {
		if (ISC_LINK_LINKED(notify, link))
			ISC_LIST_UNLINK(notify->zone->notifies, notify, link);
		dns_zone_idetach(&notify->zone);
	}
	if (notify->find != NULL)
		dns_adb_destroyfind(&notify->find);
	if (notify->request != NULL)
		dns_request_destroy(&notify->request);
	if (dns_name_dynamic(&notify->ns))
		dns_name_free(&notify->ns, notify->mctx);
	mctx = notify->mctx;
	isc_mem_put(notify->mctx, notify, sizeof *notify);
	isc_mem_detach(&mctx);
}

static isc_result_t
notify_create(isc_mem_t *mctx, dns_notify_t **notifyp) {
	dns_notify_t *notify;

	REQUIRE(notifyp != NULL && *notifyp == NULL);

	notify = isc_mem_get(mctx, sizeof *notify);
	if (notify == NULL)
		return (ISC_R_NOMEMORY);

	notify->mctx = NULL;
	isc_mem_attach(mctx, &notify->mctx);
	notify->zone = NULL;
	notify->find = NULL;
	notify->request = NULL;
	isc_sockaddr_any(&notify->dst);
	dns_name_init(&notify->ns, NULL);
	ISC_LINK_INIT(notify, link);
	notify->magic = NOTIFY_MAGIC;
	*notifyp = notify;
	return (ISC_R_SUCCESS);
}

/*
 * XXXAG should check for DNS_ZONEFLG_EXITING
 */
static void
process_adb_event(isc_task_t *task, isc_event_t *ev) {
	dns_notify_t *notify;
	isc_eventtype_t result;
	dns_zone_t *zone = NULL;

	UNUSED(task);

	notify = ev->ev_arg;
	REQUIRE(DNS_NOTIFY_VALID(notify));
	result = ev->ev_type;
	isc_event_free(&ev);
	dns_zone_iattach(notify->zone, &zone);
	if (result == DNS_EVENT_ADBNOMOREADDRESSES) {
		LOCK(&notify->zone->lock);
		notify_send(notify);
		UNLOCK(&zone->lock);
		goto detach;
	}
	if (result == DNS_EVENT_ADBMOREADDRESSES) {
		dns_adb_destroyfind(&notify->find);
		notify_find_address(notify);
		goto detach;
	}
	LOCK(&zone->lock);
	notify_destroy(notify);
	UNLOCK(&zone->lock);
 detach:
	dns_zone_idetach(&zone);
}

static void
notify_find_address(dns_notify_t *notify) {
	isc_result_t result;
	unsigned int options;
	dns_zone_t *zone = NULL;

	REQUIRE(DNS_NOTIFY_VALID(notify));
	options = DNS_ADBFIND_WANTEVENT | DNS_ADBFIND_INET |
		  DNS_ADBFIND_INET6 | DNS_ADBFIND_RETURNLAME;

	dns_zone_iattach(notify->zone, &zone);
	result = dns_adb_createfind(zone->view->adb,
				    zone->task,
				    process_adb_event, notify,
				    &notify->ns, dns_rootname,
				    options, 0, NULL, zone->view->dstport,
				    &notify->find);

	/* Something failed? */
	if (result != ISC_R_SUCCESS) {
		LOCK(&zone->lock);
		notify_destroy(notify);
		UNLOCK(&zone->lock);
		dns_zone_idetach(&zone);
		return;
	}

	/* More addresses pending? */
	if ((notify->find->options & DNS_ADBFIND_WANTEVENT) != 0) {
		dns_zone_idetach(&zone);
		return;
	}

	/* We have as many addresses as we can get. */
	LOCK(&zone->lock);
	notify_send(notify);
	UNLOCK(&zone->lock);
	dns_zone_idetach(&zone);
}


static isc_result_t
notify_send_queue(dns_notify_t *notify) {
	isc_event_t *e;
	isc_result_t result;

	e = isc_event_allocate(notify->mctx, NULL,
			       DNS_EVENT_NOTIFYSENDTOADDR,
			       notify_send_toaddr,
			       notify, sizeof(isc_event_t));
	if (e == NULL)
		return (ISC_R_NOMEMORY);
	e->ev_arg = notify;
	e->ev_sender = NULL;
	result = isc_ratelimiter_enqueue(notify->zone->zmgr->rl,
					 notify->zone->task, &e);
	if (result != ISC_R_SUCCESS)
		isc_event_free(&e);
	return (result);
}

static void
notify_send_toaddr(isc_task_t *task, isc_event_t *event) {
	dns_notify_t *notify;
	isc_result_t result;
	dns_message_t *message = NULL;
	dns_zone_t *zone = NULL;
	isc_netaddr_t dstip;
	dns_peer_t *peer = NULL;
	dns_name_t *keyname = NULL;
	dns_tsigkey_t *key = NULL;

	notify = event->ev_arg;
	REQUIRE(DNS_NOTIFY_VALID(notify));

	UNUSED(task);

	LOCK(&notify->zone->lock);
	dns_zone_iattach(notify->zone, &zone);
	if ((event->ev_attributes & ISC_EVENTATTR_CANCELED) != 0 ||
	     DNS_ZONE_FLAG(notify->zone, DNS_ZONEFLG_EXITING)) {
		result = ISC_R_CANCELED;
		goto cleanup;
	}

	result = notify_createmessage(notify->zone, &message);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	isc_netaddr_fromsockaddr(&dstip, &notify->dst);
	result = dns_peerlist_peerbyaddr(zone->view->peers,
					 &dstip, &peer);
	if (result == ISC_R_SUCCESS &&
	    dns_peer_getkey(peer, &keyname) == ISC_R_SUCCESS)
	{
		result = dns_tsigkey_find(&key, keyname, NULL,
					  zone->view->statickeys);
		if (result == ISC_R_NOTFOUND)
			(void) dns_tsigkey_find(&key, keyname, NULL,
						zone->view->dynamickeys);
	}

	result = dns_request_create(notify->zone->view->requestmgr, message,
				    &notify->dst, 0, key, 15,
				    notify->zone->task,
				    notify_done, notify,
				    &notify->request);
	dns_message_destroy(&message);
 cleanup:
	if (result != ISC_R_SUCCESS)
		notify_destroy(notify);
	UNLOCK(&zone->lock);
	dns_zone_idetach(&zone);
	isc_event_free(&event);
}

static void
notify_send(dns_notify_t *notify) {
	dns_adbaddrinfo_t *ai;
	isc_sockaddr_t dst;
	isc_result_t result;
	dns_message_t *message = NULL;
	dns_notify_t *new = NULL;

	/*
	 * Zone lock held by caller.
	 */
	REQUIRE(DNS_NOTIFY_VALID(notify));

	result = notify_createmessage(notify->zone, &message);
	if (result != ISC_R_SUCCESS)
		return;

	for (ai = ISC_LIST_HEAD(notify->find->list);
	     ai != NULL;
	     ai = ISC_LIST_NEXT(ai, publink)) {
		dst = ai->sockaddr;
		if (notify_isqueued(notify->zone, NULL, &dst))
			continue;
		new = NULL;
		result = notify_create(notify->mctx, &new);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		dns_zone_iattach(notify->zone, &new->zone);
		ISC_LIST_APPEND(new->zone->notifies, new, link);
		new->dst = dst;
		result = notify_send_queue(new);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		new = NULL;
	}

 cleanup:
	if (new != NULL)
		notify_destroy(new);
	notify_destroy(notify);
	dns_message_destroy(&message);
}

void
dns_zone_notify(dns_zone_t *zone) {
	dns_dbnode_t *node = NULL;
	dns_dbversion_t *version = NULL;
	dns_name_t *origin = NULL;
	dns_name_t master;
	dns_rdata_ns_t ns;
	dns_rdata_soa_t soa;
	dns_rdata_t rdata;
	dns_rdataset_t nsrdset;
	dns_rdataset_t soardset;
	isc_result_t result;
	dns_notify_t *notify = NULL;
	unsigned int i;
	isc_sockaddr_t dst;
	isc_boolean_t isqueued;

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	zone->flags &= ~DNS_ZONEFLG_NEEDNOTIFY;
	UNLOCK(&zone->lock);

	if (!DNS_ZONE_OPTION(zone, DNS_ZONEOPT_NOTIFY)) {
		return;
	}

	origin = &zone->origin;

	/*
	 * Enqueue notify request.
	 */
	LOCK(&zone->lock);
	for (i = 0; i < zone->notifycnt; i++) {
		dst = zone->notify[i];
		if (notify_isqueued(zone, NULL, &dst))
			continue;
		result = notify_create(zone->mctx, &notify);
		if (result != ISC_R_SUCCESS) {
			UNLOCK(&zone->lock);
			return;
		}
		dns_zone_iattach(zone, &notify->zone);
		notify->dst = dst;
		ISC_LIST_APPEND(zone->notifies, notify, link);
		result = notify_send_queue(notify);
		if (result != ISC_R_SUCCESS) {
			notify_destroy(notify);
			UNLOCK(&zone->lock);
			return;
		}
		notify = NULL;
	}
	UNLOCK(&zone->lock);

	/*
	 * Process NS RRset to generate notifies.
	 */

	dns_db_currentversion(zone->db, &version);
	result = dns_db_findnode(zone->db, origin, ISC_FALSE, &node);
	if (result != ISC_R_SUCCESS)
		goto cleanup1;

	dns_rdataset_init(&soardset);
	result = dns_db_findrdataset(zone->db, node, version,
				     dns_rdatatype_soa,
				     dns_rdatatype_none, 0, &soardset, NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup2;
	
	/*
	 * Find master server's name.
	 */
	dns_name_init(&master, NULL);
	result = dns_rdataset_first(&soardset);
	while (result == ISC_R_SUCCESS) {
		dns_rdataset_current(&soardset, &rdata);
		result = dns_rdata_tostruct(&rdata, &soa, NULL);
		if (result != ISC_R_SUCCESS)
			continue;
		result = dns_name_dup(&soa.origin, zone->mctx, &master);
		if (result != ISC_R_SUCCESS)
			continue;
		result = dns_rdataset_next(&soardset);
		if (result != ISC_R_NOMORE)
			break;
	}
	dns_rdataset_disassociate(&soardset);
	if (result != ISC_R_NOMORE)
		goto cleanup3;

	dns_rdataset_init(&nsrdset);
	result = dns_db_findrdataset(zone->db, node, version,
				     dns_rdatatype_ns,
				     dns_rdatatype_none, 0, &nsrdset, NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup3;
	
	result = dns_rdataset_first(&nsrdset);
	while (result == ISC_R_SUCCESS) {
		dns_rdataset_current(&nsrdset, &rdata);
		result = dns_rdata_tostruct(&rdata, &ns, NULL);
		if (result != ISC_R_SUCCESS)
			continue;
		/*
		 * don't notify the master server.
		 */
		if (dns_name_compare(&master, &ns.name) == 0) {
			result = dns_rdataset_next(&nsrdset);
			continue;
		}
		LOCK(&zone->lock);
		isqueued = notify_isqueued(zone, &ns.name, NULL);
		UNLOCK(&zone->lock);
		if (isqueued) {
			result = dns_rdataset_next(&nsrdset);
			continue;
		}
		result = notify_create(zone->mctx, &notify);
		if (result != ISC_R_SUCCESS)
			continue;
		dns_zone_iattach(zone, &notify->zone);
		result = dns_name_dup(&ns.name, zone->mctx, &notify->ns);
		if (result != ISC_R_SUCCESS) {
			LOCK(&zone->lock);
			notify_destroy(notify);
			UNLOCK(&zone->lock);
			continue;
		}
		LOCK(&zone->lock);
		ISC_LIST_APPEND(zone->notifies, notify, link);
		UNLOCK(&zone->lock);
		notify_find_address(notify);
		notify = NULL;
		result = dns_rdataset_next(&nsrdset);
	}
	dns_rdataset_disassociate(&nsrdset);

 cleanup3:
	if (dns_name_dynamic(&master))
		dns_name_free(&master, zone->mctx);
 cleanup2:
	dns_db_detachnode(zone->db, &node);
 cleanup1:
	dns_db_closeversion(zone->db, &version, ISC_FALSE);
}

/***
 *** Private
 ***/

static inline isc_result_t 
save_nsrrset(dns_message_t *message, dns_name_t *name, 
	     dns_db_t *db, dns_dbversion_t *version)
{
	dns_rdataset_t *nsrdataset = NULL;
	dns_rdataset_t *rdataset = NULL;
	dns_dbnode_t *node;
	dns_rdata_ns_t ns;
	isc_result_t result;
	dns_rdata_t rdata;

	/*
	 * Extract NS RRset from message.
	 */
	result = dns_message_findname(message, DNS_SECTION_ANSWER, name,
				      dns_rdatatype_ns, dns_rdatatype_none,
				      NULL, &nsrdataset);
	if (result != ISC_R_SUCCESS)
		goto fail;

	/*
	 * Add NS rdataset.
	 */
	result = dns_db_findnode(db, name, ISC_TRUE, &node);
	if (result != ISC_R_SUCCESS)
		goto fail;
	result = dns_db_addrdataset(db, node, version, 0,
				    nsrdataset, 0, NULL);
	dns_db_detachnode(db, &node);
	if (result != ISC_R_SUCCESS)
		goto fail;
	/*
	 * Add glue rdatasets.
	 */
	for (result = dns_rdataset_first(nsrdataset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(nsrdataset)) {
		dns_rdataset_current(nsrdataset, &rdata);
		result = dns_rdata_tostruct(&rdata, &ns, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
		if (!dns_name_issubdomain(&ns.name, name)) {
			result = dns_rdataset_next(nsrdataset);
			continue;
		}
		rdataset = NULL;
		result = dns_message_findname(message, DNS_SECTION_ADDITIONAL,
					      &ns.name, dns_rdatatype_a6,
					      dns_rdatatype_none, NULL,
					      &rdataset);
		if (result == ISC_R_SUCCESS) {
			result = dns_db_findnode(db, &ns.name,
						 ISC_TRUE, &node);
			if (result != ISC_R_SUCCESS)
				goto fail;
			result = dns_db_addrdataset(db, node, version, 0,
						    rdataset, 0, NULL);
			dns_db_detachnode(db, &node);
			if (result != ISC_R_SUCCESS)
				goto fail;
		}
		rdataset = NULL;
		result = dns_message_findname(message, DNS_SECTION_ADDITIONAL,
					      &ns.name, dns_rdatatype_aaaa,
					      dns_rdatatype_none, NULL,
					      &rdataset);
		if (result == ISC_R_SUCCESS) {
			result = dns_db_findnode(db, &ns.name,
						 ISC_TRUE, &node);
			if (result != ISC_R_SUCCESS)
				goto fail;
			result = dns_db_addrdataset(db, node, version, 0,
						    rdataset, 0, NULL);
			dns_db_detachnode(db, &node);
			if (result != ISC_R_SUCCESS)
				goto fail;
		}
		rdataset = NULL;
		result = dns_message_findname(message, DNS_SECTION_ADDITIONAL,
					      &ns.name, dns_rdatatype_a,
					      dns_rdatatype_none, NULL,
					      &rdataset);
		if (result == ISC_R_SUCCESS) {
			result = dns_db_findnode(db, &ns.name,
						 ISC_TRUE, &node);
			if (result != ISC_R_SUCCESS)
				goto fail;
			result = dns_db_addrdataset(db, node, version, 0,
						    rdataset, 0, NULL);
			dns_db_detachnode(db, &node);
			if (result != ISC_R_SUCCESS)
				goto fail;
		}
	}
	if (result != ISC_R_NOMORE)
		goto fail;

	return (ISC_R_SUCCESS);

fail:
	return (result);
}

static void
stub_callback(isc_task_t *task, isc_event_t *event) {
	const char me[] = "stub_callback";
	dns_requestevent_t *revent = (dns_requestevent_t *)event;
	dns_stub_t *stub = NULL;
	dns_message_t *msg = NULL;
	dns_zone_t *zone = NULL;
	char master[ISC_SOCKADDR_FORMATSIZE];
	isc_uint32_t nscnt, cnamecnt;
	isc_result_t result;
	isc_stdtime_t now;

	stub = revent->ev_arg;
	INSIST(DNS_STUB_VALID(stub));

	UNUSED(task);

	/* XXX add test for exiting */

	dns_zone_iattach(stub->zone, &zone);

	DNS_ENTER;

	isc_stdtime_get(&now);

	if (revent->result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_INFO, "failure for %s: %s",
		         master, dns_result_totext(revent->result));
		goto next_master;
	}

	result = dns_message_create(zone->mctx, DNS_MESSAGE_INTENTPARSE, &msg);
	if (result != ISC_R_SUCCESS)
		goto next_master;

	result = dns_request_getresponse(revent->request, msg, ISC_FALSE);
	if (result != ISC_R_SUCCESS)
		goto next_master;

	/*
	 * Unexpected rcode.
	 */
	if (msg->rcode != dns_rcode_noerror) {
		char rcode[128];
		isc_buffer_t rb;

		isc_buffer_init(&rb, rcode, sizeof(rcode));
		dns_rcode_totext(msg->rcode, &rb);

		zone_log(zone, me, ISC_LOG_INFO,
			 "unexpected rcode (%.*s) from %s",
			 rb.used, rcode, master);
		goto next_master;
	}

	/*
	 * We need complete messages.
	 */
	if ((msg->flags & DNS_MESSAGEFLAG_TC) != 0) {
		if (dns_request_usedtcp(revent->request)) {
			zone_log(zone, me, ISC_LOG_INFO,
				 "truncated TCP response from %s", master);
			goto next_master;
		}
		LOCK(&zone->lock);
		zone->flags |= DNS_ZONEFLG_USEVC;
		UNLOCK(&zone->lock);
		goto same_master;
	}

	/*
	 * If non-auth log and next master.
	 */
	if ((msg->flags & DNS_MESSAGEFLAG_AA) == 0) {
		zone_log(zone, me, ISC_LOG_INFO,
			 "non-authorative answer from %s", master);
		goto next_master;
	}

	/*
	 * Sanity checks.
	 */
	cnamecnt = message_count(msg, DNS_SECTION_ANSWER, dns_rdatatype_cname);
	nscnt = message_count(msg, DNS_SECTION_ANSWER, dns_rdatatype_ns);

	if (cnamecnt != 0) {
		zone_log(zone, me, ISC_LOG_INFO,
			 "found unexpected CNAME %s", master);
		goto next_master;
	}

	if (nscnt == 0) {
		zone_log(zone, me, ISC_LOG_INFO,
			 "no NS records from %s", master);
		goto next_master;
	}

	/*
	 * Save answer.
	 */
	result = save_nsrrset(msg, &zone->origin, stub->db, stub->version);
	if (result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_INFO,
			 "unable to save ns records from %s", master);
		goto next_master;
	}

	/*
	 * Tidy up.
	 */
	dns_db_closeversion(stub->db, &stub->version, ISC_TRUE);
	LOCK(&zone->lock);
	if (zone->db == NULL)
		dns_db_attach(stub->db, &zone->db);
	UNLOCK(&zone->lock);
	dns_db_detach(&stub->db);

	if (zone->dbname != NULL)
		dns_zone_dump(zone);

	dns_message_destroy(&msg);
	isc_event_free(&event);
	dns_request_destroy(&zone->request);
	goto free_stub;

 next_master:
	if (stub->version != NULL)
		dns_db_closeversion(stub->db, &stub->version, ISC_FALSE);
	if (stub->db != NULL)
		dns_db_detach(&stub->db);
	if (msg != NULL)
		dns_message_destroy(&msg);
	LOCK(&zone->lock);
	isc_event_free(&event);
	dns_request_destroy(&zone->request);
	zone->curmaster++;
	if (zone->curmaster >= zone->masterscnt) {
		zone->flags &= ~DNS_ZONEFLG_REFRESH;

		zone_settimer(zone, now);
		UNLOCK(&zone->lock);
		return;
	}
	UNLOCK(&zone->lock);
	queue_soa_query(zone);
	goto free_stub;

 same_master:
	if (msg != NULL)
		dns_message_destroy(&msg);
	isc_event_free(&event);
	LOCK(&zone->lock);
	dns_request_destroy(&zone->request);
	UNLOCK(&zone->lock);
	ns_query(zone, NULL, stub);
	goto detach;

 free_stub:
	stub->magic = 0;
	dns_zone_idetach(&stub->zone);
	INSIST(stub->db == NULL);
	INSIST(stub->version == NULL);
	isc_mem_put(stub->mctx, stub, sizeof(*stub));

 detach:
	dns_zone_idetach(&zone);
	return;
}

static void
refresh_callback(isc_task_t *task, isc_event_t *event) {
	const char me[] = "refresh_callback";
	dns_requestevent_t *revent = (dns_requestevent_t *)event;
	dns_zone_t *zone;
	dns_message_t *msg = NULL;
	isc_uint32_t soacnt, cnamecnt, soacount, nscount;
	isc_stdtime_t now;
	char master[ISC_SOCKADDR_FORMATSIZE];
	dns_rdataset_t *rdataset;
	dns_rdata_t rdata;
	dns_rdata_soa_t soa;
	isc_result_t result;
	isc_uint32_t serial;

	zone = revent->ev_arg;
	INSIST(DNS_ZONE_VALID(zone));

	UNUSED(task);

	DNS_ENTER;

	/*
	 * if timeout log and next master;
	 */

	isc_sockaddr_format(&zone->masteraddr, master, sizeof(master));

	isc_stdtime_get(&now);
	
	if (revent->result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_INFO, "failure for %s: %s",
		         master, dns_result_totext(revent->result));
		goto next_master;
	}

	result = dns_message_create(zone->mctx, DNS_MESSAGE_INTENTPARSE, &msg);
	if (result != ISC_R_SUCCESS)
		goto next_master;
	result = dns_request_getresponse(revent->request, msg, ISC_FALSE);
	if (result != ISC_R_SUCCESS)
		goto next_master;

	/*
	 * Unexpected rcode.
	 */
	if (msg->rcode != dns_rcode_noerror) {
		char rcode[128];
		isc_buffer_t rb;

		isc_buffer_init(&rb, rcode, sizeof(rcode));
		dns_rcode_totext(msg->rcode, &rb);

		zone_log(zone, me, ISC_LOG_INFO,
			 "unexpected rcode (%.*s) from %s",
			 rb.used, rcode, master);
		goto next_master;
	}

	/*
	 * If truncated punt to zone transfer which will query again.
	 */
	if ((msg->flags & DNS_MESSAGEFLAG_TC) != 0) {
		if (zone->type == dns_zone_slave) {
			zone_log(zone, me, ISC_LOG_INFO,
				 "truncated UDP answer initiating "
				 "TCP zone xfer %s",
				 master);
			goto tcp_transfer;
		} else {
			INSIST(zone->type == dns_zone_stub);
			if (dns_request_usedtcp(revent->request)) {
				zone_log(zone, me, ISC_LOG_INFO,
					 "truncated TCP response from %s",
					 master);
				goto next_master;
			}
			LOCK(&zone->lock);
			zone->flags |= DNS_ZONEFLG_USEVC;
			UNLOCK(&zone->lock);
			goto same_master;
		}
	}

	/*
	 * if non-auth log and next master;
	 */
	if ((msg->flags & DNS_MESSAGEFLAG_AA) == 0) {
		zone_log(zone, me, ISC_LOG_INFO,
			 "non-authorative answer from %s", master);
		goto next_master;
	}

	cnamecnt = message_count(msg, DNS_SECTION_ANSWER, dns_rdatatype_cname);
	soacnt = message_count(msg, DNS_SECTION_ANSWER, dns_rdatatype_soa);
	nscount = message_count(msg, DNS_SECTION_AUTHORITY, dns_rdatatype_ns);
	soacount = message_count(msg, DNS_SECTION_AUTHORITY,
				 dns_rdatatype_soa);

	/*
	 * There should not be a CNAME record at top of zone.
	 */
	if (cnamecnt != 0) {
		zone_log(zone, me, ISC_LOG_INFO,
			 "CNAME at top of zone discovered: master %s", master);
		goto next_master;
	}

	/*
	 * if referral log and next master;
	 */
	if (soacnt == 0 && soacount == 0 && nscount != 0) {
		zone_log(zone, me, ISC_LOG_INFO,
			"referral from: master %s", master);
		goto next_master;
	}

	/*
	 * if nodata log and next master;
	 */
	if (soacnt == 0 && (nscount == 0 || soacount != 0)) {
		zone_log(zone, me, ISC_LOG_INFO,
			 "NODATA from master %s", master);
		goto next_master;
	}

	/*
	 * Only one soa at top of zone.
	 */
	if (soacnt != 1) {
		zone_log(zone, me, ISC_LOG_INFO,
		   	 "Answer SOA count (%d) != 1: master %s",
			 soacnt, master);
		goto next_master;
	}
	/*
	 * Extract serial
	 */
	rdataset = NULL;
	result = dns_message_findname(msg, DNS_SECTION_ANSWER, &zone->origin,
				      dns_rdatatype_soa, dns_rdatatype_none,
				      NULL, &rdataset);
	if (result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_INFO,
			 "unable to get soa record from %s", master);
		goto next_master;
	}

	result = dns_rdataset_first(rdataset);
	if (result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_INFO, "dns_rdataset_first failed");
		goto next_master;
	}

	dns_rdataset_current(rdataset, &rdata);
	result = dns_rdata_tostruct(&rdata, &soa, NULL);
	if (result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_INFO, "dns_rdata_tostruct failed");
		goto next_master;
	}

	serial = soa.serial;

	zone_log(zone, me, ISC_LOG_DEBUG(1), "Serial: new %u, old %u",
		 serial, zone->serial);
	if (!DNS_ZONE_FLAG(zone, DNS_ZONEFLG_LOADED) ||
	    isc_serial_gt(serial, zone->serial)) {
 tcp_transfer:
		isc_event_free(&event);
		dns_request_destroy(&zone->request);
		if (zone->type == dns_zone_slave) {
			queue_xfrin(zone);
		} else {
			INSIST(zone->type == dns_zone_stub);
			ns_query(zone, rdataset, NULL);
		}
		if (msg != NULL)
			dns_message_destroy(&msg);
	} else if (isc_serial_eq(soa.serial, zone->serial)) {
		if (zone->dbname != NULL) {
			isc_time_t t;
			isc_time_set(&t, now, 0);
			result = isc_file_settime(zone->dbname, &t);
			if (result != ISC_R_SUCCESS)
				zone_log(zone, me, ISC_LOG_ERROR,
					 "isc_file_settime(%s): %s",
					 zone->dbname,
					 dns_result_totext(result));
		}
		zone->refreshtime = now + zone->refresh;
		zone->expiretime = now + zone->expire;
		goto next_master;
	} else {
		ZONE_LOG(1, "ahead");
		goto next_master;
	}
	if (msg != NULL)
		dns_message_destroy(&msg);
	return;

 next_master:
	if (msg != NULL)
		dns_message_destroy(&msg);
	LOCK(&zone->lock);
	isc_event_free(&event);
	dns_request_destroy(&zone->request);
	zone->curmaster++;
	if (zone->curmaster >= zone->masterscnt) {
		zone->flags &= ~DNS_ZONEFLG_REFRESH;
                if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_NEEDREFRESH)) {
			zone->flags &= ~DNS_ZONEFLG_NEEDREFRESH;
			zone->refreshtime = now;
		}
		zone_settimer(zone, now);
		UNLOCK(&zone->lock);
		return;
	}
	UNLOCK(&zone->lock);
	queue_soa_query(zone);
	return;

 same_master:
	if (msg != NULL)
		dns_message_destroy(&msg);
	LOCK(&zone->lock);
	isc_event_free(&event);
	dns_request_destroy(&zone->request);
	UNLOCK(&zone->lock);
	queue_soa_query(zone);
	return;
}

static void
queue_soa_query(dns_zone_t *zone) {
	const char me[] = "queue_soa_query";
	isc_event_t *e;
	dns_zone_t *dummy = NULL;
	isc_result_t result;

	DNS_ENTER;

	if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_EXITING)) {
		cancel_refresh(zone);
		return;
	}

	e = isc_event_allocate(zone->mctx, NULL, DNS_EVENT_ZONE,
			       soa_query, zone, sizeof(isc_event_t));
	if (e == NULL) {
		cancel_refresh(zone);
		return;
	}

	/*
	 * Attach so that we won't clean up
	 * until the event is delivered.
	 */	
	dns_zone_iattach(zone, &dummy);
	
	e->ev_arg = zone;
	e->ev_sender = NULL;
	result = isc_ratelimiter_enqueue(zone->zmgr->rl, zone->task, &e);
	if (result != ISC_R_SUCCESS) {
		dns_zone_idetach(&dummy);
		isc_event_free(&e);
		cancel_refresh(zone);
	}
}

static inline isc_result_t
create_query(dns_zone_t *zone, dns_rdatatype_t rdtype,
	     dns_message_t **messagep)
{
	dns_message_t *message = NULL;
	dns_name_t *qname = NULL;
	dns_rdataset_t *qrdataset = NULL;
	isc_result_t result;

	result = dns_message_create(zone->mctx, DNS_MESSAGE_INTENTRENDER,
				    &message);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	message->opcode = dns_opcode_query;
	message->rdclass = zone->rdclass;

	result = dns_message_gettempname(message, &qname);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = dns_message_gettemprdataset(message, &qrdataset);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	/*
	 * Make question.
	 */
	dns_name_init(qname, NULL);
	dns_name_clone(&zone->origin, qname);
	dns_rdataset_init(qrdataset);
	dns_rdataset_makequestion(qrdataset, zone->rdclass, rdtype);
	ISC_LIST_APPEND(qname->list, qrdataset, link);
	dns_message_addname(message, qname, DNS_SECTION_QUESTION);

	*messagep = message;
	return (ISC_R_SUCCESS);

 cleanup:
	if (qname != NULL)
		dns_message_puttempname(message, &qname);
	if (qrdataset != NULL)
		dns_message_puttemprdataset(message, &qrdataset);
	if (message != NULL)
		dns_message_destroy(&message);
	return (result);
}

static void
soa_query(isc_task_t *task, isc_event_t *event) {
	const char me[] = "soa_query";
	isc_result_t result;
	dns_message_t *message = NULL;
	dns_zone_t *zone = event->ev_arg;
	isc_netaddr_t masterip;
	dns_peer_t *peer = NULL;
	dns_name_t *keyname = NULL;
	dns_tsigkey_t *key = NULL;
	isc_uint32_t options;

	REQUIRE(DNS_ZONE_VALID(zone));

	UNUSED(task);

	DNS_ENTER;

	if (((event->ev_attributes & ISC_EVENTATTR_CANCELED) != 0) ||
	    DNS_ZONE_FLAG(zone, DNS_ZONEFLG_EXITING)) {
		if (!DNS_ZONE_FLAG(zone, DNS_ZONEFLG_EXITING))
			cancel_refresh(zone);
		isc_event_free(&event);
		dns_zone_idetach(&zone);
		return;
	}

	/* 
	 * XXX Optimisation: Create message when zone is setup and reuse.
	 */
	result = create_query(zone, dns_rdatatype_soa, &message);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	LOCK(&zone->lock);
	INSIST(zone->masterscnt > 0);
	INSIST(zone->curmaster < zone->masterscnt);
	zone->masteraddr = zone->masters[zone->curmaster];
	UNLOCK(&zone->lock);

	isc_netaddr_fromsockaddr(&masterip, &zone->masteraddr);
	result = dns_peerlist_peerbyaddr(zone->view->peers,
					 &masterip, &peer);
	if (result == ISC_R_SUCCESS &&
	    dns_peer_getkey(peer, &keyname) == ISC_R_SUCCESS)
	{
		result = dns_tsigkey_find(&key, keyname, NULL,
					  zone->view->statickeys);
		if (result == ISC_R_NOTFOUND)
			(void) dns_tsigkey_find(&key, keyname, NULL,
						zone->view->dynamickeys);
	}

	options = DNS_ZONE_FLAG(zone, DNS_ZONEFLG_USEVC) ? 
		  DNS_REQUESTOPT_TCP : 0;
	result = dns_request_create(zone->view->requestmgr, message,
				    &zone->masteraddr, options, key,
				    15 /* XXX */, zone->task,
				    refresh_callback, zone, &zone->request);
	if (result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_DEBUG(1),
			 "dns_request_create failed: %s",
			 dns_result_totext(result));
		goto cleanup;
	}
	dns_message_destroy(&message);
	isc_event_free(&event);
	dns_zone_idetach(&zone);
	return;

 cleanup:
	if (message != NULL)
		dns_message_destroy(&message);
	cancel_refresh(zone);
	isc_event_free(&event);
	dns_zone_idetach(&zone);
	return;
}

static void
ns_query(dns_zone_t *zone, dns_rdataset_t *soardataset, dns_stub_t *stub) {
	const char me[] = "ns_query";
	isc_result_t result;
	dns_message_t *message = NULL;
	isc_netaddr_t masterip;
	dns_peer_t *peer = NULL;
	dns_name_t *keyname = NULL;
	dns_tsigkey_t *key = NULL;
	dns_dbnode_t *node = NULL;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE((soardataset != NULL && stub == NULL) ||
		(soardataset == NULL && stub != NULL));
	REQUIRE(stub == NULL || DNS_STUB_VALID(stub));

	DNS_ENTER;

	if (stub == NULL) {
		stub = isc_mem_get(zone->mctx, sizeof *stub);
		if (stub == NULL)
			goto cleanup;
		stub->magic = STUB_MAGIC;
		stub->mctx = zone->mctx;
		stub->zone = NULL;
		stub->db = NULL;
		stub->version = NULL;

		/*
		 * Attach so that the zone won't disappear from under us.
		 */
		dns_zone_iattach(zone, &stub->zone);

		/*
		 * If a db exists we will update it, otherwise we create a
		 * new one and attach it to the zone once we have the NS
		 * RRset and glue.
		 */
		if (zone->db != NULL)
			dns_db_attach(zone->db, &stub->db);
		else {
			result = dns_db_create(zone->mctx, "rbt",
					       &zone->origin, dns_dbtype_stub,
					       zone->rdclass,
					       zone->db_argc, zone->db_argv,
					       &stub->db);
			if (result != ISC_R_SUCCESS) {
				zone_log(zone, me, ISC_LOG_INFO,
					 "dns_db_create failed: %s",
					 dns_result_totext(result));
				goto cleanup;
			}
		}

		dns_db_newversion(stub->db, &stub->version);

		/*
		 * Update SOA record.
		 */
		result = dns_db_findnode(stub->db, &zone->origin, ISC_TRUE,
					 &node);
		if (result != ISC_R_SUCCESS) {
			zone_log(zone, me, ISC_LOG_INFO,
				 "dns_db_findnode failed: %s",
				 dns_result_totext(result));
			goto cleanup;
		}

		result = dns_db_addrdataset(stub->db, node, stub->version, 0,
					    soardataset, 0, NULL);
		dns_db_detachnode(stub->db, &node);
		if (result != ISC_R_SUCCESS) {
			zone_log(zone, me, ISC_LOG_INFO,
				 "dns_db_addrdataset failed: %s",
				 dns_result_totext(result));
			goto cleanup;
		}

	}

	/* 
	 * XXX Optimisation: Create message when zone is setup and reuse.
	 */
	result = create_query(zone, dns_rdatatype_ns, &message);

	LOCK(&zone->lock);
	INSIST(zone->masterscnt > 0);
	INSIST(zone->curmaster < zone->masterscnt);
	zone->masteraddr = zone->masters[zone->curmaster];
	UNLOCK(&zone->lock);

	isc_netaddr_fromsockaddr(&masterip, &zone->masteraddr);
	result = dns_peerlist_peerbyaddr(zone->view->peers,
					 &masterip, &peer);
	if (result == ISC_R_SUCCESS &&
	    dns_peer_getkey(peer, &keyname) == ISC_R_SUCCESS)
	{
		result = dns_tsigkey_find(&key, keyname, NULL,
					  zone->view->statickeys);
		if (result == ISC_R_NOTFOUND)
			(void) dns_tsigkey_find(&key, keyname, NULL,
						zone->view->dynamickeys);
	}

	/*
	 * Always use TCP so that we shouldn't truncate in additional section.
	 */
	result = dns_request_create(zone->view->requestmgr, message,
				    &zone->masteraddr, DNS_REQUESTOPT_TCP, key,
				    15 /* XXX */, zone->task,
				    stub_callback, stub, &zone->request);
	if (result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_DEBUG(1),
			 "dns_request_create failed: %s",
			 dns_result_totext(result));
		goto cleanup;
	}
	dns_message_destroy(&message);
	return;

 cleanup:
	if (stub != NULL) {
		stub->magic = 0;
		if (stub->version != NULL)
			dns_db_closeversion(stub->db, &stub->version,
					    ISC_FALSE);
		if (stub->db != NULL)
			dns_db_detach(&stub->db);
		isc_mem_put(stub->mctx, stub, sizeof(*stub));
	}
	if (message != NULL)
		dns_message_destroy(&message);
	cancel_refresh(zone);
	return;
}

/*
 * Handle the control event.  Note that although this event causes the zone
 * to shut down, it is not a shutdown event in the sense of the task library.
 */
static void
zone_shutdown(isc_task_t *task, isc_event_t *event) {
	dns_zone_t *zone = (dns_zone_t *) event->ev_arg;
	dns_notify_t *notify;
	isc_result_t result;

	UNUSED(task);
	REQUIRE(DNS_ZONE_VALID(zone));
	INSIST(event->ev_type == DNS_EVENT_ZONECONTROL);
	INSIST(zone->erefs == 0);	
	zone_log(zone, "zone_shutdown", ISC_LOG_DEBUG(3), "shutting down");
	LOCK(&zone->lock);
	zone->flags |= DNS_ZONEFLG_EXITING;
	UNLOCK(&zone->lock);

	/*
	 * If we were waiting for xfrin quota, step out of
	 * the queue.
	 */
	if (zone->statelist == &zone->zmgr->waiting_for_xfrin) {
		RWLOCK(&zone->zmgr->rwlock, isc_rwlocktype_write);
		ISC_LIST_UNLINK(zone->zmgr->waiting_for_xfrin, zone,
				statelink);
		RWUNLOCK(&zone->zmgr->rwlock, isc_rwlocktype_write);
		zone->statelist = NULL;
	}
	
	if (zone->xfr != NULL)
		dns_xfrin_shutdown(zone->xfr);

	if (zone->request != NULL)
		dns_request_cancel(zone->request);

	for (notify = ISC_LIST_HEAD(zone->notifies);
	     notify != NULL;
	     notify = ISC_LIST_NEXT(notify, link)) {
		if (notify->find != NULL)
			dns_adb_cancelfind(notify->find);
		if (notify->request != NULL)
			dns_request_cancel(notify->request);
	}

	if (zone->timer != NULL) {
		result = isc_timer_reset(zone->timer, isc_timertype_inactive,
					 NULL, NULL, ISC_TRUE);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
	}

	if (zone->view != NULL)
		dns_view_weakdetach(&zone->view);
	    
	exit_check(zone);
}

static void
zone_timer(isc_task_t *task, isc_event_t *event) {
	const char me[] = "zone_timer";
	dns_zone_t *zone = (dns_zone_t *)event->ev_arg;
	UNUSED(task);

	DNS_ENTER;

	dns_zonemgr_lockconf(zone->zmgr, isc_rwlocktype_read);
	/* XXX if we use a view, we need to lock its configuration, too. */
	dns_zone_maintenance(zone);
	dns_zonemgr_unlockconf(zone->zmgr, isc_rwlocktype_read);
	
	isc_event_free(&event);
}

static isc_result_t
zone_settimer(dns_zone_t *zone, isc_stdtime_t now) {
	const char me[] = "zone_settimer";
	isc_stdtime_t next = 0;
	isc_time_t expires;
	isc_interval_t interval;
	isc_result_t result;

	REQUIRE(DNS_ZONE_VALID(zone));

	switch (zone->type) {
	case dns_zone_master:
		if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_NEEDNOTIFY))
			next = now;
		if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_NEEDDUMP) &&
		    (zone->dumptime < next || next == 0))
			next = zone->dumptime;
		break;
	case dns_zone_slave:
		if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_NEEDNOTIFY))
			next = now;
		/*FALLTHROUGH*/
	case dns_zone_stub:
		if (!DNS_ZONE_FLAG(zone, DNS_ZONEFLG_REFRESH) &&
		    !DNS_ZONE_FLAG(zone, DNS_ZONEFLG_NOMASTERS) &&
		    (zone->refreshtime < next || next == 0))
			next = zone->refreshtime;
		if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_LOADED)) {
		    	if (zone->expiretime < next || next == 0)
				next = zone->expiretime;
		}
		break;
	default:
		break;
	}

	if (next == 0) {
		zone_log(zone, me, ISC_LOG_DEBUG(10),
			 "settimer inactive");
		result = isc_timer_reset(zone->timer, isc_timertype_inactive,
					  NULL, NULL, ISC_TRUE);
	} else {
		if (next <= now)
			next = now + 1;
		zone_log(zone, me, ISC_LOG_DEBUG(10),
			 "settimer %d %d = %d seconds",
			 next, now, next - now);
		isc_time_settoepoch(&expires);
		isc_interval_set(&interval, next - now, 0);
		result = isc_timer_reset(zone->timer, isc_timertype_once,
					  &expires, &interval, ISC_TRUE);
	}
	if (result != ISC_R_SUCCESS)
		return (result);
	return (ISC_R_SUCCESS);
}

static void
cancel_refresh(dns_zone_t *zone) {
	const char me[] = "cancel_refresh";
	isc_stdtime_t now;
	/*
	 * caller to lock.
	 */

	REQUIRE(DNS_ZONE_VALID(zone));

	DNS_ENTER;

	zone->flags &= ~DNS_ZONEFLG_REFRESH;
	isc_stdtime_get(&now);
	if (!DNS_ZONE_FLAG(zone, DNS_ZONEFLG_EXITING))
		zone_settimer(zone, now);
}

static isc_result_t
notify_createmessage(dns_zone_t *zone, dns_message_t **messagep)
{
	dns_dbnode_t *node = NULL;
	dns_dbversion_t *version = NULL;
	dns_message_t *message = NULL;
	dns_rdataset_t rdataset;
	dns_rdata_t rdata;

	dns_name_t *tempname = NULL;
	dns_rdata_t *temprdata = NULL;
	dns_rdatalist_t *temprdatalist = NULL;
	dns_rdataset_t *temprdataset = NULL;

	isc_result_t result;
	isc_region_t r;
	isc_buffer_t *b = NULL;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(messagep != NULL && *messagep == NULL);

	message = NULL;
	result = dns_message_create(zone->mctx, DNS_MESSAGE_INTENTRENDER,
				    &message);
	if (result != ISC_R_SUCCESS)
		goto fail;

	message->opcode = dns_opcode_notify;
	message->rdclass = zone->rdclass;

	result = dns_message_gettempname(message, &tempname);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = dns_message_gettemprdataset(message, &temprdataset);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	/*
	 * Make question.
	 */
	dns_name_init(tempname, NULL);
	dns_name_clone(&zone->origin, tempname);
	dns_rdataset_init(temprdataset);
	dns_rdataset_makequestion(temprdataset, zone->rdclass,
				  dns_rdatatype_soa);
	ISC_LIST_APPEND(tempname->list, temprdataset, link);
	dns_message_addname(message, tempname, DNS_SECTION_QUESTION);
	tempname = NULL;
	temprdataset = NULL;
	
	/*
	 * If the zone is dialup we are done as we don't want to send
	 * the current soa so as to force a refresh query.
	 */
	if (DNS_ZONE_OPTION(zone, DNS_ZONEOPT_DIALUP))
		goto done;

	result = dns_message_gettempname(message, &tempname);
	if (result != ISC_R_SUCCESS)
		goto done;
	result = dns_message_gettemprdata(message, &temprdata);
	if (result != ISC_R_SUCCESS)
		goto done;
	result = dns_message_gettemprdataset(message, &temprdataset);
	if (result != ISC_R_SUCCESS)
		goto done;
	result = dns_message_gettemprdatalist(message, &temprdatalist);
	if (result != ISC_R_SUCCESS)
		goto done;

	dns_name_init(tempname, NULL);
	dns_name_clone(&zone->origin, tempname);
	dns_db_currentversion(zone->db, &version);
        result = dns_db_findnode(zone->db, tempname, ISC_FALSE, &node);
	if (result != ISC_R_SUCCESS)
		goto done;

	dns_rdataset_init(&rdataset);
	result = dns_db_findrdataset(zone->db, node, version,
				     dns_rdatatype_soa,
				     dns_rdatatype_none, 0, &rdataset,
				     NULL);
	if (result != ISC_R_SUCCESS)
		goto done;
	result = dns_rdataset_first(&rdataset);
	if (result != ISC_R_SUCCESS)
		goto done;
	dns_rdata_init(&rdata);
	dns_rdataset_current(&rdataset, &rdata);
	dns_rdata_toregion(&rdata, &r);
	result = isc_buffer_allocate(zone->mctx, &b, r.length);
	if (result != ISC_R_SUCCESS)
		goto done;
	isc_buffer_putmem(b, r.base, r.length);
	isc_buffer_usedregion(b, &r);
	dns_rdata_init(temprdata);
	dns_rdata_fromregion(temprdata, rdata.rdclass, rdata.type, &r);
	dns_message_takebuffer(message, &b);
	result = dns_rdataset_next(&rdataset);
	dns_rdataset_disassociate(&rdataset);
	if (result != ISC_R_NOMORE)
		goto done;
	temprdatalist->rdclass = rdata.rdclass;
	temprdatalist->type = rdata.type;
	temprdatalist->covers = 0;
	temprdatalist->ttl = rdataset.ttl;
	ISC_LIST_INIT(temprdatalist->rdata);
	ISC_LIST_APPEND(temprdatalist->rdata, temprdata, link);

	dns_rdataset_init(temprdataset);
	result = dns_rdatalist_tordataset(temprdatalist, temprdataset);
	if (result != ISC_R_SUCCESS)
		goto done;

	ISC_LIST_APPEND(tempname->list, temprdataset, link);
	dns_message_addname(message, tempname, DNS_SECTION_ANSWER);
	temprdatalist = NULL;
	temprdataset = NULL;
	temprdata = NULL;
	tempname = NULL;

 done:
	*messagep = message;
	message = NULL;
	result = ISC_R_SUCCESS;

 cleanup:
	if (node != NULL)
		dns_db_detachnode(zone->db, &node);
	if (version != NULL)
		dns_db_closeversion(zone->db, &version, ISC_FALSE);
	if (tempname != NULL)
		dns_message_puttempname(message, &tempname);
	if (temprdata != NULL)
		dns_message_puttemprdata(message, &temprdata);
	if (temprdataset != NULL)
		dns_message_puttemprdataset(message, &temprdataset);
	if (temprdatalist != NULL)
		dns_message_puttemprdatalist(message, &temprdatalist);
	if (message != NULL)
		dns_message_destroy(&message);

 fail:
	return (result);
}

isc_result_t
dns_zone_notifyreceive(dns_zone_t *zone, isc_sockaddr_t *from,
		       dns_message_t *msg)
{
	const char me[] = "dns_zone_notifyreceive";
	unsigned int i;
	dns_rdata_soa_t soa;
	dns_rdataset_t *rdataset = NULL;
	dns_rdata_t rdata;
	isc_result_t result;
	isc_stdtime_t now;

	REQUIRE(DNS_ZONE_VALID(zone));

	/*
	 * If type != T_SOA return DNS_R_REFUSED.  We don't yet support
	 * ROLLOVER.
	 *
	 * SOA:	RFC 1996
	 * Check that 'from' is a valid notify source, (zone->masters).
	 *	Return DNS_R_REFUSED if not.
	 *
	 * If the notify message contains a serial number check it
	 * against the zones serial and return if <= current serial
	 *
	 * If a refresh check is progress, if so just record the
	 * fact we received a NOTIFY and from where and return. 
	 * We will perform a new refresh check when the current one
	 * completes. Return ISC_R_SUCCESS.
	 *
	 * Otherwise initiate a refresh check using 'from' as the
	 * first address to check.  Return ISC_R_SUCCESS.
	 */

	/*
	 *  We only handle NOTIFY (SOA) at the present.
	 */
	LOCK(&zone->lock);
	if (msg->counts[DNS_SECTION_QUESTION] == 0 ||
	    dns_message_findname(msg, DNS_SECTION_QUESTION, &zone->origin,
				 dns_rdatatype_soa, dns_rdatatype_none,
				 NULL, NULL) != ISC_R_SUCCESS) {
		UNLOCK(&zone->lock);
		if (msg->counts[DNS_SECTION_QUESTION] == 0) {
			zone_log(zone, me, ISC_LOG_NOTICE,
				 "FORMERR no question");
			return (DNS_R_FORMERR);
		}
		zone_log(zone, me, ISC_LOG_NOTICE,
			 "REFUSED zone does not match");
		return (DNS_R_NOTIMP);
	}

	/*
	 * If we are a master zone just succeed.
	 */
	if (zone->type == dns_zone_master) {
		UNLOCK(&zone->lock);
		return (ISC_R_SUCCESS);
	}

	for (i = 0; i < zone->masterscnt; i++)
		if (isc_sockaddr_eqaddr(from, &zone->masters[i]))
			break;

	if (i >= zone->masterscnt) {
		UNLOCK(&zone->lock);
		zone_log(zone, me, ISC_LOG_DEBUG(3),
			 "REFUSED notify from non master");
		return (DNS_R_REFUSED);
	}

	/*
	 * If the zone is loaded and there are answers check the serial
	 * to see if we need to do a refresh.  Do not worry about this
	 * check if we are a dialup zone as we use the notify request
	 * to trigger a refresh check.
	 */
	if (msg->counts[DNS_SECTION_ANSWER] > 0 &&
	    DNS_ZONE_FLAG(zone, DNS_ZONEFLG_LOADED) &&
	    !DNS_ZONE_OPTION(zone, DNS_ZONEOPT_DIALUP)) {
		result = dns_message_findname(msg, DNS_SECTION_ANSWER,
					      &zone->origin,
					      dns_rdatatype_soa,
					      dns_rdatatype_none, NULL, 
					      &rdataset);
		if (result == ISC_R_SUCCESS)
			result = dns_rdataset_first(rdataset);
		if (result == ISC_R_SUCCESS) {
			isc_uint32_t serial = 0;

			dns_rdataset_current(rdataset, &rdata);
			result = dns_rdata_tostruct(&rdata, &soa, NULL);
			if (result == ISC_R_SUCCESS) {
				serial = soa.serial;
				if (isc_serial_le(serial, zone->serial)) {
					zone_log(zone, me, ISC_LOG_DEBUG(3),
						 "zone up to date");
					UNLOCK(&zone->lock);
					return (ISC_R_SUCCESS);
				}
			}
		} 
	}

	/*
	 * If we got this far and there was a refresh in progress just
	 * let it complete.  Record where we got the notify from so we
	 * can perform a refresh check when the current one completes
	 */
	if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_REFRESH)) {
		zone->flags |= DNS_ZONEFLG_NEEDREFRESH;
		zone->notifyfrom = *from;
		UNLOCK(&zone->lock);
		zone_log(zone, me, ISC_LOG_DEBUG(3),
			 "refresh in progress, refresh check queued");
		return (ISC_R_SUCCESS);
	}
	isc_stdtime_get(&now);
	zone->refreshtime = now;
	zone->notifyfrom = *from;
	zone_settimer(zone, now);
	UNLOCK(&zone->lock);
	zone_log(zone, me, ISC_LOG_DEBUG(3), "immediate refresh check queued");
	return (ISC_R_SUCCESS);
}

void
dns_zone_setqueryacl(dns_zone_t *zone, dns_acl_t *acl) {

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->query_acl != NULL)
		dns_acl_detach(&zone->query_acl);
	dns_acl_attach(acl, &zone->query_acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_setupdateacl(dns_zone_t *zone, dns_acl_t *acl) {

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->update_acl != NULL)
		dns_acl_detach(&zone->update_acl);
	dns_acl_attach(acl, &zone->update_acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_setxfracl(dns_zone_t *zone, dns_acl_t *acl) {

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->xfr_acl != NULL)
		dns_acl_detach(&zone->xfr_acl);
	dns_acl_attach(acl, &zone->xfr_acl);
	UNLOCK(&zone->lock);
}

dns_acl_t *
dns_zone_getqueryacl(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->query_acl);
}

dns_acl_t *
dns_zone_getupdateacl(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->update_acl);
}

dns_acl_t *
dns_zone_getxfracl(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->xfr_acl);
}

void
dns_zone_clearupdateacl(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->update_acl != NULL)
		dns_acl_detach(&zone->update_acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_clearqueryacl(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->query_acl != NULL)
		dns_acl_detach(&zone->query_acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_clearxfracl(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->xfr_acl != NULL)
		dns_acl_detach(&zone->xfr_acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_setchecknames(dns_zone_t *zone, dns_severity_t severity) {

	REQUIRE(DNS_ZONE_VALID(zone));

	zone->check_names = severity;
}

dns_severity_t
dns_zone_getchecknames(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->check_names);
}

void
dns_zone_setjournalsize(dns_zone_t *zone, isc_int32_t size) {
	
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->journalsize = size;
}

isc_int32_t
dns_zone_getjournalsize(dns_zone_t *zone) {
	
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->journalsize);
}

static void
zone_log(dns_zone_t *zone, const char *me, int level, const char *fmt, ...) {
	va_list ap;
	char message[4096];
	char namebuf[1024+32];
	isc_buffer_t buffer;
	int len;
	isc_result_t result = ISC_R_FAILURE;

	isc_buffer_init(&buffer, namebuf, sizeof(namebuf));

	if (dns_name_dynamic(&zone->origin))
		result = dns_name_totext(&zone->origin, ISC_TRUE, &buffer);
	if (result != ISC_R_SUCCESS)
		isc_buffer_putstr(&buffer, "<UNKNOWN>");

	isc_buffer_putstr(&buffer, "/");
	(void)dns_rdataclass_totext(zone->rdclass, &buffer);
	len = isc_buffer_usedlength(&buffer);

	va_start(ap, fmt);
	vsnprintf(message, sizeof message, fmt, ap);
	va_end(ap);
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_ZONE,
		      level, "%s: zone %.*s: %s", me, len, namebuf, message);
}

static int
message_count(dns_message_t *msg, dns_section_t section, dns_rdatatype_t type)
{
	isc_result_t result;
	dns_name_t *name;
	dns_rdataset_t *curr;
	int count = 0;

	result = dns_message_firstname(msg, section);
	while (result == ISC_R_SUCCESS) {
		name = NULL;
		dns_message_currentname(msg, section, &name);

		for (curr = ISC_LIST_TAIL(name->list); curr != NULL; 
		     curr = ISC_LIST_PREV(curr, link)) {
			if (curr->type == type)
				count++;
		}
		result = dns_message_nextname(msg, section);
	}

	return (count);
}

void
dns_zone_setmaxxfrin(dns_zone_t *zone, isc_uint32_t maxxfrin) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(maxxfrin != 0);
	zone->maxxfrin = maxxfrin;
}

isc_uint32_t
dns_zone_getmaxxfrin(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->maxxfrin);
}

void
dns_zone_setmaxxfrout(dns_zone_t *zone, isc_uint32_t maxxfrout) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(maxxfrout != 0);
	zone->maxxfrout = maxxfrout;
}

isc_uint32_t
dns_zone_getmaxxfrout(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->maxxfrout);
}

dns_zonetype_t dns_zone_gettype(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->type);
}

dns_name_t *
dns_zone_getorigin(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return (&zone->origin);
}

void
dns_zone_settask(dns_zone_t *zone, isc_task_t *task) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->task != NULL)
		isc_task_detach(&zone->task);
	isc_task_attach(task, &zone->task);
	UNLOCK(&zone->lock);
}

void
dns_zone_gettask(dns_zone_t *zone, isc_task_t **target) {
	REQUIRE(DNS_ZONE_VALID(zone));
	isc_task_attach(zone->task, target);
}

const char *
dns_zone_getdatabase(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->dbname);
}

void
dns_zone_setidlein(dns_zone_t *zone, isc_uint32_t idlein) {
	REQUIRE(DNS_ZONE_VALID(zone));

	if (idlein == 0)
		idlein = DNS_DEFAULT_IDLEIN;
	zone->idlein = idlein;
}

isc_uint32_t
dns_zone_getidlein(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->idlein);
}

void
dns_zone_setidleout(dns_zone_t *zone, isc_uint32_t idleout) {
	REQUIRE(DNS_ZONE_VALID(zone));

	if (idleout == 0)
		idleout = DNS_DEFAULT_IDLEOUT;
	zone->idleout = idleout;
}

isc_uint32_t
dns_zone_getidleout(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->idleout);
}

#ifdef notyet
static void
record_serial() {
}
#endif

static void
notify_done(isc_task_t *task, isc_event_t *event) {
        const char me[] = "notify_done";
	dns_notify_t *notify;
	dns_zone_t *zone = NULL;
	
	UNUSED(task);

	notify = event->ev_arg;
	REQUIRE(DNS_NOTIFY_VALID(notify));

	dns_zone_iattach(notify->zone, &zone);
	DNS_ENTER;
	isc_event_free(&event);
	LOCK(&zone->lock);
	notify_destroy(notify);
	UNLOCK(&zone->lock);
	dns_zone_idetach(&zone);
}


isc_boolean_t
dns_zone_equal(dns_zone_t *oldzone, dns_zone_t *newzone) {
	unsigned int i;

	REQUIRE(DNS_ZONE_VALID(oldzone));
	REQUIRE(DNS_ZONE_VALID(newzone));

	LOCK(&oldzone->lock);
	LOCK(&newzone->lock);
	if (oldzone->type != newzone->type ||
	    oldzone->maxxfrin != newzone->maxxfrin ||
	    oldzone->maxxfrout != newzone->maxxfrout ||
	    oldzone->idlein != newzone->idlein ||
	    oldzone->idleout != newzone->idleout ||
	    oldzone->rdclass != newzone->rdclass ||
	    oldzone->db_argc != newzone->db_argc ||
	    oldzone->notifycnt != newzone->notifycnt ||
	    oldzone->masterscnt != newzone->masterscnt ||
	    oldzone->check_names != newzone->check_names ||
	    oldzone->diff_on_reload != newzone->diff_on_reload ||
	    oldzone->journalsize != newzone->journalsize)
		goto false;

	if (!dns_name_equal(&oldzone->origin, &newzone->origin))
		goto false;

	if ((oldzone->journal == NULL && newzone->journal != NULL) ||
	    (oldzone->journal != NULL && newzone->journal == NULL) ||
	    (oldzone->journal != NULL &&
	     strcmp(oldzone->journal, newzone->journal) != 0))
		goto false;

	if ((oldzone->db_type == NULL && newzone->db_type != NULL) ||
	    (oldzone->db_type != NULL && newzone->db_type == NULL) ||
	    (oldzone->db_type != NULL &&
	     strcmp(oldzone->db_type, newzone->db_type) != 0))
		goto false;

	for (i = 0; i < oldzone->db_argc; i++)
		if (strcmp(oldzone->db_argv[i], newzone->db_argv[i]) != 0)
			goto false;

	if (!isc_sockaddr_equal(&oldzone->xfrsource4, &newzone->xfrsource4))
		goto false;

	if (!isc_sockaddr_equal(&oldzone->xfrsource6, &newzone->xfrsource6))
		goto false;

	for (i = 0; i < oldzone->notifycnt; i++)
		if (!isc_sockaddr_equal(&oldzone->notify[i],
					&newzone->notify[i]))
			goto false;

	for (i = 0; i < oldzone->masterscnt; i++)
		if (!isc_sockaddr_equal(&oldzone->masters[i],
					&newzone->masters[i]))
			goto false;

#define COMPARE_POINTERS(equalp, member) \
	if ((oldzone->member == NULL && newzone->member != NULL) || \
	    (oldzone->member != NULL && newzone->member == NULL) || \
	    (oldzone->member != NULL && 			    \
	     !(equalp)(oldzone->member, newzone->member)))	    \
			goto false

	COMPARE_POINTERS(dns_acl_equal, update_acl);
	COMPARE_POINTERS(dns_acl_equal, query_acl);
	COMPARE_POINTERS(dns_acl_equal, xfr_acl);

#undef COMPARE_POINTERS

	UNLOCK(&newzone->lock);
	UNLOCK(&oldzone->lock);
	return(ISC_TRUE);	/* XXX should be ISC_TRUE once acl/pubkey
				   checks are done. */

 false:
	UNLOCK(&newzone->lock);
	UNLOCK(&oldzone->lock);
	return (ISC_FALSE);
}


isc_result_t
dns_zone_replacedb(dns_zone_t *zone, dns_db_t *db, isc_boolean_t dump) {
	isc_result_t result;
	
	REQUIRE(DNS_ZONE_VALID(zone));
	LOCK(&zone->lock);
	result = zone_replacedb(zone, db, dump);
	UNLOCK(&zone->lock);
	return (result);
}

static isc_result_t
zone_replacedb(dns_zone_t *zone, dns_db_t *db, isc_boolean_t dump) {
	dns_dbversion_t *ver;
	isc_result_t result;

	REQUIRE(DNS_ZONE_VALID(zone));

	ver = NULL;
	dns_db_currentversion(db, &ver);

	/*
	 * The initial version of a slave zone is always dumped; 
	 * subsequent versions may be journalled instead if this
	 * is enabled in the configuration.
	 */
	if (zone->db != NULL && zone->journal != NULL &&
	    zone->diff_on_reload) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_ZONE, ISC_LOG_DEBUG(3),
			      "generating diffs");
		result = dns_db_diff(zone->mctx, db, ver,
				     zone->db, NULL /* XXX */,
				     zone->journal);
		if (result != ISC_R_SUCCESS)
			goto fail;
	} else {
		if (dump && zone->dbname != NULL) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
				      DNS_LOGMODULE_ZONE, ISC_LOG_DEBUG(3),
				      "dumping new zone version");
			/* XXX should use temporary file and rename */
			result = dns_db_dump(db, ver, zone->dbname);
			if (result != ISC_R_SUCCESS)
				goto fail;

			/*
			 * Update the time the zone was updated, so
			 * dns_zone_load can avoid loading it when
			 * the server is reloaded.  If isc_time_now
			 * fails for some reason, all that happens is
			 * the timestamp is not updated.
			 */
			(void)isc_time_now(&zone->loadtime);
		}
		if (zone->journal != NULL) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
				      DNS_LOGMODULE_ZONE, ISC_LOG_DEBUG(3),
				      "removing journal file");
			(void)remove(zone->journal);
		}
	}
	dns_db_closeversion(db, &ver, ISC_FALSE);

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
		      DNS_LOGMODULE_ZONE, ISC_LOG_DEBUG(3),
		      "replacing zone database");
	
	if (zone->db != NULL)
		dns_db_detach(&zone->db);
	dns_db_attach(db, &zone->db);
	zone->flags |= DNS_ZONEFLG_LOADED|DNS_ZONEFLG_NEEDNOTIFY;
	return (ISC_R_SUCCESS);
	
 fail:
	dns_db_closeversion(db, &ver, ISC_FALSE);
	return (result);
}

static void
zone_xfrdone(dns_zone_t *zone, isc_result_t result) {
	const char me[] = "zone_xfrdone";
	isc_stdtime_t now;
	isc_boolean_t again = ISC_FALSE;
	unsigned int soacount;
	unsigned int nscount;
	isc_uint32_t serial, refresh, retry, expire, minimum;

	REQUIRE(DNS_ZONE_VALID(zone));

	zone_log(zone, me, ISC_LOG_DEBUG(1), "%s", dns_result_totext(result));

	LOCK(&zone->lock);
	INSIST((zone->flags & DNS_ZONEFLG_REFRESH) != 0);
	zone->flags &= ~DNS_ZONEFLG_REFRESH;

	isc_stdtime_get(&now);
	switch (result) {
	case ISC_R_SUCCESS:
		zone->flags |= DNS_ZONEFLG_NEEDNOTIFY;
		/*FALLTHROUGH*/
	case DNS_R_UPTODATE:
		/*
		 * This is not neccessary if we just performed a AXFR
		 * however it is necessary for an IXFR / UPTODATE and
		 * won't hurt with an AXFR.
		 */
		if (zone->dbname != NULL) {
			isc_time_t t;
			isc_time_set(&t, now, 0);
			result = isc_file_settime(zone->dbname, &t);
			if (result != ISC_R_SUCCESS)
				zone_log(zone, me, ISC_LOG_ERROR,
					 "isc_file_settime(%s): %s",
					 zone->dbname,
					 dns_result_totext(result));
		}

		/*
		 * Update the zone structure's data from the actual
		 * SOA received.
		 */
		nscount = 0;
		soacount = 0;
		INSIST(zone->db != NULL);
		result = zone_get_from_db(zone->db, &zone->origin, &nscount,
					  &soacount, &serial, &refresh,
					  &retry, &expire, &minimum);
		if (result == ISC_R_SUCCESS) {
			if (soacount != 1)
				zone_log(zone, me, ISC_LOG_ERROR,
					 "has %d SOA record%s", soacount,
					 (soacount != 0) ? "s" : "");
			if (nscount == 0)
				zone_log(zone, me, ISC_LOG_ERROR,
					 "no NS records");
			zone->serial = serial;
			zone->refresh = RANGE(refresh, DNS_MIN_REFRESH,
					      DNS_MAX_REFRESH);
			zone->retry = RANGE(retry, DNS_MIN_REFRESH,
					    DNS_MAX_REFRESH);
			zone->expire = RANGE(expire,
					     zone->refresh + zone->retry,
					     DNS_MAX_EXPIRE);
			zone->minimum = minimum;
		}

		/*
		 * Set our next update/expire times.
		 */
		if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_NEEDREFRESH)) {
			zone->flags &= ~DNS_ZONEFLG_NEEDREFRESH;
			zone->refreshtime = now;
			zone->expiretime = now + zone->expire;
		} else {
			zone->refreshtime = now + zone->refresh;
			zone->expiretime = now + zone->expire;
		}
	
		break;

	default:
		zone->curmaster++;
		if (zone->curmaster >= zone->masterscnt)
			zone->curmaster = 0;
		else {
			zone->flags |= DNS_ZONEFLG_REFRESH;
			again = ISC_TRUE;
		}
		break;
	}
	zone_settimer(zone, now);
	UNLOCK(&zone->lock);

	/*
	 * If creating the transfer object failed, zone->xfr is NULL.
	 * Otherwise, we are called as the done callback of a zone
	 * transfer object that just entered its shutting-down
	 * state.  Since we are no longer responsible for shutting
	 * it down, we can detach our reference.
	 */
	if (zone->xfr != NULL)
		dns_xfrin_detach(&zone->xfr);

	/*
	 * This transfer finishing freed up a transfer quota slot.
	 * Let any zones waiting for quota have it.
	 */
	RWLOCK(&zone->zmgr->rwlock, isc_rwlocktype_write);	
	ISC_LIST_UNLINK(zone->zmgr->xfrin_in_progress, zone, statelink);
	zone->statelist = NULL;
	if (!DNS_ZONE_FLAG(zone, DNS_ZONEFLG_EXITING))
		zmgr_resume_xfrs(zone->zmgr);
	RWUNLOCK(&zone->zmgr->rwlock, isc_rwlocktype_write);
	
	/*
	 * Retry with a different server if necessary.
	 */
	if (again && !DNS_ZONE_FLAG(zone, DNS_ZONEFLG_EXITING))
		queue_soa_query(zone);
}

void
dns_zone_getssutable(dns_zone_t *zone, dns_ssutable_t **table) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(table != NULL);
	REQUIRE(*table == NULL);
	*table = zone->ssutable;
}

void
dns_zone_setssutable(dns_zone_t *zone, dns_ssutable_t *table) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(table != NULL);
	zone->ssutable = table;
}

void
dns_zone_setsigvalidityinterval(dns_zone_t *zone, isc_uint32_t interval) {
	REQUIRE(DNS_ZONE_VALID(zone));     

	zone->sigvalidityinterval = interval;
}

isc_uint32_t
dns_zone_getsigvalidityinterval(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));     	

	return (zone->sigvalidityinterval);
}

static void
queue_xfrin(dns_zone_t *zone) {
	const char me[] = "queue_xfrin";
	isc_result_t result;
	dns_zonemgr_t *zmgr = zone->zmgr;

	DNS_ENTER;

	INSIST(zone->statelist == NULL);

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_write);	
	ISC_LIST_APPEND(zmgr->waiting_for_xfrin, zone, statelink);
	zone->statelist = &zmgr->waiting_for_xfrin;
	result = zmgr_start_xfrin_ifquota(zmgr, zone);
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_write);	

	if (result == ISC_R_QUOTA) {
		zone_log(zone, me, ISC_LOG_DEBUG(1),
			 "zone transfer deferred due to quota");
	} else if (result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_ERROR,
			 "starting zone transfer: %s",
			 isc_result_totext(result));
	}
}

/*
 * This event callback is called when a zone has received
 * any necessary zone transfer quota.  This is the time
 * to go ahead and start the transfer.
 */
static void
got_transfer_quota(isc_task_t *task, isc_event_t *event) {
	const char me[] = "got_transfer_quota";
	isc_result_t result;
	dns_peer_t *peer = NULL;
	dns_tsigkey_t *tsigkey = NULL;
	dns_name_t *keyname = NULL;
	char mastertext[256];
	dns_rdatatype_t xfrtype;
	dns_zone_t *zone = event->ev_arg;
	isc_netaddr_t masterip;
	
	UNUSED(task);
	
	INSIST(task == zone->task);

	if (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_EXITING)) {
		result = ISC_R_CANCELED;
		goto cleanup;
	}
	
	isc_sockaddr_format(&zone->masteraddr, mastertext, sizeof(mastertext));
	
	isc_netaddr_fromsockaddr(&masterip, &zone->masteraddr);
	(void)dns_peerlist_peerbyaddr(zone->view->peers,
				      &masterip, &peer);
	
	/*
	 * Decide whether we should request IXFR or AXFR.
	 */
	if (zone->db == NULL) {
		zone_log(zone, me, ISC_LOG_DEBUG(3), 
			 "no database exists yet, requesting AXFR of "
			 "initial version from %s", mastertext);
		xfrtype = dns_rdatatype_axfr;
	} else {
		isc_boolean_t use_ixfr = ISC_TRUE;
		if (peer != NULL &&
		    dns_peer_getrequestixfr(peer, &use_ixfr) ==
		    ISC_R_SUCCESS) {
			; /* Using peer setting */ 
		} else {
			use_ixfr = zone->view->requestixfr;
		}
		if (use_ixfr == ISC_FALSE) {
			zone_log(zone, me, ISC_LOG_DEBUG(3),
				 "IXFR disabled, requesting AXFR from %s",
				 mastertext);
			xfrtype = dns_rdatatype_axfr;			
		} else {
			zone_log(zone, me, ISC_LOG_DEBUG(3),
				 "requesting IXFR form %s",
				 mastertext);
			xfrtype = dns_rdatatype_ixfr;
		}
	}

	/*
	 * Determine if we should attempt to sign the request with TSIG.
	 */
	if (peer != NULL && dns_peer_getkey(peer, &keyname) == ISC_R_SUCCESS) {
		dns_view_t *view = dns_zone_getview(zone);
		result = dns_tsigkey_find(&tsigkey, keyname, NULL,
					  view->statickeys);
		if (result == ISC_R_NOTFOUND)
			result = dns_tsigkey_find(&tsigkey, keyname, NULL,
						  view->dynamickeys);
		if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
			zone_log(zone, me, ISC_LOG_ERROR,
				 "error getting tsig keys "
				 "for zone transfer: %s",
				 isc_result_totext(result));
			goto cleanup;
		}
	}

	result = dns_xfrin_create(zone, xfrtype, &zone->masteraddr,
				  tsigkey, zone->mctx,
				  zone->zmgr->timermgr, zone->zmgr->socketmgr,
				  zone->task, zone_xfrdone, &zone->xfr);
 cleanup:
	/*
	 * Any failure in this function is handled like a failed
	 * zone transfer.  This ensures that we get removed from
	 * zmgr->xfrin_in_progress.
	 */
	if (result != ISC_R_SUCCESS)
		zone_xfrdone(zone, result);
	
	isc_event_free(&event);

	dns_zone_detach(&zone); /* XXXAG */
	return;

}

/***
 ***	Zone manager. 
 ***/

isc_result_t
dns_zonemgr_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		   isc_timermgr_t *timermgr, isc_socketmgr_t *socketmgr,
		   dns_zonemgr_t **zmgrp)
{
	dns_zonemgr_t *zmgr;
	isc_result_t result;
	isc_interval_t interval;

	zmgr = isc_mem_get(mctx, sizeof *zmgr);
	if (zmgr == NULL)
		return (ISC_R_NOMEMORY);
	zmgr->mctx = NULL;
	zmgr->refs = 1;
	isc_mem_attach(mctx, &zmgr->mctx);
	zmgr->taskmgr = taskmgr;
	zmgr->timermgr = timermgr;
	zmgr->socketmgr = socketmgr;
	zmgr->zonetasks = NULL;
	zmgr->task = NULL;
	zmgr->rl = NULL;
	ISC_LIST_INIT(zmgr->zones);
	ISC_LIST_INIT(zmgr->waiting_for_xfrin);
	ISC_LIST_INIT(zmgr->xfrin_in_progress);
	result = isc_rwlock_init(&zmgr->rwlock, 0, 0);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_rwlock_init() failed: %s",
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto free_mem;
	}
	result = isc_rwlock_init(&zmgr->conflock, 1, 1);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_rwlock_init() failed: %s",
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto free_rwlock;
	}

	zmgr->transfersin = 10;
	zmgr->transfersperns = 2;
	
	/* Create the zone task pool. */
	result = isc_taskpool_create(taskmgr, mctx, 
				     8 /* XXX */, 0, &zmgr->zonetasks);
	if (result != ISC_R_SUCCESS)
		goto free_conflock;

	/* Create a single task for queueing of SOA queries. */
	result = isc_task_create(taskmgr, 1, &zmgr->task);
	if (result != ISC_R_SUCCESS)
		goto free_taskpool;
	isc_task_setname(zmgr->task, "zmgr", zmgr);
	result = isc_ratelimiter_create(mctx, timermgr, zmgr->task,
					&zmgr->rl);
	if (result != ISC_R_SUCCESS)
		goto free_task;
	/* 20 refresh queries / notifies per second. */
	isc_interval_set(&interval, 0, 1000000000/2);
	result = isc_ratelimiter_setinterval(zmgr->rl, &interval);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	isc_ratelimiter_setpertic(zmgr->rl, 10);
	zmgr->magic = ZONEMGR_MAGIC;

	*zmgrp = zmgr;
	return (ISC_R_SUCCESS);

 free_task:
	isc_task_detach(&zmgr->task);
 free_taskpool:
	isc_taskpool_destroy(&zmgr->zonetasks);	
 free_conflock:
	isc_rwlock_destroy(&zmgr->conflock);
 free_rwlock:
	isc_rwlock_destroy(&zmgr->rwlock);
 free_mem:
	isc_mem_put(zmgr->mctx, zmgr, sizeof *zmgr);
	isc_mem_detach(&mctx);
	return (result);
}

isc_result_t
dns_zonemgr_managezone(dns_zonemgr_t *zmgr, dns_zone_t *zone) {
	isc_result_t result;
	
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	LOCK(&zone->lock);
	REQUIRE(zone->task == NULL);
	REQUIRE(zone->timer == NULL);
	REQUIRE(zone->zmgr == NULL);

	isc_taskpool_gettask(zmgr->zonetasks,
			     dns_name_hash(dns_zone_getorigin(zone),
					   ISC_FALSE),
			     &zone->task);

	/*
	 * Set the task name.  The tag will arbitrarily point to one
	 * of the zones sharing the task (in practice, the one
	 * to be managed last).
	 */
	isc_task_setname(zone->task, "zone", zone);

	result = isc_timer_create(zmgr->timermgr, isc_timertype_inactive,
				  NULL, NULL,
				  zmgr->task, zone_timer, zone,
				  &zone->timer);
	if (result != ISC_R_SUCCESS)
		goto cleanup_task;

	ISC_LIST_APPEND(zmgr->zones, zone, link);
	zone->zmgr = zmgr;
	zmgr->refs++;

	goto unlock;

 cleanup_task:
	isc_task_detach(&zone->task);
	
 unlock:
	UNLOCK(&zone->lock);
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	return (result);
}

void
dns_zonemgr_releasezone(dns_zonemgr_t *zmgr, dns_zone_t *zone) {
	isc_boolean_t free_now = ISC_FALSE;
	
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));
	REQUIRE(zone->zmgr == zmgr);

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	LOCK(&zone->lock);

	ISC_LIST_UNLINK(zmgr->zones, zone, link);
	zone->zmgr = NULL;
	zmgr->refs--;
	if (zmgr->refs == 0)
		free_now = ISC_TRUE;
	
	UNLOCK(&zone->lock);
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_write);

	if (free_now)
		zonemgr_free(zmgr);
	ENSURE(zone->zmgr == NULL);
}

void
dns_zonemgr_detach(dns_zonemgr_t **zmgrp) {
	dns_zonemgr_t *zmgr;
	isc_boolean_t free_now = ISC_FALSE;
	
	REQUIRE(zmgrp != NULL);
	zmgr = *zmgrp;
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	zmgr->refs--;
	if (zmgr->refs == 0)
		free_now = ISC_TRUE;
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_write);

	if (free_now)
		zonemgr_free(zmgr);
}

isc_result_t
dns_zonemgr_forcemaint(dns_zonemgr_t *zmgr) {
	dns_zone_t *p;

	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_read);
	for (p = ISC_LIST_HEAD(zmgr->zones);
	     p != NULL;
	     p = ISC_LIST_NEXT(p, link))
	{
		dns_zone_maintenance(p);
	}
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_read);
	return (ISC_R_SUCCESS);
}

void
dns_zonemgr_shutdown(dns_zonemgr_t *zmgr) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	isc_ratelimiter_shutdown(zmgr->rl);
}

static void
zonemgr_free(dns_zonemgr_t *zmgr) {
	isc_mem_t *mctx;

	INSIST(zmgr->refs == 0);
	INSIST(ISC_LIST_EMPTY(zmgr->zones));

	zmgr->magic = 0;

	if (zmgr->task != NULL)
		isc_task_destroy(&zmgr->task);
	if (zmgr->zonetasks != NULL)
		isc_taskpool_destroy(&zmgr->zonetasks);

	isc_ratelimiter_destroy(&zmgr->rl);

	isc_rwlock_destroy(&zmgr->conflock);
	isc_rwlock_destroy(&zmgr->rwlock);
	mctx = zmgr->mctx;
	isc_mem_put(zmgr->mctx, zmgr, sizeof *zmgr);
	isc_mem_detach(&mctx);
}

void
dns_zonemgr_lockconf(dns_zonemgr_t *zmgr, isc_rwlocktype_t type) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	RWLOCK(&zmgr->conflock, type);
}

void
dns_zonemgr_unlockconf(dns_zonemgr_t *zmgr, isc_rwlocktype_t type) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	RWUNLOCK(&zmgr->conflock, type);
}

void
dns_zonemgr_settransfersin(dns_zonemgr_t *zmgr, int value) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	zmgr->transfersin = value;
}

int
dns_zonemgr_getttransfersin(dns_zonemgr_t *zmgr) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	return (zmgr->transfersin);
}

void
dns_zonemgr_settransfersperns(dns_zonemgr_t *zmgr, int value) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	zmgr->transfersperns = value;
}

int
dns_zonemgr_getttransfersperns(dns_zonemgr_t *zmgr) {
	REQUIRE(DNS_ZONEMGR_VALID(zmgr));

	return (zmgr->transfersperns);
}

/*
 * Try to start a new incoming zone transfer to fill a quota
 * slot that was just vacated.
 *
 * Requires:
 *	The zone manager is locked by the caller.
 */
static void
zmgr_resume_xfrs(dns_zonemgr_t *zmgr) {
	static char me[] = "zmgr_resume_xfrs";
	dns_zone_t *zone;
	
	for (zone = ISC_LIST_HEAD(zmgr->waiting_for_xfrin);
	     zone != NULL;
	     zone = ISC_LIST_NEXT(zone, statelink))
	{
		isc_result_t result;
		result = zmgr_start_xfrin_ifquota(zmgr, zone);
		if (result == ISC_R_SUCCESS) {
			/*
			 * We successfully filled the slot.  We're done.
			 */
			break;
		} else if (result == ISC_R_QUOTA) {
			/*
			 * Not enough quota.  This is probably the per-server 
			 * quota, because we only get called when a unit of 
			 * global quota has just been freed.  Try the next 
			 * zone, it may succeed if it uses another master.
			 */
			continue;
		} else {
			zone_log(zone, me, ISC_LOG_DEBUG(3), 
				 "starting zone transfer: %s",
				 isc_result_totext(result));
			break;
		}
	}
}
		
/*
 * Try to start an incoming zone transfer for 'zone', quota permitting.
 *
 * Requires:
 *	The zone manager is locked by the caller.
 *
 * Returns:
 *	ISC_R_SUCCESS	There was enough quota and we attempted to
 *			start a transfer.  zone_xfrdone() has been or will
 *			be called.
 *	ISC_R_QUOTA	Not enough quota.
 *	Others		Failure.
 */
static isc_result_t
zmgr_start_xfrin_ifquota(dns_zonemgr_t *zmgr, dns_zone_t *zone) {
	dns_peer_t *peer = NULL;
	isc_netaddr_t masterip;
	int nxfrsin, nxfrsperns;
	dns_zone_t *x;
	int maxtransfersin, maxtransfersperns;
	isc_event_t *e;

	/*
	 * Find any configured information about the server we'd
	 * like to transfer this zone from.
	 */
	isc_netaddr_fromsockaddr(&masterip, &zone->masteraddr);
	(void)dns_peerlist_peerbyaddr(zone->view->peers,
				      &masterip, &peer);

	/*
	 * Determine the total maximum number of simultaneous
	 * transfers allowed, and the maximum for this specific
	 * master.
	 */
	maxtransfersin = zmgr->transfersin;
	maxtransfersperns = zmgr->transfersperns;
	if (peer != NULL)
		(void)dns_peer_gettransfers(peer, &maxtransfersperns);

	/* 
	 * Count the total number of transfers that are in progress,
	 * and the number of transfers in progress from this master.
	 * We linearly scan a list of all transfers; if this turns
	 * out to be too slow, we could hash on the master address.
	 */
	nxfrsin = nxfrsperns = 0;
	for (x = ISC_LIST_HEAD(zmgr->xfrin_in_progress);
	     x != NULL;
	     x = ISC_LIST_NEXT(x, statelink))
	{
		isc_netaddr_t xip;
		isc_netaddr_fromsockaddr(&xip, &x->masteraddr);
		nxfrsin++;
		if (isc_netaddr_equal(&xip, &masterip))
			nxfrsperns++;
	}

	/* Enforce quota. */
	if (nxfrsin >= maxtransfersin)
		return (ISC_R_QUOTA);

	if (nxfrsperns >= maxtransfersperns)
		return (ISC_R_QUOTA);

	/*
	 * We have sufficient quota.  Move the zone to the "xfrin_in_progress"
	 * list and send it an event to let it start the actual transfer in the
	 * context of its own task.
	 */
	e = isc_event_allocate(zmgr->mctx, zmgr,
			       DNS_EVENT_ZONESTARTXFRIN,
			       got_transfer_quota, zone,
			       sizeof(isc_event_t));
	if (e == NULL)
		return (ISC_R_NOMEMORY);

	LOCK(&zone->lock);
	INSIST(zone->statelist == &zmgr->waiting_for_xfrin);
	ISC_LIST_UNLINK(zmgr->waiting_for_xfrin, zone, statelink);
	ISC_LIST_APPEND(zmgr->xfrin_in_progress, zone, statelink);
	zone->statelist = &zmgr->xfrin_in_progress;
	/*
	 * Make sure the zone does not go away before it has processed
	 * the event; in effect, the event is attached to the zone.
	 *
	 * XXXAG This should be done as soon as the zone goes on the
	 * queue, using irefs.
	 */
	zone->erefs++;
	isc_task_send(zone->task, &e);
	UNLOCK(&zone->lock);
	
	return (ISC_R_SUCCESS);
}

#if 0
/* Hook for ondestroy notifcation from a database. */

static void
dns_zonemgr_dbdestroyed(isc_task_t *task, isc_event_t *event) {
	dns_db_t *db = event->sender;
	UNUSED(task);

	isc_event_free(&event);
	
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
		      DNS_LOGMODULE_ZONE, ISC_LOG_INFO,
		      "database (%p) destroyed", (void*) db);
}
#endif
