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

/* $Id: zone.c,v 1.98 2000/04/19 22:21:22 marka Exp $ */

#include <config.h>

#include <string.h>
#include <stdarg.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/magic.h>
#include <isc/mktemplate.h>
#include <isc/print.h>
#include <isc/ratelimiter.h>
#include <isc/rwlock.h>
#include <isc/quota.h>
#include <isc/serial.h>
#include <isc/taskpool.h>
#include <isc/timer.h>
#include <isc/ufile.h>
#include <isc/util.h>

#include <dns/acl.h>
#include <dns/adb.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/dispatch.h>
#include <dns/events.h>
#include <dns/journal.h>
#include <dns/log.h>
#include <dns/master.h>
#include <dns/masterdump.h>
#include <dns/message.h>
#include <dns/rcode.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatastruct.h>
#include <dns/resolver.h>
#include <dns/request.h>
#include <dns/ssu.h>
#include <dns/xfrin.h>
#include <dns/zone.h>
#include <dns/zt.h>

/* XXX remove once config changes are in place */
#define dns_zone_uptodate(x) zone_log(x, me, ISC_LOG_INFO, "dns_zone_uptodate")
#define referral(x) ISC_FALSE


#define ZONE_MAGIC 0x5a4f4e45U		/* ZONE */
#define CHECKSERVERS_MAGIC 0x43484346U	/* CHCF */
#define NOTIFY_MAGIC 0x4e746679U	/* Ntfy */

#define DNS_ZONE_VALID(zone) \
	ISC_MAGIC_VALID(zone, ZONE_MAGIC)
#ifdef notyet
#define DNS_CHECKSERVERS_VALID(server) \
	ISC_MAGIC_VALID(zone, CHECKSERVERS_MAGIC)
#endif
#define DNS_NOTIFY_VALID(notify) \
	ISC_MAGIC_VALID(notify, NOTIFY_MAGIC)

#define DEFAULT_REFRESH	900	/*XXX*/
#define DEFAULT_RETRY 300	/*XXX*/
#define MAX_XFER_TIME (2*3600)	/* Documented default is 2 hours. */

#define RANGE(a, b, c) (((a) < (b)) ? (b) : ((a) < (c) ? (a) : (c)))

#define DNS_MIN_REFRESH 2
#define DNS_MAX_REFRESH 2419200		/* 4 weeks */
#define DNS_MIN_RETRY	1
#define DNS_MAX_RETRY	1209600		/* 2 weeks */
#define DNS_MAX_EXPIRE	14515200	/* 24 weeks */
#define DNS_DEFAULT_IDLEIN 3600		/* 1 hour */
#define DNS_DEFAULT_IDLEOUT 3600	/* 1 hour */

typedef struct dns_zone_checkservers dns_zone_checkservers_t;
typedef struct notify notify_t;


#ifdef notyet
typedef enum {
	get_a6, get_aaaa, get_a, get_ns, get_soa
} dns_zone_state_t;

struct dns_zone_checkservers {
	isc_uint32_t			magic;
	isc_boolean_t			name_known;
	dns_name_t			server;
	isc_sockaddr_t			address;
	dns_zone_state_t		state;
	dns_zone_t			*zone;
	dns_resolver_t			*res;
	isc_mem_t			*mctx;
	dns_fetch_t			*request;
	ISC_LINK(struct dns_zone_checkservers) link;
};
#endif

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
	isc_boolean_t		shuttingdown;
	dns_name_t		origin;
	char 			*dbname;
	char			*journal;
	isc_int32_t		journalsize;
	dns_rdataclass_t	rdclass;
	dns_zonetype_t		type;
	unsigned int		flags;
	unsigned int		options;
	char *			db_type;
	unsigned int		db_argc;
	char **			db_argv;
	isc_stdtime_t		expiretime;
	isc_stdtime_t		refreshtime;
	isc_stdtime_t		dumptime;
	isc_stdtime_t		servertime;
	isc_stdtime_t		parenttime;
	isc_stdtime_t		childtime;
	isc_uint32_t		serial;
	isc_uint32_t		refresh;
	isc_uint32_t		retry;
	isc_uint32_t		expire;
	isc_uint32_t		minimum;
	isc_sockaddr_t *	masters;
	unsigned int		masterscnt;
	in_port_t		masterport;
	unsigned int		curmaster;
	isc_sockaddr_t		masteraddr;
	isc_sockaddr_t *	notify;
	unsigned int		notifycnt;
	isc_sockaddr_t		notifyfrom;
	isc_task_t *		task;
	isc_sockaddr_t	 	xfrsource4;
	isc_sockaddr_t	 	xfrsource6;
	dns_xfrin_ctx_t *	xfr;
	/* Access Control Lists */
	dns_acl_t		*update_acl;
	dns_acl_t		*query_acl;
	dns_acl_t		*xfr_acl;
	dns_severity_t		check_names;
	ISC_LIST(dns_zone_checkservers_t)	checkservers;
	ISC_LIST(notify_t)	notifies;
	dns_requestmgr_t	*requestmgr;
	dns_request_t		*request;
	dns_resolver_t		*res;
	dns_adb_t		*adb;
	isc_socketmgr_t		*socketmgr;
	isc_ratelimiter_t	*rl;
	isc_uint32_t		maxxfrin;
	isc_uint32_t		maxxfrout;
	isc_uint32_t		idlein;
	isc_uint32_t		idleout;
	isc_boolean_t		diff_on_reload;
	isc_event_t		ctlevent;
	dns_ssutable_t		*ssutable;
	dns_view_t		*view;
};

#define DNS_ZONE_FLAG(z,f) (((z)->flags & (f)) != 0)
	/* XXX MPA these may need to go back into zone.h */
#define DNS_ZONE_F_REFRESH      0x00000001U     /* refresh check in progress */
#define DNS_ZONE_F_NEEDDUMP     0x00000002U     /* zone need consolidation */
#define DNS_ZONE_F_SERVERS      0x00000004U     /* servers check in progress */
#define DNS_ZONE_F_PARENTS      0x00000008U     /* parents check in progress */
#define DNS_ZONE_F_CHILDREN     0x00000010U     /* child check in progress */
#define DNS_ZONE_F_LOADED       0x00000020U     /* database has loaded */
#define DNS_ZONE_F_EXITING      0x00000040U     /* zone is being destroyed */
#define DNS_ZONE_F_EXPIRED      0x00000080U     /* zone has expired */
#define DNS_ZONE_F_NEEDREFRESH	0x00000100U	/* refresh check needed */
#define DNS_ZONE_F_UPTODATE	0x00000200U	/* zone contents are 
						 * uptodate */
#define DNS_ZONE_F_NEEDNOTIFY	0x00000400U	/* need to send out notify
						 * messages */

#define DNS_ZONE_OPTION(z,o) (((z)->options & (o)) != 0)

struct dns_zonemgr {
	isc_mem_t *		mctx;
	isc_taskmgr_t *		taskmgr;
	isc_timermgr_t *	timermgr;
	isc_socketmgr_t *	socketmgr;
	isc_taskpool_t *	zonetasks;
	isc_task_t *		task;
	isc_rwlock_t		rwlock;
	isc_rwlock_t		conflock;
	/* Locked by rwlock. */
	ISC_LIST(dns_zone_t)	zones;
	/* Locked by conflock. */
	int			transfersin;
	int			transfersperns;
	/* Contains its own lock. */
	dns_xfrinlist_t		transferlist;
};

/*
 * Hold notify state.
 */
struct notify {
	isc_mem_t		*mctx;
	isc_int32_t		magic;
	dns_zone_t		*zone;
	dns_adbfind_t		*find;
	dns_request_t		*request;
	dns_name_t		ns;
	ISC_LINK(notify_t)	link;
};

static isc_result_t zone_settimer(dns_zone_t *, isc_stdtime_t);
static void cancel_refresh(dns_zone_t *);

static void zone_log(dns_zone_t *zone, const char *, int, const char *msg,
		     ...);
static void dns_zone_transfer_in(dns_zone_t *zone);
static isc_result_t dns_zone_tostr(dns_zone_t *zone, isc_mem_t *mctx,
				   char **s);
static void unload(dns_zone_t *zone);
static void expire(dns_zone_t *zone);
static isc_result_t replacedb(dns_zone_t *zone, dns_db_t *db,
			      isc_boolean_t dump);
static isc_result_t default_journal(dns_zone_t *zone);
static void releasezone(dns_zonemgr_t *zmgr, dns_zone_t *zone);
static void xfrdone(dns_zone_t *zone, isc_result_t result);
static void zone_shutdown(isc_task_t *, isc_event_t *);

#if 0
/* ondestroy example */
static void dns_zonemgr_dbdestroyed(isc_task_t *task, isc_event_t *event);
#endif

static void refresh_callback(isc_task_t *, isc_event_t *);
static void soa_query(dns_zone_t *, isc_taskaction_t);
static int message_count(dns_message_t *msg, dns_section_t section,
			 dns_rdatatype_t type);
#ifdef notyet
static void checkservers_callback(isc_task_t *task, isc_event_t *event);
static void add_address_tocheck(dns_message_t *msg,
				dns_zone_checkservers_t *checkservers,
				dns_rdatatype_t type);
static void record_serial(void);
#endif

static void notify_find_address(notify_t *notify);
static void notify_send(notify_t *notify);
static isc_result_t notify_createmessage(dns_zone_t *zone,
					 dns_message_t **messagep);
static void notify_done(isc_task_t *task, isc_event_t *event);

#define PRINT_ZONE_REF(zone) \
	do { \
		char *s = NULL; \
		isc_result_t r; \
		r = dns_zone_tostr(zone, zone->mctx, &s); \
		if (r == ISC_R_SUCCESS) { \
			printf("%p: %s: erefs = %d\n", zone, s, \
			       zone->erefs); \
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
	isc_sockaddr_t sockaddr_any4;
	isc_sockaddr_t sockaddr_any6;
	struct in_addr in4addr_any;
	
	REQUIRE(zonep != NULL && *zonep == NULL);
	REQUIRE(mctx != NULL);

	in4addr_any.s_addr = htonl(INADDR_ANY);
	isc_sockaddr_fromin(&sockaddr_any4, &in4addr_any, 0);
	isc_sockaddr_fromin6(&sockaddr_any6, &in6addr_any, 0);

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
	zone->shuttingdown = ISC_FALSE;
	dns_name_init(&zone->origin, NULL);
	zone->dbname = NULL;
	zone->journalsize = -1;
	zone->journal = NULL;
	zone->rdclass = dns_rdataclass_none;
	zone->type = dns_zone_none;
	zone->flags = 0;
	zone->options = DNS_ZONE_O_NOTIFY;
	zone->db_type = NULL;
	zone->db_argc = 0;
	zone->db_argv = NULL;
	zone->expiretime = 0;
	zone->refreshtime = 0;
	zone->dumptime = 0;
	zone->servertime = 0;
	zone->parenttime = 0;
	zone->childtime = 0;
	zone->serial = 0;
	zone->refresh = DEFAULT_REFRESH;
	zone->retry = DEFAULT_RETRY;
	zone->expire = 0;
	zone->minimum = 0;
	zone->masters = NULL;
	zone->masterscnt = 0;
	zone->masterport = 0;
	zone->curmaster = 0;
	zone->notify = NULL;
	zone->notifycnt = 0;
	zone->task = NULL;
	zone->update_acl = NULL;
	zone->query_acl = NULL;
	zone->xfr_acl = NULL;
	zone->check_names = dns_severity_ignore;
	zone->requestmgr = NULL;
	zone->request = NULL;
	zone->res = NULL;
	zone->adb = NULL;
	zone->socketmgr = NULL;
	zone->timer = NULL;
	zone->rl = NULL;
	zone->idlein = DNS_DEFAULT_IDLEIN;
	zone->idleout = DNS_DEFAULT_IDLEOUT;
	ISC_LIST_INIT(zone->checkservers);
	ISC_LIST_INIT(zone->notifies);
	zone->xfrsource4 = sockaddr_any4;
	zone->xfrsource6 = sockaddr_any6;
	zone->xfr = NULL;
	zone->maxxfrin = MAX_XFER_TIME;
	zone->maxxfrout = MAX_XFER_TIME;
	zone->diff_on_reload = ISC_FALSE;
	zone->ssutable = NULL;
	zone->view = NULL;
	zone->magic = ZONE_MAGIC;
	ISC_EVENT_INIT(&zone->ctlevent, sizeof(zone->ctlevent), 0, NULL,
		       DNS_EVENT_ZONECONTROL, zone_shutdown, zone, zone,
		       NULL, NULL);
	*zonep = zone;
	return (ISC_R_SUCCESS);
}

static void
zone_free(dns_zone_t *zone) {
	isc_mem_t *mctx = NULL;

	REQUIRE(DNS_ZONE_VALID(zone));
	LOCK(&zone->lock);
	REQUIRE(zone->erefs == 0);
	zone->flags |= DNS_ZONE_F_EXITING;
	UNLOCK(&zone->lock);


	/* managed objects */
	/* order is important */
	if (DNS_ZONE_FLAG(zone, DNS_ZONE_F_REFRESH))
		cancel_refresh(zone);
	if (zone->timer != NULL)
		isc_timer_detach(&zone->timer);
	if (zone->res != NULL)
		dns_resolver_detach(&zone->res);
	if (zone->adb != NULL)
		dns_adb_detach(&zone->adb);
	if (zone->request != NULL) {
		dns_request_cancel(zone->request);	/* XXXMPA */
		dns_request_destroy(&zone->request);	/* XXXMPA */
	}
	if (zone->requestmgr != NULL)
		dns_requestmgr_detach(&zone->requestmgr);
	if (zone->rl != NULL)
		isc_ratelimiter_destroy(&zone->rl);
	if (zone->task != NULL)
		isc_task_detach(&zone->task);
	if (zone->socketmgr != NULL)
		isc_socketmgr_destroy(&zone->socketmgr);
	if (zone->zmgr)
		dns_zonemgr_releasezone(zone->zmgr, zone);

	/* unmanaged objects */
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
	dns_zone_clearmasters(zone);
	zone->masterport = 0;
	dns_zone_clearnotify(zone);
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

	/* test and set */
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

	/* test and set */
	LOCK(&zone->lock);
	REQUIRE(zone->type == dns_zone_none || zone->type == type);
	zone->type = type;
	UNLOCK(&zone->lock);
}

isc_result_t
dns_zone_setdbtype(dns_zone_t *zone, char *db_type) {
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

void dns_zone_setview(dns_zone_t *zone, dns_view_t *view) {
	zone->view = view;
}
     

dns_view_t *dns_zone_getview(dns_zone_t *zone) {
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

void
dns_zone_validate(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(dns_name_countlabels(&zone->origin) != 0);
	REQUIRE(zone->type != dns_zone_none);

	switch (zone->rdclass) {
	case dns_zone_master:
	case dns_zone_slave:
	case dns_zone_stub:
	case dns_zone_hint:
		REQUIRE(zone->dbname != NULL);
		/*FALLTHROUGH*/
	case dns_zone_forward:
		REQUIRE(zone->rdclass != dns_rdataclass_none);
		break;
	case dns_zone_cache:
		REQUIRE(zone->rdclass == dns_rdataclass_none);
		REQUIRE(zone->dbname == NULL);
		break;
	}

	REQUIRE(zone->db_type != NULL);
}

isc_result_t
dns_zone_load(dns_zone_t *zone) {
	const char me[] = "dns_zone_load";
	int soacount = 0;
	int nscount = 0;
	isc_result_t result;
	dns_dbnode_t *node = NULL;
	dns_dbversion_t *version = NULL;
	dns_rdataset_t rdataset;
	isc_boolean_t cache = ISC_FALSE;
	dns_rdata_soa_t soa;
	dns_rdata_t rdata;
	isc_stdtime_t now;
	dns_db_t *db = NULL;

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	isc_stdtime_get(&now);

	switch (zone->type) {
	case dns_zone_forward:
	case dns_zone_none:
		result = ISC_R_SUCCESS;
		goto cleanup;
	case dns_zone_master:
	case dns_zone_slave:
	case dns_zone_stub:
	case dns_zone_hint:
		cache = ISC_FALSE;
		break;
	case dns_zone_cache:
		cache = ISC_TRUE;
		break;
	default:
		INSIST("bad zone type" == NULL);
	}

	REQUIRE(zone->dbname != NULL);

	result = dns_db_create(zone->mctx, zone->db_type,
			       &zone->origin,
			       cache, zone->rdclass,
			       zone->db_argc, zone->db_argv, &db);

	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = dns_db_load(db, zone->dbname);

	/*
	 * Initiate zone transfer?  We may need a error code that
	 * indicates that the "permanent" form does not exist.
	 * XXX better error feedback to log.
	 */
	if (result != ISC_R_SUCCESS) {
		if (zone->type == dns_zone_slave) {
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

	/*
	 * Apply update log, if any.
	 */
	if (zone->journal != NULL) {
		result = dns_journal_rollforward(zone->mctx, db, zone->journal);
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
			zone->flags |= DNS_ZONE_F_NEEDDUMP;
	}

	/*
	 * Obtain ns and soa counts for top of zone.
	 */
	nscount = 0;
	soacount = 0;
	dns_db_currentversion(db, &version);
	result = dns_db_findnode(db, &zone->origin, ISC_FALSE, &node);

	if (result == ISC_R_SUCCESS) {
		dns_rdataset_init(&rdataset);
		result = dns_db_findrdataset(db, node, version,
					     dns_rdatatype_ns,
					     dns_rdatatype_none, 0, &rdataset,
					     NULL);
		if (result == ISC_R_SUCCESS) {
			result = dns_rdataset_first(&rdataset);
			while (result == ISC_R_SUCCESS) {
				nscount++;
				result = dns_rdataset_next(&rdataset);
			}
			dns_rdataset_disassociate(&rdataset);
		}
		result = dns_db_findrdataset(db, node, version,
					     dns_rdatatype_soa,
					     dns_rdatatype_none, 0, &rdataset,
					     NULL);

		if (result == ISC_R_SUCCESS) {
			result = dns_rdataset_first(&rdataset);
			while (result == ISC_R_SUCCESS) {
				dns_rdataset_current(&rdataset, &rdata);
				if (soacount == 0)
					dns_rdata_tostruct(&rdata, &soa,
							   zone->mctx);
				soacount++;
				result = dns_rdataset_next(&rdataset);
			}
			dns_rdataset_disassociate(&rdataset);
		}
		dns_rdataset_invalidate(&rdataset);
	}
	dns_db_detachnode(db, &node);
	dns_db_closeversion(db, &version, ISC_FALSE);

	/*
	 * Master / Slave / Stub zones require both NS and SOA records at
	 * the top of the zone.
	 * Hint zones only require NS records.
	 * Cache zones have no reqirements.
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
			if (!isc_serial_ge(soa.serial, zone->serial)) {
				zone_log(zone, me, ISC_LOG_ERROR,
					"zone serial has gone backwards");
			}
		}
		zone->serial = soa.serial;
		zone->refresh = RANGE(soa.refresh, DNS_MIN_REFRESH,
				      DNS_MAX_REFRESH);
		zone->retry = RANGE(soa.retry, DNS_MIN_REFRESH,
				    DNS_MAX_REFRESH);
		zone->expire = RANGE(soa.expire, zone->refresh + zone->retry,
				     DNS_MAX_EXPIRE);
		zone->minimum = soa.minimum;
		if (zone->type == dns_zone_slave ||
		    zone->type == dns_zone_stub) {
			/* XXX need database modification time */
			zone->expiretime = now /*XXX*/ + zone->expire;
			zone->refreshtime = now /*XXX*/;
		}
		break;
	case dns_zone_hint:
		if (nscount == 0) {
			zone_log(zone, me, ISC_LOG_ERROR, "no NS records");
			result = DNS_R_BADZONE;
			goto cleanup;
		}
		break;
	case dns_zone_cache:
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
		result = replacedb(zone, db, ISC_FALSE);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
	} else {
		dns_db_attach(db, &zone->db);
		zone->flags |= DNS_ZONE_F_LOADED|DNS_ZONE_F_NEEDNOTIFY;
	}
	result = ISC_R_SUCCESS; 

 cleanup:
	UNLOCK(&zone->lock);
	if (soacount != 0)
		dns_rdata_freestruct(&soa);
	if (db != NULL)
		dns_db_detach(&db);
	return (result);
}

#ifdef notyet
void
dns_zone_checkservers(dns_zone_t *zone) {
	dns_name_t *zonename;
	unsigned int i;
	dns_zone_checkservers_t *checkservers;
	dns_rdataset_t rdataset;
	dns_rdata_t rdata;
	dns_dbnode_t *node = NULL;
	dns_dbversion_t *version = NULL;
	isc_result_t result;
	dns_rdata_ns_t ns;

	REQUIRE(DNS_ZONE_VALID(zone));
	/* XXX MPA */

	/*
	 * get NS list from database, add in notify also list
	 */
	zonename = &zone->origin;
	dns_db_currentversion(zone->db, &version);
	result = dns_db_findnode(zone->db, zonename, ISC_FALSE, &node);

	if (result == ISC_R_SUCCESS) {
		dns_rdataset_init(&rdataset);
		result = dns_db_findrdataset(zone->db, node, version,
					     dns_rdatatype_ns,
					     dns_rdatatype_none, 0, &rdataset,
					     NULL);
		if (result == ISC_R_SUCCESS) {
			result = dns_rdataset_first(&rdataset);
			while (result == ISC_R_SUCCESS) {
				dns_rdataset_current(&rdataset, &rdata);
				result = dns_rdata_tostruct(&rdata, &ns, zone->mctx);
				if (result != ISC_R_SUCCESS)
					continue;
				checkservers = isc_mem_get(zone->mctx,
							  sizeof *checkservers);
				if (checkservers == NULL)
					break;
				dns_name_init(&checkservers->server, NULL);
				dns_name_dup(&ns.name, zone->mctx,
					     &checkservers->server);
				checkservers->name_known = ISC_TRUE;
				checkservers->state = get_a; /* XXXMPA */
				dns_zone_attach(zone, &checkservers->zone);
				checkservers->mctx = NULL;
				isc_mem_attach(zone->mctx, &checkservers->mctx);
				dns_resolver_attach(zone->res, &checkservers->res);
				checkservers->request = NULL;
				ISC_LINK_INIT(checkservers, link);
				checkservers->magic = CHECKSERVERS_MAGIC;

				/* XXX lookup A/AAAA/A6 records */
				result = dns_rdataset_next(&rdataset);
			}
		}
		dns_rdataset_disassociate(&rdataset);
		dns_rdataset_invalidate(&rdataset);
	}
	dns_db_detachnode(zone->db, &node);
	dns_db_closeversion(zone->db, &version, ISC_FALSE);

	/*
	 * Foreach NS in NS list perform a non-recursive query to obtain
	 * NS list for zone (remove self from list).
	 *
	 * callback to check:
	 * If NXDOMAIN -> log error.
	 * If NODATA -> log error.
	 * If referral -> log error.
	 * If non-auth -> log error.
	 * Compare NS list returned with server list if not identical 
	 * log error if current list is at least 3 x refresh old.
	 * Compare glue A/AAAA/A6 records.
	 */

	/*
	 * Foreach NS in NS list perform a non-recursive query to obtain
	 * SOA record for zone (remove self from list).
	 *
	 * callback to check:
	 * If NXDOMAIN -> log error.
	 * If NODATA -> log error.
	 * If referral -> log error.
	 * If no-auth -> log error.
	 * Compare SOA serial with ixfr list and if older that 3x refresh
	 * log error.
	 */
	LOCK(&zone->lock);
	for (i = 0 ; i < zone->notifycnt; i++) {
		checkservers = isc_mem_get(zone->mctx, sizeof *checkservers);
		if (checkservers == NULL)
			break;
		dns_name_init(&checkservers->server, NULL);
		checkservers->name_known = ISC_FALSE;
		checkservers->state = get_ns;
		checkservers->address = zone->notify[i];
		dns_zone_attach(zone, &checkservers->zone);
		checkservers->mctx = NULL;
		isc_mem_attach(zone->mctx, &checkservers->mctx);
		dns_resolver_attach(zone->res, &checkservers->res);
		checkservers->request = NULL;
		ISC_LINK_INIT(checkservers, link);
		checkservers->magic = CHECKSERVERS_MAGIC;
		ISC_LIST_APPEND(zone->checkservers, checkservers, link);
		dns_resolver_createfetch(zone->res, zonename, dns_rdatatype_ns,
				         NULL, NULL, NULL,
					 DNS_FETCHOPT_UNSHARED,
					 zone->task, checkservers_callback, 
					 checkservers, &checkservers->request);
	}
	UNLOCK(&zone->lock);
}
#endif

#ifdef notyet
static void
checkservers_callback(isc_task_t *task, isc_event_t *event) {
	const char me[] = "checkservers_callback";
	dns_requestevent_t *devent = (dns_requestdoneevent_t *)event;
	dns_zone_checkservers_t *checkservers = event->ev_arg;
	dns_zone_state_t state;
	dns_zone_t *zone;
	dns_name_t *name;
	isc_mem_t *mctx;
	isc_sockaddr_t *address;
	dns_resolver_t *res;
	dns_message_t *msg; 

	REQUIRE(DNS_CHECKSERVERS_VALID(checkservers));

	state = checkservers->state;
	zone = checkservers->zone;
	name = &checkservers->server;
	address = &checkservers->address;
	mctx =checkservers->mctx;
	res = checkservers->res;

	UNUSED(task);

	if (devent->result != ISC_R_SUCCESS) {
		/* timeout */
		switch (state) {
		case get_a6:
		case get_aaaa:
		case get_a:
			zone_log(zone, me, ISC_LOG_INFO,
			         "unable to obtain address for (%s)");
			break;
		case get_ns:
		case get_soa:
			zone_log(zone, me, ISC_LOG_INFO,
				 "unable to obtain %s RRset from %s"
				);
		}
		goto cleanup;
	}

	msg = NULL;
	/* dns_resolver_getanswer(event, &msg); */


	switch (state) {
	case get_a6:
		add_address_tocheck(msg, checkservers, dns_rdatatype_a6);
		dns_resolver_createfetch(res, name, dns_rdatatype_aaaa,
				         NULL, NULL, NULL, 0, zone->task,
					 checkservers_callback, 
					 checkservers, &checkservers->request);
		checkservers->state = get_aaaa;
		break;
	case get_aaaa:
		add_address_tocheck(msg, checkservers, dns_rdatatype_a6);
		dns_resolver_createfetch(res, name, dns_rdatatype_a,
				         NULL, NULL, NULL, 0, zone->task,
					 checkservers_callback, 
					 checkservers, &checkservers->request);
		checkservers->state = get_a;
		break;
	case get_a:
		add_address_tocheck(msg, checkservers, dns_rdatatype_a);
		/* make NS query to address */
		dns_resolver_createfetch(res, name, dns_rdatatype_ns,
				         NULL, NULL, NULL,
					 DNS_FETCHOPT_UNSHARED, 
					 zone->task, checkservers_callback, 
					 checkservers, &checkservers->request);
		checkservers->state = get_ns;
		break;
	case get_ns:
	case get_soa:
		if (msg->rcode != dns_rcode_noerror) {
			char rcode[128];
			isc_buffer_t rb;

			isc_buffer_init(&rb, rcode, sizeof rcode,
					ISC_BUFFERTYPE_TEXT);
			dns_rcode_totext(msg->rcode, &rb);
			zone_log(zone, me, ISC_LOG_INFO,
				 "server %s (%s) unexpected rcode = %.*s",
				 rb.used, rcode);
			break;
		}
		if (msg->counts[DNS_SECTION_ANSWER] == 0) {
			if (referral(msg))
				zone_log(zone, me, ISC_LOG_INFO,
					"server %s (%s) referral response");
			else
				zone_log(zone, me, ISC_LOG_INFO,
				   "server %s (%s) type = %s NODATA response");
		}

		if ((msg->flags & DNS_MESSAGEFLAG_AA) == 0) {
			zone_log(zone, me, ISC_LOG_INFO,
				"server %s (%s) not authorative");
		}
		if (state == get_ns) {
			/* compare NS RR sets */
			/* make soa query to address */
			dns_resolver_createfetch(res, name, dns_rdatatype_soa,
						 NULL, NULL, NULL,
						 DNS_FETCHOPT_UNSHARED, 
						 zone->task,
						 checkservers_callback, 
						 checkservers,
						 &checkservers->request);
			checkservers->state = get_soa;
			break;
		} else {
			/* compare SOA RR sets */

			goto cleanup;
		}

		break;
	default:
		UNEXPECTED_ERROR(__FILE__, __LINE__, "unexpected state");
		break;
	}
	isc_event_free(&event);
	return;

 cleanup:
	isc_event_free(&event);
	ISC_LIST_UNLINK(zone->checkservers, checkservers, link);
	checkservers->magic = 0;
	dns_zone_detach(&checkservers->zone);
	isc_mem_put(mctx, checkservers, sizeof *checkservers);
	isc_mem_detach(&mctx);
}
#endif

#if 0
static void
cmp_soa(dns_message_t *msg, dns_zone_t *zone, char *server) {
	dns_rdata_soa_t msgsoa, zonesoa;
	isc_result_t result;
	dns_rdataset_t *rdataset = NULL;
	dns_rdataset_t zonerdataset;
	dns_rdata_t rdata;

	dns_rdata_init(&rdata);

	/*
	 * extract SOA from message
	 */
	result = dns_message_findname(msg, DNS_SECTION_ANSWER,
				      &zone->origin,
				      dns_rdatatype_soa,
				      dns_rdatatype_none, NULL, &rdataset);
	if (result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_INFO,
			 "Unable to extract SOA from answer: %s", server);
		return;
	}
	result = dns_rdataset_first(rdataset); 
	if (ISC_R_SUCCESS != result)
		return;
	dns_rdataset_current(rdataset, &rdata);
	result = dns_rdata_tostruct(&rdata, &msgsoa, zone->mctx);
	if (ISC_R_SUCCESS != result)
		return;
	result = dns_rdataset_next(rdataset);
	if (ISC_R_NOMORE != result) {
		zone_log(zone, me, ISC_LOG_INFO,
		         "More that one SOA record returned: %s", server);
		goto cleanup_msgsoa;
	}

	/*
	 * Get SOA record for zone.
	 */

	dns_rdataset_init(&zonerdataset);
	LOCK(&zone->lock);
	result = dns_db_find(zone->db, &zone->origin,
			     NULL, dns_rdatatype_soa, dns_rdatatype_none,
			     0, 0, NULL, NULL, &zonerdataset);
	UNLOCK(&zone->lock);
	if (result != ISC_R_SUCCESS) {
		/* XXXMPA */
		goto cleanup_msgsoa;
	}

	result = dns_rdataset_first(&zonerdataset); 
	if (ISC_R_SUCCESS != result)
		return;
	dns_rdataset_current(&zonerdataset, &rdata);
	result = dns_rdata_tostruct(&rdata, &msgsoa, zone->mctx);
	if (ISC_R_SUCCESS != result)
		return;
	result = dns_rdataset_next(&zonerdataset);
	if (ISC_R_NOMORE != result) {
		zone_log(zone, me, ISC_LOG_INFO, "More than one SOA in zone");
		goto cleanup_msgsoa;
	}
	dns_rdataset_disassociate(&zonerdataset);

	/*
	 * Check SOA contents.  If serials do not match check to see
	 * if the slave is ahead of us (i.e. we have reset the serial
	 * number).
	 *
	 * If the serials do match then check the other values for
	 * consistancy.
	 */
	if (msgsoa.serial != zonesoa.serial) {
		if (!isc_serial_lt(msgsoa.serial, zonesoa.serial)) {
			zone_log(zone, me, ISC_LOG_INFO,
		   "slave serial not less than or equal to zone serial: %s",
					   server);
			goto cleanup_zonesoa;
		}
		record_serial();
		goto cleanup_zonesoa;
	}

	if (msgsoa.refresh != zonesoa.refresh ||
	    msgsoa.retry != zonesoa.retry ||
	    msgsoa.expire != zonesoa.expire ||
	    msgsoa.minimum != zonesoa.minimum ||
	    dns_name_compare(&msgsoa.origin, &zonesoa.origin) != 0 ||
	    dns_name_compare(&msgsoa.mname, &zonesoa.mname) != 0) {

		zone_log(zone, me, ISC_LOG_INFO, "SOA contents differ: %s",
			 server);
	}
 cleanup_zonesoa:
	dns_rdata_freestruct(&zonesoa);
 cleanup_msgsoa:
	dns_rdata_freestruct(&msgsoa);
}
#endif

#ifdef notyet
static void
add_address_tocheck(dns_message_t *msg, dns_zone_checkservers_t *checkservers,
		    dns_rdatatype_t type)
{
	dns_rdataset_t *rdataset = NULL;
	isc_result_t result;
	isc_sockaddr_t sockaddr;
	dns_rdata_in_a_t a;
	dns_rdata_in_a6_t a6;
	dns_rdata_t rdata;

	if (msg->rcode != dns_rcode_noerror)
		return;

	if (msg->counts[DNS_SECTION_QUESTION] != 0 ||
	    dns_message_findname(msg, DNS_SECTION_QUESTION,
				 &checkservers->server,
				 type, dns_rdatatype_none,
				 NULL, &rdataset) != ISC_R_SUCCESS)
		return;

	result = dns_rdataset_first(rdataset);
	while (ISC_R_SUCCESS == result) {
		dns_rdataset_current(rdataset, &rdata);
		switch (type) {
		case dns_rdatatype_a:
			result = dns_rdata_tostruct(&rdata, &a,
						    checkservers->mctx);
			isc_sockaddr_fromin(&sockaddr, &a.in_addr, 0);
			dns_rdata_freestruct(&a);
			break;
		case dns_rdatatype_a6:
			result = dns_rdata_tostruct(&rdata, &a6,
						    checkservers->mctx);
			isc_sockaddr_fromin6(&sockaddr, &a6.in6_addr, 0);
			dns_rdata_freestruct(&a6);
			break;
		default:
			INSIST(0);
		}
		result = dns_rdataset_next(rdataset);
	}
}
#endif

void
dns_zone_checkparents(dns_zone_t *zone) {
	/* XXX MPA */

	REQUIRE(DNS_ZONE_VALID(zone));
	/*
	 * Obtain a parent NS list.
	 *	Remove LSL from zone name. Check to see if we are serving
	 *	zone otherwise make non-recursive query for NS set of
	 *	of given name.  Follow referral until NXDOMAIN, NODATA or
	 *	answer is found.  If NXDOMAIN or NODATA remove next LSL
	 *	and repeat.
	 */

	/*
	 * If self in NS list check masked NS list in parent against zone 
	 * ns list.
	 *
	 * Foreach NS on parent NS list make non recursive query for NS set
	 * of current zone (removed self from list if required).
	 *
	 * Check NS list return for agreement with zone's NS list.
	 */
}

void
dns_zone_checkchildren(dns_zone_t *zone) {
	/* XXX MPA */
	REQUIRE(DNS_ZONE_VALID(zone));
	/*
	 * For each child zone obtain NS list from parent zone.
	 * For each NS in list send non-recursive query for child zone's
	 * NS list for zone.
	 *
	 * If NXDOMAIN is returned log error.
	 * If NODATA is return log error.
	 * If referral is return log error.
	 * If non-auth is return log error.
	 * If NS list disagree's with parents NS list log error.
	 */
}

void
dns_zone_checkglue(dns_zone_t *zone) {
	/* XXX MPA */
	REQUIRE(DNS_ZONE_VALID(zone));
	/*
	 * For each glue record in this zone, check with an authorative
	 * server for the zone to ensure that there have not been any
	 * changes.
	 */
}

static void
exit_check(dns_zone_t *zone)
{
	if (zone->irefs == 0 && zone->shuttingdown == ISC_TRUE)
		zone_free(zone);
}

void
dns_zone_attach(dns_zone_t *source, dns_zone_t **target) {
	REQUIRE(DNS_ZONE_VALID(source));
	REQUIRE(target != NULL && *target == NULL);
	LOCK(&source->lock);
	REQUIRE(source->erefs > 0);
	source->erefs++;
	INSIST(source->erefs != 0xffffffffU);
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
			free_now = ISC_TRUE;
		}
	}
	UNLOCK(&zone->lock);
	if (free_now)
		zone_free(zone);
	*zonep = NULL;
}

static void
zone_iattach(dns_zone_t *source, dns_zone_t **target) {
	REQUIRE(DNS_ZONE_VALID(source));
	REQUIRE(target != NULL && *target == NULL);
	source->irefs++;
	INSIST(source->irefs != 0xffffffffU);
	*target = source;
}

void
dns_zone_iattach(dns_zone_t *source, dns_zone_t **target) {
	REQUIRE(DNS_ZONE_VALID(source));

	LOCK(&source->lock);
	zone_iattach(source, target);
	UNLOCK(&source->lock);
}

static void
zone_idetach(dns_zone_t **zonep, isc_boolean_t doexitcheck) {
	dns_zone_t *zone;

	REQUIRE(zonep != NULL && DNS_ZONE_VALID(*zonep));
	zone = *zonep;
	REQUIRE(zone->irefs > 0);
	zone->irefs--;
	*zonep = NULL;
	if (doexitcheck)
		exit_check(zone);
}

void
dns_zone_idetach(dns_zone_t **zonep) {
	dns_zone_t *zone;

	REQUIRE(zonep != NULL && DNS_ZONE_VALID(*zonep));
	zone = *zonep;
	LOCK(&zone->lock);
	zone_idetach(zonep, ISC_FALSE);
	UNLOCK(&zone->lock);
	exit_check(zone);
}

void
dns_zone_print(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	PRINT_ZONE_REF(zone);
}

isc_mem_t *
dns_zone_getmctx(dns_zone_t *zone) {
	return (zone->mctx);
}

dns_zonemgr_t *
dns_zone_getmgr(dns_zone_t *zone) {
	return (zone->zmgr);
}

static isc_result_t
dns_zone_tostr(dns_zone_t *zone, isc_mem_t *mctx, char **s) {
	isc_buffer_t tbuf;
	char outbuf[1024];
	isc_result_t result;

	REQUIRE(s != NULL && *s == NULL);
	REQUIRE(DNS_ZONE_VALID(zone));

	isc_buffer_init(&tbuf, outbuf, sizeof(outbuf) - 1,
			ISC_BUFFERTYPE_TEXT);
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
dns_zone_addnotify(dns_zone_t *zone, isc_sockaddr_t *notify) {
	isc_sockaddr_t *new;
	REQUIRE(DNS_ZONE_VALID(zone));
	
	LOCK(&zone->lock);
	new = isc_mem_get(zone->mctx, (zone->notifycnt + 1) * sizeof *new);
	if (new == NULL)
		goto cleanup;

	new[zone->notifycnt] = *notify;
	if (zone->notifycnt > 0) {
		memcpy(new, zone->notify, zone->notifycnt * sizeof *new);
		isc_mem_put(zone->mctx, zone->notify,
			    zone->notifycnt * sizeof *new);
	}
	zone->notify = new;
	zone->notifycnt++;
	UNLOCK(&zone->lock);
	return (ISC_R_SUCCESS);

 cleanup:
	UNLOCK(&zone->lock);
	return (ISC_R_NOMEMORY);
}

void
dns_zone_clearnotify(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->notify != NULL) {
		isc_mem_put(zone->mctx, zone->notify,
			    zone->notifycnt * sizeof *zone->notify);
		zone->notify = NULL;
		zone->notifycnt = 0;
	}
	UNLOCK(&zone->lock);
}

isc_result_t
dns_zone_addmaster(dns_zone_t *zone, isc_sockaddr_t *master) {
	isc_sockaddr_t *new;
	REQUIRE(DNS_ZONE_VALID(zone));
	
	LOCK(&zone->lock);
	new = isc_mem_get(zone->mctx, (zone->masterscnt + 1) * sizeof *new);
	if (new == NULL) {
		UNLOCK(&zone->lock);
		return (ISC_R_NOMEMORY);
	}
	new[zone->masterscnt] = *master;
	if (zone->masterscnt > 0) {
		memcpy(new, zone->masters, zone->masterscnt * sizeof *new);
		isc_mem_put(zone->mctx, zone->masters,
			    zone->masterscnt * sizeof *new);
	}
	zone->masters = new;
	zone->masterscnt++;
	UNLOCK(&zone->lock);
	return (ISC_R_SUCCESS);
}

void
dns_zone_clearmasters(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	while (DNS_ZONE_FLAG(zone, DNS_ZONE_F_REFRESH)) {
		cancel_refresh(zone);
	}
	if (zone->masters != NULL) {
		isc_mem_put(zone->mctx, zone->masters,
			    zone->masterscnt * sizeof *zone->masters);
		zone->masters = NULL;
		zone->masterscnt = 0;
		zone->curmaster = 0;
	}
	UNLOCK(&zone->lock);
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
		    DNS_ZONE_FLAG(zone, DNS_ZONE_F_LOADED)) {
			expire(zone);
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
		if (now >= zone->dumptime &&
		    DNS_ZONE_FLAG(zone, DNS_ZONE_F_LOADED) &&
		    DNS_ZONE_FLAG(zone, DNS_ZONE_F_NEEDDUMP)) {
			dns_zone_dump(zone);
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
		if (DNS_ZONE_FLAG(zone, DNS_ZONE_F_LOADED) &&
		    DNS_ZONE_FLAG(zone, DNS_ZONE_F_NEEDNOTIFY)) {
			dns_zone_notify(zone);
		}
	default:
		break;
	}
	/*
	 * Check servers for zone.
	 */
	switch (zone->type) {
	case dns_zone_master:
	case dns_zone_slave:
	case dns_zone_stub:
#ifdef notyet
		if (now >= zone->servertime &&
		    DNS_ZONE_FLAG(zone, DNS_ZONE_F_LOADED) &&
		    DNS_ZONE_OPTION(zone, DNS_ZONE_O_SERVERS) &&
		    !DNS_ZONE_FLAG(zone, DNS_ZONE_F_SERVERS))
			dns_zone_checkservers(zone);
#endif
		break;
	default:
		break;
	}

	/*
	 * Check parent servers for zone.
	 */
	switch (zone->type) {
	case dns_zone_master:
	case dns_zone_slave:
	case dns_zone_stub:
		if (now >= zone->parenttime &&
		    DNS_ZONE_FLAG(zone, DNS_ZONE_F_LOADED) &&
		    DNS_ZONE_OPTION(zone, DNS_ZONE_O_PARENTS) &&
		    !DNS_ZONE_FLAG(zone, DNS_ZONE_F_PARENTS))
			dns_zone_checkparents(zone);
		break;
	default:
		break;
	}

	/*
	 * Check child servers for zone.
	 */
	switch (zone->type) {
	case dns_zone_master:
	case dns_zone_slave:
	case dns_zone_stub:
		if (now >= zone->childtime &&
		    DNS_ZONE_FLAG(zone, DNS_ZONE_F_LOADED) &&
		    DNS_ZONE_OPTION(zone, DNS_ZONE_O_CHILDREN) &&
		    !DNS_ZONE_FLAG(zone, DNS_ZONE_F_CHILDREN))
			dns_zone_checkchildren(zone);
		break;
	default:
		break;
	}
	(void) zone_settimer(zone, now); /*XXX*/
}

void
dns_zone_expire(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	expire(zone);
	UNLOCK(&zone->lock);
}

static void
expire(dns_zone_t *zone) {
	if (DNS_ZONE_FLAG(zone, DNS_ZONE_F_NEEDDUMP))
		dns_zone_dump(zone);
	zone->flags |= DNS_ZONE_F_EXPIRED;
	dns_zone_setrefresh(zone, DEFAULT_REFRESH, DEFAULT_RETRY);
	unload(zone);
}

void
dns_zone_refresh(dns_zone_t *zone) {
	isc_stdtime_t now;
	isc_uint32_t oldflags;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(zone->masterscnt > 0);

	isc_stdtime_get(&now);

	/*
	 * Set DNS_ZONE_F_REFRESH so that there is only one refresh operation
	 * in progress at the one time.
	 */

	LOCK(&zone->lock);
	oldflags = zone->flags;
	zone->flags |= DNS_ZONE_F_REFRESH;
	UNLOCK(&zone->lock);
	if ((oldflags & DNS_ZONE_F_REFRESH) != 0)
		return;

	/*
	 * Set the next refresh time as if refresh check has failed.
	 * If we are successful it will be reset using zone->refresh.
	 */

	zone->refreshtime = now + zone->retry;
	zone->curmaster = 0;
	/* initiate soa query */
	soa_query(zone, refresh_callback);
}

isc_result_t
dns_zone_dump(dns_zone_t *zone) {
	isc_result_t result;
	dns_dbversion_t *version = NULL;
	dns_db_t *db = NULL;
	char *buf;
	int buflen;
	FILE *f;
	int n;
	
	REQUIRE(DNS_ZONE_VALID(zone));

	buflen = strlen(zone->dbname) + 20;
	buf = isc_mem_get(zone->mctx, buflen);
	result = isc_mktemplate(zone->dbname, buf, buflen);
	if (result != ISC_R_SUCCESS)
		return (result);
	f = isc_ufile(buf);
	if (f == NULL) {
		result = ISC_R_UNEXPECTED;
		goto cleanup;
	}
	dns_db_attach(zone->db, &db);
	dns_db_currentversion(db, &version);
	result = dns_master_dumptostream(zone->mctx, db, version,
					 &dns_master_style_default, f);
	dns_db_closeversion(db, &version, ISC_FALSE);
	dns_db_detach(&db);
	n = fflush(f);
	if (n != 0)
		result = ISC_R_UNEXPECTED;
	n = ferror(f);
	if (n != 0)
		result = ISC_R_UNEXPECTED;
	n = fclose(f);
	if (n != 0)
		result = ISC_R_UNEXPECTED;
	if (result == ISC_R_SUCCESS) {
		n = rename(buf, zone->dbname);
		if (n == -1) {
			(void)remove(buf);
			result = ISC_R_UNEXPECTED;
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
	unload(zone);
	UNLOCK(&zone->lock);
}

static void
unload(dns_zone_t *zone) {
	/* caller to lock */
	dns_db_detach(&zone->db);
	zone->flags &= ~DNS_ZONE_F_LOADED;
}


void
dns_zone_unmount(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	/*XXX MPA*/
}

#ifdef notyet
/*
 * For reference only.  Use dns_zonemgr_managezone() instead.
 */
static isc_result_t
dns_zone_manage(dns_zone_t *zone, isc_taskmgr_t *tmgr) {
#if 1
	REQUIRE(DNS_ZONE_VALID(zone));
	(void)tmgr;
	dns_zone_maintenance(zone);
	return (ISC_R_SUCCESS);
#else
	isc_result_t result;

	/*
	 * XXXRTH  Zones do not have resolvers!!!!
	 */

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(zone->task == NULL);

	result = isc_task_create(tmgr, 0, &zone->task);
	if (result != ISC_R_SUCCESS) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}
	result = isc_task_onshutdown(zone->task, zone_shutdown, zone);
	if (result != ISC_R_SUCCESS) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}
	if (zone->res == NULL) {
		isc_socket_t *s;
		dns_dispatch_t *dispatch;

		RUNTIME_CHECK(isc_socketmgr_create(zone->mctx, &zone->socketmgr)
			      == ISC_R_SUCCESS);
		s = NULL;
		RUNTIME_CHECK(isc_socket_create(zone->socketmgr, PF_INET,
			      isc_sockettype_udp, &s) == ISC_R_SUCCESS);
		dispatch = NULL;
		RUNTIME_CHECK(dns_dispatch_create(zone->mctx, s, zone->task,
						  4096, 1000, 1000, 17, 19,
						  &dispatch) == ISC_R_SUCCESS);
		result = dns_resolver_create(zone->mctx, tmgr, 10, zone->timgr,
				             zone->rdclass, dispatch,
					     &zone->res); 
		if (result != ISC_R_SUCCESS)
			return (result);

		dns_dispatch_detach(&dispatch);
		isc_socket_detach(&s);
	}

	dns_zone_maintenance(zone);
	return (ISC_R_SUCCESS);
#endif
}
#endif

void
dns_zone_setrefresh(dns_zone_t *zone, isc_uint32_t refresh,
		    isc_uint32_t retry)
{
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->refresh = refresh;
	zone->retry = retry;
}

static void
notify_destroy(notify_t *notify) {
	isc_mem_t *mctx;

	/*
	 * Caller holds zone lock.
	 */
	REQUIRE(DNS_NOTIFY_VALID(notify));

	if (notify->zone != NULL) {
		if (ISC_LINK_LINKED(notify, link))
			ISC_LIST_UNLINK(notify->zone->notifies, notify, link);
		zone_idetach(&notify->zone, ISC_FALSE);
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
create_notify(isc_mem_t *mctx, notify_t **notifyp) {
	notify_t *notify;

	REQUIRE(notifyp != NULL && *notifyp == NULL);

	notify = isc_mem_get(mctx, sizeof *notify);
	if (notify == NULL)
		return (ISC_R_NOMEMORY);

	notify->mctx = NULL;
	isc_mem_attach(mctx, &notify->mctx);
	notify->zone = NULL;
	notify->find = NULL;
	notify->request = NULL;
	dns_name_init(&notify->ns, NULL);
	ISC_LINK_INIT(notify, link);
	notify->magic = NOTIFY_MAGIC;
	*notifyp = notify;
	return (ISC_R_SUCCESS);
}

static void
process_adb_event(isc_task_t *task, isc_event_t *ev) {
	notify_t *notify;
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
	LOCK(&notify->zone->lock);
	notify_destroy(notify);
	UNLOCK(&zone->lock);
 detach:
	dns_zone_idetach(&zone);
}

static void
notify_find_address(notify_t *notify) {
	isc_result_t result;
	unsigned int options;
	dns_zone_t *zone = NULL;

	REQUIRE(DNS_NOTIFY_VALID(notify));
	options = DNS_ADBFIND_WANTEVENT | DNS_ADBFIND_INET |
		  DNS_ADBFIND_INET6 | DNS_ADBFIND_RETURNLAME;

	dns_zone_iattach(notify->zone, &zone);
	result = dns_adb_createfind(zone->adb,
				    zone->task,
				    process_adb_event, notify,
				    &notify->ns, dns_rootname,
				    options, 0, NULL, &notify->find);

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

static void
notify_send(notify_t *notify) {
	dns_adbaddrinfo_t *ai;
	isc_sockaddr_t dst;
#ifdef notyet
	isc_sockaddr_t src;
#endif
	isc_result_t result;
	dns_message_t *message = NULL;
	notify_t *new = NULL;

	/*
	 * Zone lock held by caller.
	 */
	REQUIRE(DNS_NOTIFY_VALID(notify));

	result = notify_createmessage(notify->zone, &message);
	if (result != ISC_R_SUCCESS)
		return;

	ai = ISC_LIST_HEAD(notify->find->list);
	while (ai != NULL) {
		dst = *ai->sockaddr;
		isc_sockaddr_setport(&dst, 53); /* XXX */
#ifdef notyet
		switch (isc_sockaddr_pf(&dst)) {
		case AF_INET:
			src = zone->xfrsource4;
			break;
		case AF_INET6:
			src = zone->xfrsource6;
			break;
		default:
			FATAL_ERROR(__FILE__, __LINE__,
				    "unknown address family");
		}
#endif
		new = NULL;
		result = create_notify(notify->mctx, &new);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		zone_iattach(notify->zone, &new->zone);
		result = dns_request_create(new->zone->requestmgr, message,
					    &dst, 0, 15, new->zone->task,
					    notify_done, new,
					    &new->request);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		ISC_LIST_APPEND(new->zone->notifies, new, link);
		new = NULL;
		ai = ISC_LIST_NEXT(ai, publink);
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
	dns_message_t *message = NULL;
	dns_name_t *origin = NULL;
	dns_name_t master;
	dns_rdata_ns_t ns;
	dns_rdata_soa_t soa;
	dns_rdata_t rdata;
	dns_rdataset_t nsrdset;
	dns_rdataset_t soardset;
	isc_result_t result;
	isc_sockaddr_t dst;
	isc_sockaddr_t src;
	notify_t *notify = NULL;
	unsigned int i;

	REQUIRE(DNS_ZONE_VALID(zone));

	if (!DNS_ZONE_OPTION(zone, DNS_ZONE_O_NOTIFY)) {
		LOCK(&zone->lock);
		zone->flags &= ~DNS_ZONE_F_NEEDNOTIFY;
		UNLOCK(&zone->lock);
		return;
	}

	origin = &zone->origin;

	result = notify_createmessage(zone, &message);
	if (result != ISC_R_SUCCESS)
		return;

	LOCK(&zone->lock);
	zone->flags &= ~DNS_ZONE_F_NEEDNOTIFY;
	UNLOCK(&zone->lock);

	/*
	 * Enqueue notify request.
	 */
	for (i = 0; i < zone->notifycnt; i++) {
		dst = zone->notify[i];
		isc_sockaddr_setport(&dst, 53); /* XXX */
#ifdef notyet
		switch (isc_sockaddr_pf(&dst)) {
		case AF_INET:
			src = zone->xfrsource4;
			break;
		case AF_INET6:
			src = zone->xfrsource6;
			break;
		default:
			FATAL_ERROR(__FILE__, __LINE__,
				    "unknown address family");
		}
#else
		UNUSED(src);
#endif
		result = create_notify(zone->mctx, &notify);
		if (result != ISC_R_SUCCESS)
			goto cleanup0;
		dns_zone_iattach(zone, &notify->zone);
		result = dns_request_create(zone->requestmgr, message,
					    &dst, 0, 15, zone->task,
					    notify_done, notify,
					    &notify->request);
		if (result != ISC_R_SUCCESS) {
			LOCK(&zone->lock);
			notify_destroy(notify);
			UNLOCK(&zone->lock);
			goto cleanup0;
		}
		LOCK(&zone->lock);
		ISC_LIST_APPEND(zone->notifies, notify, link);
		UNLOCK(&zone->lock);
		notify = NULL;
	}

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
		result = dns_rdata_tostruct(&rdata, &soa, zone->mctx);
		if (result != ISC_R_SUCCESS)
			continue;
		result = dns_name_dup(&soa.origin, zone->mctx, &master);
		dns_rdata_freestruct(&soa);
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
		result = dns_rdata_tostruct(&rdata, &ns, zone->mctx);
		if (result != ISC_R_SUCCESS)
			continue;
		/*
		 * don't notify the master server.
		 */
		if (dns_name_compare(&master, &ns.name) == 0) {
			dns_rdata_freestruct(&ns);
			result = dns_rdataset_next(&nsrdset);
			continue;
		}
		result = create_notify(zone->mctx, &notify);
		if (result != ISC_R_SUCCESS) {
			dns_rdata_freestruct(&ns);
			continue;
		}
		dns_zone_iattach(zone, &notify->zone);
		result = dns_name_dup(&ns.name, zone->mctx, &notify->ns);
		dns_rdata_freestruct(&ns);
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
 cleanup0:
	dns_message_destroy(&message);
}

/***
 *** Private
 ***/

static void
refresh_callback(isc_task_t *task, isc_event_t *event) {
	char me[] = "refresh_callback";
	dns_requestevent_t *revent = (dns_requestevent_t *)event;
	dns_zone_t *zone;
	dns_message_t *msg = NULL;
	isc_uint32_t soacnt, cnamecnt, soacount, nscount;
	isc_stdtime_t now;
	char *master;
	isc_buffer_t masterbuf;
	char mastermem[256];
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

	isc_buffer_init(&masterbuf, mastermem, sizeof(mastermem),
			ISC_BUFFERTYPE_TEXT);
	result = isc_sockaddr_totext(&zone->masteraddr, &masterbuf);
	if (result == ISC_R_SUCCESS)
		master = (char *) masterbuf.base;
	else
		master = "<UNKNOWN>";
	
	if (revent->result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_INFO, "failure for %s: %s",
		         master, dns_result_totext(revent->result));
		goto next_master;
	}

	result = dns_message_create(zone->mctx, DNS_MESSAGE_INTENTPARSE, &msg);
	if (result != ISC_R_SUCCESS)
		goto next_master;
	result = dns_request_getresponse(revent->request, msg);
	if (result != ISC_R_SUCCESS)
		goto next_master;

	/*
	 * Unexpected rcode.
	 */
	if (msg->rcode != dns_rcode_noerror) {
		char rcode[128];
		isc_buffer_t rb;

		isc_buffer_init(&rb, rcode, sizeof rcode, ISC_BUFFERTYPE_TEXT);
		dns_rcode_totext(msg->rcode, &rb);

		zone_log(zone, me, ISC_LOG_INFO,
			 "unexpected rcode (%.*s) from %s\n",
			 rb.used, rcode, master);
		goto next_master;
	}

	/*
	 * If truncated punt to zone transfer which will query again.
	 */
	if ((msg->flags & DNS_MESSAGEFLAG_TC) != 0) {
		zone_log(zone, me, ISC_LOG_INFO,
			 "truncated UDP answer initiating TCP zone xfer %s",
			 master);
		goto tcp_transfer;
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
	soacount = message_count(msg, DNS_SECTION_AUTHORITY, dns_rdatatype_soa);

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
	result = dns_rdata_tostruct(&rdata, &soa, zone->mctx);
	if (result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_INFO, "dns_rdata_tostruct failed");
		goto next_master;
	}

	serial = soa.serial;
	dns_rdata_freestruct(&soa);
	dns_message_destroy(&msg);

	zone_log(zone, me, ISC_LOG_DEBUG(1), "Serial: new %u, old %u",
		 serial, zone->serial);
	if (!DNS_ZONE_FLAG(zone, DNS_ZONE_F_LOADED) ||
	    isc_serial_gt(serial, zone->serial)) {
 tcp_transfer:
		isc_event_free(&event);
		dns_request_destroy(&zone->request);
		dns_zone_transfer_in(zone);
	} else if (isc_serial_eq(soa.serial, zone->serial)) {
		dns_zone_uptodate(zone);
		goto next_master;
	} else {
		ZONE_LOG(1, "ahead");
		goto next_master;
	}
	return;

 next_master:
	if (msg != NULL)
		dns_message_destroy(&msg);
	LOCK(&zone->lock);
	isc_event_free(&event);
	dns_request_destroy(&zone->request);
	zone->curmaster++;
	if (zone->curmaster >= zone->masterscnt) {
		zone->flags &= ~DNS_ZONE_F_REFRESH;

		isc_stdtime_get(&now);
		zone_settimer(zone, now);
		UNLOCK(&zone->lock);
		return;
	}
	UNLOCK(&zone->lock);
	soa_query(zone, refresh_callback);
	return;
}

static void
soa_query(dns_zone_t *zone, isc_taskaction_t callback) {
	const char me[] = "soa_query";
	isc_result_t result;
	in_port_t port;
	dns_message_t *message = NULL;
	dns_name_t *qname = NULL;
	dns_rdataset_t *qrdataset = NULL;

	DNS_ENTER;

	if (zone->shuttingdown)
		return;
	/* 
	 * XXX Optimisation: Create message when zone is setup and reuse.
	 */
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
	dns_rdataset_makequestion(qrdataset, zone->rdclass, dns_rdatatype_soa);
	ISC_LIST_APPEND(qname->list, qrdataset, link);
	dns_message_addname(message, qname, DNS_SECTION_QUESTION);
	qname = NULL;
	qrdataset = NULL;

	LOCK(&zone->lock);
	INSIST(zone->masterscnt > 0);
	INSIST(zone->curmaster < zone->masterscnt);
	zone->masteraddr = zone->masters[zone->curmaster];
	port = zone->masterport;
	UNLOCK(&zone->lock);

	if (port == 0)
		port = 53; /* XXX is this the right place? */
	isc_sockaddr_setport(&zone->masteraddr, port);

	result = dns_request_create(zone->requestmgr, message,
				    &zone->masteraddr, 0,
				    15 /* XXX */, zone->task,
				    callback, zone, &zone->request);
	if (result != ISC_R_SUCCESS) {
		zone_log(zone, me, ISC_LOG_DEBUG(1),
			 "dns_request_create failed: %s",
			 dns_result_totext(result));
		goto cleanup;
	}
	dns_message_destroy(&message);
	return;

 cleanup:
	if (qname != NULL)
		dns_message_puttempname(message, &qname);
	if (qrdataset != NULL)
		dns_message_puttemprdataset(message, &qrdataset);
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
	notify_t *notify;

	UNUSED(task);
	REQUIRE(DNS_ZONE_VALID(zone));
	INSIST(event->ev_type == DNS_EVENT_ZONECONTROL);
	INSIST(zone->erefs == 0);
	zone_log(zone, "zone_shutdown", ISC_LOG_DEBUG(3), "shutting down");
	zone->shuttingdown = ISC_TRUE;
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
		if (DNS_ZONE_FLAG(zone, DNS_ZONE_F_NEEDNOTIFY))
			next = now;
		if (DNS_ZONE_FLAG(zone, DNS_ZONE_F_NEEDDUMP) &&
		    (zone->dumptime < next || next == 0))
			next = zone->dumptime;
		if (DNS_ZONE_FLAG(zone, DNS_ZONE_F_LOADED)) {
			if (DNS_ZONE_OPTION(zone, DNS_ZONE_O_SERVERS) &&
			    (zone->servertime < next || next == 0))
				next = zone->servertime;
			if (DNS_ZONE_OPTION(zone, DNS_ZONE_O_PARENTS) &&
			    (zone->parenttime < next || next == 0))
				next = zone->parenttime;
			if (DNS_ZONE_OPTION(zone, DNS_ZONE_O_CHILDREN) &&
			    (zone->childtime < next || next == 0))
				next = zone->childtime;
		}
		break;
	case dns_zone_slave:
		if (DNS_ZONE_FLAG(zone, DNS_ZONE_F_NEEDNOTIFY))
			next = now;
	case dns_zone_stub:
		if (!DNS_ZONE_FLAG(zone, DNS_ZONE_F_REFRESH) &&
		    (zone->refreshtime < next || next == 0))
			next = zone->refreshtime;
		if (DNS_ZONE_FLAG(zone, DNS_ZONE_F_LOADED)) {
		    	if (zone->expiretime < next || next == 0)
				next = zone->expiretime;
			if (DNS_ZONE_OPTION(zone, DNS_ZONE_O_SERVERS) &&
			    (zone->servertime < next || next == 0))
				next = zone->servertime;
			if (DNS_ZONE_OPTION(zone, DNS_ZONE_O_PARENTS) &&
			    (zone->parenttime < next || next == 0))
				next = zone->parenttime;
			if (DNS_ZONE_OPTION(zone, DNS_ZONE_O_CHILDREN) &&
			    (zone->childtime < next || next == 0))
				next = zone->childtime;
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

	zone->flags &= ~DNS_ZONE_F_REFRESH;
	isc_stdtime_get(&now);
	if (!DNS_ZONE_FLAG(zone, DNS_ZONE_F_EXITING))
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
	if (DNS_ZONE_OPTION(zone, DNS_ZONE_O_DIALUP))
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
	result = isc_buffer_allocate(zone->mctx, &b, r.length,
		 ISC_BUFFERTYPE_BINARY);
	if (result != ISC_R_SUCCESS)
		goto done;
	isc_buffer_putmem(b, r.base, r.length);
	isc_buffer_used(b, &r);
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
		zone_log(zone, me, ISC_LOG_NOTICE,
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
	    DNS_ZONE_FLAG(zone, DNS_ZONE_F_LOADED) &&
	    !DNS_ZONE_OPTION(zone, DNS_ZONE_O_DIALUP)) {
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
			result = dns_rdata_tostruct(&rdata, &soa, zone->mctx);
			if (result == ISC_R_SUCCESS) {
				serial = soa.serial;
				dns_rdata_freestruct(&soa);
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
	if (DNS_ZONE_FLAG(zone, DNS_ZONE_F_REFRESH)) {
		zone->flags |= DNS_ZONE_F_NEEDREFRESH;
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

void
dns_zone_setmasterport(dns_zone_t *zone,  in_port_t port) {

	REQUIRE(DNS_ZONE_VALID(zone));

	zone->masterport = port;
}

in_port_t
dns_zone_getmasterport(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->masterport);
}

static void
zone_log(dns_zone_t *zone, const char *me, int level,
		  const char *fmt, ...) {
	va_list ap;
	char message[4096];
	char namebuf[1024+32];
	isc_buffer_t buffer;
	int len;
	isc_result_t result;

	isc_buffer_init(&buffer, namebuf, sizeof namebuf, ISC_BUFFERTYPE_TEXT);
	result = dns_name_totext(&zone->origin, ISC_FALSE, &buffer);
	if (result != ISC_R_SUCCESS)
		(void)isc_buffer_putstr(&buffer, "<UNKNOWN>");
	(void)isc_buffer_putstr(&buffer, "/");
	(void)dns_rdataclass_totext(zone->rdclass, &buffer);
	len = buffer.used;	/* XXX */

	va_start(ap, fmt);
	vsnprintf(message, sizeof message, fmt, ap);
	va_end(ap);
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_ZONE,
		      level, "%s: zone %.*s: %s", me, len, namebuf, message);
}

#if 1
static int
message_count(dns_message_t *msg, dns_section_t section, dns_rdatatype_t type) {
	isc_result_t result;
	dns_name_t *name;
	dns_rdataset_t *curr;
	int res = 0;

	result = dns_message_firstname(msg, section);
	while (result == ISC_R_SUCCESS) {
		name = NULL;
		dns_message_currentname(msg, section, &name);

		for (curr = ISC_LIST_TAIL(name->list); curr != NULL; 
		     curr = ISC_LIST_PREV(curr, link)) {
			if (curr->type == type)
				res++;
		}
		result = dns_message_nextname(msg, section);
	}

	return (res);
}
#endif

void
dns_zone_setadb(dns_zone_t *zone, dns_adb_t *adb) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->adb != NULL)
		dns_adb_detach(&zone->adb);
	dns_adb_attach(adb, &zone->adb);
	UNLOCK(&zone->lock);
}

void
dns_zone_setresolver(dns_zone_t *zone, dns_resolver_t *resolver) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->res != NULL)
		dns_resolver_detach(&zone->res);
	dns_resolver_attach(resolver, &zone->res);
	UNLOCK(&zone->lock);
}

void
dns_zone_setrequestmgr(dns_zone_t *zone, dns_requestmgr_t *requestmgr) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->requestmgr != NULL)
		dns_requestmgr_detach(&zone->requestmgr);
	dns_requestmgr_attach(requestmgr, &zone->requestmgr);
	UNLOCK(&zone->lock);
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
        char me[] = "notify_done";
	notify_t *notify;
	dns_zone_t *zone = NULL;
	
	UNUSED(task);

	notify = event->ev_arg;
	REQUIRE(DNS_NOTIFY_VALID(notify));

	dns_zone_iattach(notify->zone, &zone);
	DNS_ENTER;
	isc_event_free(&event);
	notify_destroy(notify);
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
	    oldzone->masterport != newzone->masterport ||
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
	result = replacedb(zone, db, dump);
	UNLOCK(&zone->lock);
	return (result);
}

static isc_result_t
replacedb(dns_zone_t *zone, dns_db_t *db, isc_boolean_t dump) {
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
		result = dns_db_diff(zone->mctx, 
					db, ver,
					zone->db, NULL /* XXX */,
					zone->journal);
		if (result != ISC_R_SUCCESS)
			goto fail;
	} else {
		if (dump) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
				      DNS_LOGMODULE_ZONE, ISC_LOG_DEBUG(3),
				      "dumping new zone version");
			/* XXX should use temporary file and rename */
			result = dns_db_dump(db, ver, zone->dbname);
			if (result != ISC_R_SUCCESS)
				goto fail;
		}
		if (zone->journal != NULL) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
				      DNS_LOGMODULE_ZONE, ISC_LOG_DEBUG(3),
				      "removing journal file");
			(void) remove(zone->journal);
		}
	}
	dns_db_closeversion(db, &ver, ISC_FALSE);

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
		      DNS_LOGMODULE_ZONE, ISC_LOG_DEBUG(3),
		      "replacing zone database");
	
	if (zone->db != NULL)
		dns_db_detach(&zone->db);
	dns_db_attach(db, &zone->db);
	zone->flags |= DNS_ZONE_F_LOADED|DNS_ZONE_F_NEEDNOTIFY;
	return (ISC_R_SUCCESS);
	
 fail:
	dns_db_closeversion(db, &ver, ISC_FALSE);
	return (result);
}

static void
xfrdone(dns_zone_t *zone, isc_result_t result) {
	const char me[] = "xfrdone";
	isc_stdtime_t now;
	isc_boolean_t again = ISC_FALSE;

	REQUIRE(DNS_ZONE_VALID(zone));

	zone_log(zone, me, ISC_LOG_DEBUG(1), "%s", dns_result_totext(result));

	LOCK(&zone->lock);
	INSIST((zone->flags & DNS_ZONE_F_REFRESH) != 0);
	zone->flags &= ~DNS_ZONE_F_REFRESH;

	isc_stdtime_get(&now);
	switch (result) {
	case ISC_R_SUCCESS:
		zone->flags |= DNS_ZONE_F_NEEDNOTIFY;
		/* FALLTHROUGH */
	case DNS_R_UPTODATE:
		if (DNS_ZONE_FLAG(zone, DNS_ZONE_F_NEEDREFRESH)) {
			zone->flags &= ~DNS_ZONE_F_NEEDREFRESH;
			zone->refreshtime = now;
		} else
			zone->refreshtime = now + zone->refresh;
		break;

	default:
		zone->curmaster++;
		if (zone->curmaster >= zone->masterscnt)
			zone->curmaster = 0;
		else {
			zone->flags |= DNS_ZONE_F_REFRESH;
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
	 * Retry with a different server if necessary.
	 */
	if (again)
		soa_query(zone, refresh_callback);
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

/***
 ***	Zone manager. 
 ***/

static void
dns_zone_transfer_in(dns_zone_t *zone) {
	const char me[] = "dns_zone_transfer_in";
	isc_result_t result;

	DNS_ENTER;

	if (zone->masterscnt < 1)
		return;

	result = dns_xfrin_create(zone, &zone->masteraddr, zone->mctx,
				  zone->zmgr->timermgr, zone->zmgr->socketmgr,
				  zone->task,
				  xfrdone, &zone->xfr);
	if (result != ISC_R_SUCCESS)
		xfrdone(zone, result);
}

isc_result_t
dns_zonemgr_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		   isc_timermgr_t *timermgr, isc_socketmgr_t *socketmgr,
		   dns_zonemgr_t **zmgrp)
{
	dns_zonemgr_t *zmgr;
	isc_result_t result;

	zmgr = isc_mem_get(mctx, sizeof *zmgr);
	if (zmgr == NULL)
		return (ISC_R_NOMEMORY);
	zmgr->mctx = NULL;
	isc_mem_attach(mctx, &zmgr->mctx);
	zmgr->taskmgr = taskmgr;
	zmgr->timermgr = timermgr;
	zmgr->socketmgr = socketmgr;
	zmgr->zonetasks = NULL;
	zmgr->task = NULL;
	ISC_LIST_INIT(zmgr->zones);
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
	
	result = dns_xfrinlist_init(&zmgr->transferlist);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "dns_transferlist_init() failed: %s",
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto free_conflock;
	}

	/* Create the zone task pool. */
	result = isc_taskpool_create(taskmgr, mctx, 
				     8 /* XXX */, 0, &zmgr->zonetasks);
	if (result != ISC_R_SUCCESS)
		goto free_transferlist;

	/* Create a single task for queueing of SOA queries. */
	result = isc_task_create(taskmgr, 1, &zmgr->task);
	if (result != ISC_R_SUCCESS)
		goto free_taskpool;
	isc_task_setname(zmgr->task, "zmgr", zmgr);

	*zmgrp = zmgr;
	return (ISC_R_SUCCESS);

 free_transferlist:
	dns_xfrinlist_destroy(&zmgr->transferlist);
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

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	LOCK(&zone->lock);
	REQUIRE(zone->task == NULL);
	REQUIRE(zone->timer == NULL);
	REQUIRE(zone->zmgr == NULL);
	REQUIRE(zone->rl == NULL);

	isc_taskpool_gettask(zmgr->zonetasks,
			     dns_name_hash(dns_zone_getorigin(zone),
					   ISC_FALSE),
			     &zone->task);

	result = isc_timer_create(zmgr->timermgr, isc_timertype_inactive,
				  NULL, NULL,
				  zmgr->task, zone_timer, zone,
				  &zone->timer);
	if (result != ISC_R_SUCCESS)
		goto cleanup_task;

	zone->zmgr = zmgr;
	ISC_LIST_APPEND(zmgr->zones, zone, link);

	goto unlock;

 cleanup_task:
	isc_task_detach(&zone->task);
	
 unlock:
	UNLOCK(&zone->lock);
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	return (result);
}

static void
releasezone(dns_zonemgr_t *zmgr, dns_zone_t *zone) {
	/*
	 * Caller to lock zone and zmgr
	 */
	ISC_LIST_UNLINK(zmgr->zones, zone, link);
	zone->zmgr = NULL;
}

void
dns_zonemgr_releasezone(dns_zonemgr_t *zmgr, dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	LOCK(&zone->lock);
	releasezone(zmgr, zone);
	UNLOCK(&zone->lock);
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_write);
}

isc_result_t
dns_zonemgr_forcemaint(dns_zonemgr_t *zmgr) {
	dns_zone_t *p;

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
	if (zmgr->task != NULL)
		isc_task_destroy(&zmgr->task);
	if (zmgr->zonetasks != NULL)
		isc_taskpool_destroy(&zmgr->zonetasks);
}

void
dns_zonemgr_destroy(dns_zonemgr_t **zmgrp) {
	isc_mem_t *mctx;
	dns_zonemgr_t *zmgr = *zmgrp;
	dns_zone_t *zone;

	RWLOCK(&zmgr->rwlock, isc_rwlocktype_write);
	zone = ISC_LIST_HEAD(zmgr->zones);
	while (zone != NULL) {
		LOCK(&zone->lock);
		releasezone(zmgr, zone);
		UNLOCK(&zone->lock);
		zone = ISC_LIST_HEAD(zmgr->zones);
	}
	RWUNLOCK(&zmgr->rwlock, isc_rwlocktype_write);

	/* Probably done already, but does not hurt to repeat. */
	dns_zonemgr_shutdown(zmgr);

	isc_rwlock_destroy(&zmgr->conflock);
	isc_rwlock_destroy(&zmgr->rwlock);
	mctx = zmgr->mctx;
	isc_mem_put(zmgr->mctx, zmgr, sizeof *zmgr);
	isc_mem_detach(&mctx);
	*zmgrp = NULL;
}

void
dns_zonemgr_lockconf(dns_zonemgr_t *zmgr, isc_rwlocktype_t type) {
	RWLOCK(&zmgr->conflock, type);
}

void
dns_zonemgr_unlockconf(dns_zonemgr_t *zmgr, isc_rwlocktype_t type) {
	RWUNLOCK(&zmgr->conflock, type);
}

void
dns_zonemgr_settransfersin(dns_zonemgr_t *zmgr, int value) {
	zmgr->transfersin = value;
}

int
dns_zonemgr_getttransfersin(dns_zonemgr_t *zmgr) {
	return (zmgr->transfersin);
}

void
dns_zonemgr_settransfersperns(dns_zonemgr_t *zmgr, int value) {
	zmgr->transfersperns = value;
}

int
dns_zonemgr_getttransfersperns(dns_zonemgr_t *zmgr) {
	return (zmgr->transfersperns);
}

dns_xfrinlist_t	*
dns_zonemgr_gettransferlist(dns_zonemgr_t *zmgr) {
	return (&zmgr->transferlist);
}

#if 0
/* hook for ondestroy notifcation from a database. */

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
