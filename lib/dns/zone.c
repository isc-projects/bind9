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

 /* $Id: zone.c,v 1.29 1999/10/29 02:17:31 halley Exp $ */

#include <config.h>

#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <../isc/util.h> /* XXX MPA */
#include <isc/timer.h>
#include <isc/print.h>
#include <isc/serial.h>
#include <isc/magic.h>
#include <isc/taskpool.h>

#include <dns/confparser.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/dispatch.h>
#include <dns/journal.h>
#include <dns/master.h>
#include <dns/message.h>
#include <dns/rcode.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatastruct.h>
#include <dns/resolver.h>
#include <dns/zone.h>
#include <dns/zt.h>

/* XXX remove once config changes are in place */
#define dns_zone_uptodate(x) dns_zone_logerror(x, "dns_zone_uptodate")
#define referral(x) ISC_FALSE

#include <stdarg.h>

#define ZONE_MAGIC 0x5a4f4e45U
#define CHECKSERVERS_MAGIC 0x43484346U

#define DNS_ZONE_VALID(zone) \
	ISC_MAGIC_VALID(zone, ZONE_MAGIC)
#define DNS_CHECKSERVERS_VALID(server) \
	ISC_MAGIC_VALID(zone, CHECKSERVERS_MAGIC)

#ifndef DNS_GLOBAL_OPTION	/* XXX MPA */
#define DNS_GLOBAL_OPTION(o) 0
#endif

#define DEFAULT_REFRESH	900	/*XXX*/
#define DEFAULT_RETRY 300	/*XXX*/
#define MAX_XFER_TIME 3600	/*XXX*/

#define RANGE(a, b, c) (((a) < (b)) ? (b) : ((a) < (c) ? (a) : (c)))

#define DNS_MIN_REFRESH 2
#define DNS_MAX_REFRESH 2419200		/* 4 weeks */
#define DNS_MIN_RETRY	1
#define DNS_MAX_RETRY	1209600		/* 2 weeks */
#define DNS_MAX_EXPIRE	14515200	/* 24 weeks */

typedef enum {
	get_a6, get_aaaa, get_a, get_ns, get_soa
} dns_zone_state_t;

typedef struct dns_zone_checkservers {
	isc_uint32_t			magic;
	isc_boolean_t			name_known;
	dns_name_t			server;
	isc_sockaddr_t			address;
	dns_zone_state_t		state;
	dns_zone_t			*zone;
	dns_resolver_t			*res;
	isc_mem_t			*mctx;
	dns_fetch_t			*fetch;
	ISC_LINK(struct dns_zone_checkservers) link;
} dns_zone_checkservers_t;

struct dns_zone {
	/* Unlocked */
	unsigned int		magic;
	isc_mutex_t		lock;
	isc_mem_t		*mctx;

	/* Locked */
	dns_db_t		*top;
	dns_zonemgr_t		*zmgr;
	ISC_LINK(dns_zone_t)	link;		/* Used by zmgr. */
	isc_timermgr_t		*timgr;
	isc_timer_t		*timer;
	unsigned int		references;
	dns_name_t		origin;
	char 			*database;
	char 			*ixfrlog;	/*
						 * XXX merge w/ updatelog to
						 * locate transaction log
						 */
	char 			*updatelog;
	char			*journal;
	isc_int32_t		ixfrlogsize;
	dns_rdataclass_t	rdclass;
	dns_zonetype_t		type;
	unsigned int		flags;
	unsigned int		options;
	unsigned int		setoptions;
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
	isc_sockaddr_t *	notify;
	unsigned int		notifycnt;
	isc_sockaddr_t		notifyfrom;
	isc_task_t *		task;
	isc_sockaddr_t	 	xfrsource;
	/* Access Control Lists */
	dns_c_ipmatchlist_t	*update_acl;
	dns_c_ipmatchlist_t	*query_acl;
	dns_c_ipmatchlist_t	*xfr_acl;
	dns_c_severity_t	check_names;
	dns_c_pubkey_t		*pubkey;
	ISC_LIST(dns_zone_checkservers_t)	checkservers;
	dns_fetch_t		*fetch;
	dns_resolver_t		*res;
	isc_socketmgr_t		*socketmgr;
	isc_uint32_t		xfrtime;
	isc_boolean_t		diff_on_reload;
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

#define DNS_ZONE_OPTION(z,o) ((((z)->setoptions & (o)) != 0) ? \
			      (((z)->options & (o)) != 0) : \
			      DNS_GLOBAL_OPTION(o))

struct dns_zonemgr {
	isc_mem_t *		mctx;
	isc_taskmgr_t *		taskmgr;
	isc_timermgr_t *	timermgr;
	isc_taskpool_t *	zonetasks;
	struct soaquery {
		isc_task_t *	task;
	} soaquery;
	ISC_LIST(dns_zone_t)	zones;
};

static void refresh_callback(isc_task_t *, isc_event_t *);
static void zone_shutdown(isc_task_t *, isc_event_t *);
static void soa_query(dns_zone_t *, isc_taskaction_t);
static dns_result_t zone_settimer(dns_zone_t *, isc_stdtime_t);
static void cancel_refresh(dns_zone_t *);
static dns_result_t dns_notify(dns_name_t *, isc_sockaddr_t *, dns_rdatatype_t,
		       dns_rdataclass_t, isc_sockaddr_t *, isc_mem_t *);
static void checkservers_callback(isc_task_t *task, isc_event_t *event);

static void dns_zone_logerror(dns_zone_t *zone, const char *msg, ...);
static int message_count(dns_message_t *msg, dns_section_t section,
			 dns_rdatatype_t type);
#if 0
static void sockaddr_fromaddr(isc_sockaddr_t *sockaddr, dns_c_addr_t *a,
			      in_port_t port);
#endif
static void add_address_tocheck(dns_message_t *msg,
				dns_zone_checkservers_t *checkservers,
				dns_rdatatype_t type);
extern void dns_zone_transfer_in(dns_zone_t *zone);
static void record_serial(void);
static dns_result_t dns_zone_tostr(dns_zone_t *zone, isc_mem_t *mctx, char **s);
static void unload(dns_zone_t *zone);
static void expire(dns_zone_t *zone);
static dns_result_t replacedb(dns_zone_t *zone, dns_db_t *db,
			      isc_boolean_t dump);
static dns_result_t default_journal(dns_zone_t *zone);


#define PRINT_ZONE_REF(zone) \
	do { \
		char *s = NULL; \
		dns_result_t r; \
		r = dns_zone_tostr(zone, zone->mctx, &s); \
		if (r == DNS_R_SUCCESS) { \
			printf("%p: %s: references = %d\n", zone, s, \
			       zone->references); \
			isc_mem_free(zone->mctx, s); \
		} \
	} while (0)


/***
 ***	Public functions.
 ***/

dns_result_t
dns_zone_create(dns_zone_t **zonep, isc_mem_t *mctx) {
	isc_result_t iresult;
	dns_zone_t *zone;
	isc_sockaddr_t sockaddr_any;

	REQUIRE(zonep != NULL && *zonep == NULL);
	REQUIRE(mctx != NULL);

	isc_sockaddr_fromin6(&sockaddr_any, &in6addr_any, 0);

	zone = isc_mem_get(mctx, sizeof *zone);
	if (zone == NULL)
		return (DNS_R_NOMEMORY);

	iresult = isc_mutex_init(&zone->lock);
	if (iresult != ISC_R_SUCCESS) {
		isc_mem_put(mctx, zone, sizeof *zone);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed: %s",
				 isc_result_totext(iresult));
		return (DNS_R_UNEXPECTED);
	}

	/* XXX MPA check that all elements are initialised */
	zone->mctx = mctx;
	zone->top = NULL;
	zone->zmgr = NULL;
	ISC_LINK_INIT(zone, link);
	zone->timgr = NULL;
	zone->references = 1;		/* Implicit attach. */
	dns_name_init(&zone->origin, NULL);
	zone->database = NULL;
	zone->ixfrlog = NULL;
	zone->ixfrlogsize = -1;
	zone->updatelog = NULL;
	zone->journal = NULL;
	zone->rdclass = dns_rdataclass_none;
	zone->type = dns_zone_none;
	zone->flags = 0;
	zone->options = 0;
	zone->setoptions = 0;
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
	zone->check_names = dns_c_severity_ignore;
	zone->pubkey = NULL;
	zone->fetch = NULL;
	zone->res = NULL;
	zone->socketmgr = NULL;
	zone->timer = NULL;
	ISC_LIST_INIT(zone->checkservers);
	zone->xfrsource = sockaddr_any;
	zone->xfrtime = MAX_XFER_TIME;
	zone->diff_on_reload = ISC_FALSE;
	zone->magic = ZONE_MAGIC;
#if 0
	PRINT_ZONE_REF(zone);
#endif
	*zonep = zone;
	return (DNS_R_SUCCESS);
}

static void
zone_free(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));
	LOCK(&zone->lock);
	REQUIRE(zone->references == 0);
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
	if (zone->fetch != NULL)
		dns_resolver_destroyfetch(zone->res, &zone->fetch);
	if (zone->timgr != NULL)
		isc_timermgr_destroy(&zone->timgr);
	if (zone->task != NULL)
		isc_task_destroy(&zone->task);
	if (zone->socketmgr != NULL)
		isc_socketmgr_destroy(&zone->socketmgr);

	/* unmanaged objects */
	if (zone->database != NULL)
		isc_mem_free(zone->mctx, zone->database);
	zone->database = NULL;
	if (zone->ixfrlog != NULL)
		isc_mem_free(zone->mctx, zone->ixfrlog);
	zone->ixfrlog = NULL;
	zone->ixfrlogsize = -1;
	if (zone->updatelog != NULL)
		isc_mem_free(zone->mctx, zone->updatelog);
	zone->updatelog = NULL;
	if (zone->journal != NULL)
		isc_mem_free(zone->mctx, zone->journal);
	zone->journal = NULL;
	if (zone->db_type != NULL)
		isc_mem_free(zone->mctx, zone->db_type);
	zone->db_type = NULL;
	if (zone->top != NULL)
		dns_db_detach(&zone->top);
	dns_zone_cleardbargs(zone);
	dns_zone_clearmasters(zone);
	zone->masterport = 0;
	dns_zone_clearnotify(zone);
	zone->check_names = dns_c_severity_ignore;
	zone->pubkey = NULL; /* XXX detach */
	if (zone->update_acl != NULL)
		dns_c_ipmatchlist_delete(NULL, &zone->update_acl);
	if (zone->query_acl != NULL)
		dns_c_ipmatchlist_delete(NULL, &zone->query_acl);
	if (zone->xfr_acl != NULL)
		dns_c_ipmatchlist_delete(NULL, &zone->xfr_acl);
	if (dns_name_dynamic(&zone->origin))
		dns_name_free(&zone->origin, zone->mctx);

	/* last stuff */
	isc_mutex_destroy(&zone->lock);
	zone->magic = 0;
	isc_mem_put(zone->mctx, zone, sizeof *zone);
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

dns_result_t
dns_zone_setdbtype(dns_zone_t *zone, char *db_type) {
	dns_result_t result = DNS_R_SUCCESS;

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->db_type != NULL)
		isc_mem_free(zone->mctx, zone->db_type);
	zone->db_type = isc_mem_strdup(zone->mctx, db_type);
	if (zone->db_type == NULL)
		result = DNS_R_NOMEMORY;
	UNLOCK(&zone->lock);
	return (result);
}

dns_result_t
dns_zone_setorigin(dns_zone_t *zone, char *origin) {
	isc_buffer_t buffer;
	dns_fixedname_t fixed;
	dns_result_t result;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(origin != NULL);

	dns_fixedname_init(&fixed);
	isc_buffer_init(&buffer, origin, strlen(origin), ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&buffer, strlen(origin));
	result = dns_name_fromtext(dns_fixedname_name(&fixed),
			  	   &buffer, dns_rootname, ISC_FALSE, NULL);
	if (result != DNS_R_SUCCESS)
		return (result);
	LOCK(&zone->lock);
	if (dns_name_dynamic(&zone->origin)) {
		dns_name_free(&zone->origin, zone->mctx);
		dns_name_init(&zone->origin, NULL);
	}
	result = dns_name_dup(dns_fixedname_name(&fixed), zone->mctx,
			      &zone->origin);
	UNLOCK(&zone->lock);
	return (result);
}

dns_result_t
dns_zone_setdatabase(dns_zone_t *zone, const char *database) {
	dns_result_t result = DNS_R_SUCCESS;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(database != NULL);

	LOCK(&zone->lock);
	if (zone->database != NULL)
		isc_mem_free(zone->mctx, zone->database);
	zone->database = isc_mem_strdup(zone->mctx, database);
	if (zone->database == NULL)
		result = DNS_R_NOMEMORY;
	else
		result = default_journal(zone);
	UNLOCK(&zone->lock);
	return (result);
}

static dns_result_t
default_journal(dns_zone_t *zone) {
	int len;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(zone->database != NULL);

	if (zone->journal != NULL) 
		isc_mem_free(zone->mctx, zone->journal);
	len = strlen(zone->database) + sizeof ".jnl"; 	/* includes '\0' */
	zone->journal = isc_mem_allocate(zone->mctx, len);
	if (zone->journal == NULL)
		return (DNS_R_NOMEMORY);
	strcpy(zone->journal, zone->database);
	strcat(zone->journal, ".jnl");
	return (DNS_R_SUCCESS);
}

dns_result_t
dns_zone_setjournal(dns_zone_t *zone, const char *journal) {
	dns_result_t result = DNS_R_SUCCESS;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(journal != NULL);

	LOCK(&zone->lock);
	if (zone->journal != NULL)
		isc_mem_free(zone->mctx, zone->journal);
	zone->journal = isc_mem_strdup(zone->mctx, journal);
	if (zone->journal == NULL)
		result = DNS_R_NOMEMORY;
	UNLOCK(&zone->lock);
	return (result);
}

char *
dns_zone_getjournal(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));
	return (zone->journal);
}

dns_result_t
dns_zone_setupdatelog(dns_zone_t *zone, char *updatelog) {
	dns_result_t result = DNS_R_SUCCESS;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(updatelog != NULL);

	LOCK(&zone->lock);
	if (zone->updatelog != NULL)
		isc_mem_free(zone->mctx, zone->updatelog);
	zone->updatelog = isc_mem_strdup(zone->mctx, updatelog);
	if (zone->updatelog == NULL)
		result = DNS_R_NOMEMORY;
	UNLOCK(&zone->lock);
	return (result);
}


dns_result_t
dns_zone_setixfrlog(dns_zone_t *zone, const char *ixfrlog) {
	dns_result_t result = DNS_R_SUCCESS;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(ixfrlog != NULL);

	LOCK(&zone->lock);
	if (zone->ixfrlog != NULL)
		isc_mem_free(zone->mctx, zone->ixfrlog);
	zone->ixfrlog = isc_mem_strdup(zone->mctx, ixfrlog);
	if (zone->ixfrlog == NULL)
		result = DNS_R_NOMEMORY;
	UNLOCK(&zone->lock);
	return (result);
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
		REQUIRE(zone->database != NULL);
		/*FALLTHROUGH*/
	case dns_zone_forward:
		REQUIRE(zone->rdclass != dns_rdataclass_none);
		break;
	case dns_zone_cache:
		REQUIRE(zone->rdclass == dns_rdataclass_none);
		REQUIRE(zone->database == NULL);
		break;
	}

	REQUIRE(zone->db_type != NULL);
}

dns_result_t
dns_zone_load(dns_zone_t *zone) {
	int soacount = 0;
	int nscount = 0;
	dns_result_t result;
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
	if (isc_stdtime_get(&now) != ISC_R_SUCCESS) {
		result = DNS_R_UNEXPECTED;
		goto cleanup;
	}

	switch (zone->type) {
	case dns_zone_forward:
	case dns_zone_none:
		result = DNS_R_SUCCESS;
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

	REQUIRE(zone->database != NULL);

	result = dns_db_create(zone->mctx, zone->db_type,
			       &zone->origin,
			       cache, zone->rdclass,
			       zone->db_argc, zone->db_argv, &db);

	if (result != DNS_R_SUCCESS)
		goto cleanup;

	result = dns_db_load(db, zone->database);

	/*
	 * Initiate zone transfer?  We may need a error code that
	 * indicates that the "permanent" form does not exist.
	 * XXX better error feedback to log.
	 */
	if (result != DNS_R_SUCCESS) {
		dns_zone_logerror(zone, "database %s: dns_db_load failed: %s",
				  zone->database,
				  dns_result_totext(result));
		goto cleanup;
	}

	/*
	 * Apply update log, if any.
	 */
	if (zone->ixfrlog != NULL) {
		result = dns_journal_rollforward(zone->mctx, db, zone->ixfrlog);
		if (result != DNS_R_SUCCESS && result != DNS_R_NOTFOUND &&
		    result != DNS_R_UPTODATE)
			goto cleanup;
		if (result == DNS_R_SUCCESS)
			zone->flags |= DNS_ZONE_F_NEEDDUMP;
	}

	/*
	 * Obtain ns and soa counts for top of zone.
	 */
	nscount = 0;
	soacount = 0;
	dns_db_currentversion(db, &version);
	result = dns_db_findnode(db, &zone->origin, ISC_FALSE, &node);

	if (result == DNS_R_SUCCESS) {
		dns_rdataset_init(&rdataset);
		result = dns_db_findrdataset(db, node, version,
					     dns_rdatatype_ns,
					     dns_rdatatype_none, 0, &rdataset,
					     NULL);
		if (result == DNS_R_SUCCESS) {
			result = dns_rdataset_first(&rdataset);
			while (result == DNS_R_SUCCESS) {
				nscount++;
				result = dns_rdataset_next(&rdataset);
			}
			dns_rdataset_disassociate(&rdataset);
		}
		result = dns_db_findrdataset(db, node, version,
					     dns_rdatatype_soa,
					     dns_rdatatype_none, 0, &rdataset,
					     NULL);

		if (result == DNS_R_SUCCESS) {
			result = dns_rdataset_first(&rdataset);
			while (result == DNS_R_SUCCESS) {
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
				dns_zone_logerror(zone,
						"has %d SOA record%s",
						soacount,
						(soacount != 0) ? "s" : "");
			if (nscount == 0)
				dns_zone_logerror(zone, "no NS records");
			result = DNS_R_BADZONE;
			goto cleanup;
		}
		if (zone->top != NULL) {
			if (!isc_serial_gt(soa.serial, zone->serial)) {
				dns_zone_logerror(zone,
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
			zone->expiretime = now /*XXX*/ + zone->expire;
			zone->refreshtime = now + zone->refresh /*XXX*/;
		}
		break;
	case dns_zone_hint:
		if (nscount == 0) {
			dns_zone_logerror(zone, "no NS records");
			result = DNS_R_BADZONE;
			goto cleanup;
		}
		break;
	case dns_zone_cache:
		break;
	default:
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "unexpected zone type %d", zone->type);
		result = DNS_R_UNEXPECTED;
		goto cleanup;
	}
	if (zone->top != NULL) {
		result = replacedb(zone, db, ISC_FALSE);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
	} else {
		dns_db_attach(db, &zone->top);
		zone->flags |= DNS_ZONE_F_LOADED;
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
	dns_result_t result;
	dns_rdata_ns_t ns;

	REQUIRE(DNS_ZONE_VALID(zone));
	/* XXX MPA */

	/*
	 * get NS list from database, add in notify also list
	 */
	zonename = &zone->origin;
	dns_db_currentversion(zone->top, &version);
	result = dns_db_findnode(zone->top, zonename, ISC_FALSE, &node);

	if (result == DNS_R_SUCCESS) {
		dns_rdataset_init(&rdataset);
		result = dns_db_findrdataset(zone->top, node, version,
					     dns_rdatatype_ns,
					     dns_rdatatype_none, 0, &rdataset,
					     NULL);
		if (result == DNS_R_SUCCESS) {
			result = dns_rdataset_first(&rdataset);
			while (result == DNS_R_SUCCESS) {
				dns_rdataset_current(&rdataset, &rdata);
				result = dns_rdata_tostruct(&rdata, &ns, zone->mctx);
				if (result != DNS_R_SUCCESS)
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
				checkservers->mctx = zone->mctx;
				dns_resolver_attach(zone->res, &checkservers->res);
				checkservers->fetch = NULL;
				ISC_LINK_INIT(checkservers, link);
				checkservers->magic = CHECKSERVERS_MAGIC;

				/* XXX lookup A/AAAA/A6 records */
				result = dns_rdataset_next(&rdataset);
			}
		}
		dns_rdataset_disassociate(&rdataset);
		dns_rdataset_invalidate(&rdataset);
	}
	dns_db_detachnode(zone->top, &node);
	dns_db_closeversion(zone->top, &version, ISC_FALSE);

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
		checkservers->mctx = zone->mctx;
		dns_resolver_attach(zone->res, &checkservers->res);
		checkservers->fetch = NULL;
		ISC_LINK_INIT(checkservers, link);
		checkservers->magic = CHECKSERVERS_MAGIC;
		ISC_LIST_APPEND(zone->checkservers, checkservers, link);
		dns_resolver_createfetch(zone->res, zonename, dns_rdatatype_ns,
				         NULL, NULL, NULL,
					 DNS_FETCHOPT_UNSHARED,
					 zone->task, checkservers_callback, 
					 checkservers, &checkservers->fetch);
	}
	UNLOCK(&zone->lock);
}
#endif

#ifdef notyet
static void
checkservers_callback(isc_task_t *task, isc_event_t *event) {
	dns_fetchdoneevent_t *devent = (dns_fetchdoneevent_t *)event;
	dns_zone_checkservers_t *checkservers = event->arg;
	dns_zone_state_t state;
	dns_zone_t *zone;
	dns_name_t *name;
	isc_mem_t *mctx;
	isc_sockaddr_t *address;
	dns_resolver_t *res;
	dns_message_t *msg; 
	char *master;

	REQUIRE(DNS_CHECKSERVERS_VALID(checkservers));
	state = checkservers->state;
	zone = checkservers->zone;
	name = &checkservers->server;
	address = &checkservers->address;
	mctx = checkservers->mctx;
	res = checkservers->res;

	task = task;	/* unused */

	master = isc_sockaddr_totext(&zone->masters[zone->curmaster],
				     zone->mctx);

	if (devent->result != DNS_R_SUCCESS) {
		/* timeout */
		switch (state) {
		case get_a6:
		case get_aaaa:
		case get_a:
			dns_zone_logerror(zone,
				       "unable to obtain address for (%s)");
			break;
		case get_ns:
		case get_soa:
			dns_zone_logerror(zone,
				"unable to obtain %s RRset from %s"
				);
		}
		goto cleanup;
	}

	msg = NULL;
	dns_resolver_getanswer(event, &msg);


	switch (state) {
	case get_a6:
		add_address_tocheck(msg, checkservers, dns_rdatatype_a6);
		dns_resolver_createfetch(res, name, dns_rdatatype_aaaa,
				         NULL, NULL, NULL, 0, zone->task,
					 checkservers_callback, 
					 checkservers, &checkservers->fetch);
		checkservers->state = get_aaaa;
		break;
	case get_aaaa:
		add_address_tocheck(msg, checkservers, dns_rdatatype_a6);
		dns_resolver_createfetch(res, name, dns_rdatatype_a,
				         NULL, NULL, NULL, 0, zone->task,
					 checkservers_callback, 
					 checkservers, &checkservers->fetch);
		checkservers->state = get_a;
		break;
	case get_a:
		add_address_tocheck(msg, checkservers, dns_rdatatype_a);
		/* make NS query to address */
		dns_resolver_createfetch(res, name, dns_rdatatype_ns,
				         NULL, NULL, NULL,
					 DNS_FETCHOPT_UNSHARED, 
					 zone->task, checkservers_callback, 
					 checkservers, &checkservers->fetch);
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
			dns_zone_logerror(zone,
				"server %s (%s) unexpected rcode = %.*s",
				rb.used, rcode);
			break;
		}
		if (msg->counts[DNS_SECTION_ANSWER] == 0) {
			if (referral(msg))
				dns_zone_logerror(zone,
					"server %s (%s) referral response");
			else
				dns_zone_logerror(zone,
				   "server %s (%s) type = %s NODATA response");
		}

		if ((msg->flags & DNS_MESSAGEFLAG_AA) == 0) {
			dns_zone_logerror(zone,
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
						 &checkservers->fetch);
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
}
#endif

#if 0
static void
cmp_soa(dns_message_t *msg, dns_zone_t *zone, char *server) {
	dns_rdata_soa_t msgsoa, zonesoa;
	dns_result_t result;
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
	if (result != DNS_R_SUCCESS) {
		dns_zone_logerror(zone,
				   "Unable to extract SOA from answer: %s",
				   server);
		return;
	}
	result = dns_rdataset_first(rdataset); 
	if (DNS_R_SUCCESS != result)
		return;
	dns_rdataset_current(rdataset, &rdata);
	result = dns_rdata_tostruct(&rdata, &msgsoa, zone->mctx);
	if (DNS_R_SUCCESS != result)
		return;
	result = dns_rdataset_next(rdataset);
	if (DNS_R_NOMORE != result) {
		dns_zone_logerror(zone,
				   "More that one SOA record returned: %s",
				   server);
		goto cleanup_msgsoa;
	}

	/*
	 * Get SOA record for zone.
	 */

	dns_rdataset_init(&zonerdataset);
	LOCK(&zone->lock);
	result = dns_db_find(zone->top, &zone->origin,
			     NULL, dns_rdatatype_soa, dns_rdatatype_none,
			     0, 0, NULL, NULL, &zonerdataset);
	UNLOCK(&zone->lock);
	if (result != DNS_R_SUCCESS) {
		/* XXXMPA */
		goto cleanup_msgsoa;
	}

	result = dns_rdataset_first(&zonerdataset); 
	if (DNS_R_SUCCESS != result)
		return;
	dns_rdataset_current(&zonerdataset, &rdata);
	result = dns_rdata_tostruct(&rdata, &msgsoa, zone->mctx);
	if (DNS_R_SUCCESS != result)
		return;
	result = dns_rdataset_next(&zonerdataset);
	if (DNS_R_NOMORE != result) {
		dns_zone_logerror(zone, "More that one SOA in zone");
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
			dns_zone_logerror(zone,
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

		dns_zone_logerror(zone, "SOA contents differ: %s",
				   server);
	}
 cleanup_zonesoa:
	dns_rdata_freestruct(&zonesoa);
 cleanup_msgsoa:
	dns_rdata_freestruct(&msgsoa);
}
#endif

static void
add_address_tocheck(dns_message_t *msg, dns_zone_checkservers_t *checkservers,
		    dns_rdatatype_t type)
{
	dns_rdataset_t *rdataset = NULL;
	dns_result_t result;
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
				 NULL, &rdataset) != DNS_R_SUCCESS)
		return;

	result = dns_rdataset_first(rdataset);
	while (DNS_R_SUCCESS == result) {
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

void
dns_zone_attach(dns_zone_t *source, dns_zone_t **target) {
	REQUIRE(DNS_ZONE_VALID(source));
	REQUIRE(target != NULL && *target == NULL);

	LOCK(&source->lock);
	REQUIRE(source->references > 0);
	source->references++;
#if 0
	PRINT_ZONE_REF(source);
#endif
	INSIST(source->references != 0xffffffffU);
	UNLOCK(&source->lock);
	*target = source;
}

void
dns_zone_print(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	PRINT_ZONE_REF(zone);
}

static dns_result_t
dns_zone_tostr(dns_zone_t *zone, isc_mem_t *mctx, char **s) {
	isc_buffer_t tbuf;
	char outbuf[1024];
	dns_result_t result;

	REQUIRE(s != NULL && *s == NULL);
	REQUIRE(DNS_ZONE_VALID(zone));

	isc_buffer_init(&tbuf, outbuf, sizeof(outbuf) - 1,
			ISC_BUFFERTYPE_TEXT);
	if (dns_name_countlabels(&zone->origin) > 0) {
		result = dns_name_totext(&zone->origin, ISC_FALSE, &tbuf);
		if (result == DNS_R_SUCCESS)
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
	return ((*s == NULL) ? DNS_R_NOMEMORY : DNS_R_SUCCESS);
}

void
dns_zone_detach(dns_zone_t **zonep) {
	dns_zone_t *zone;

	REQUIRE(zonep != NULL && DNS_ZONE_VALID(*zonep));

	zone = *zonep;
	LOCK(&zone->lock);
	REQUIRE(zone->references > 0);
	zone->references--;
#if 0
	PRINT_ZONE_REF(zone);
#endif
	UNLOCK(&zone->lock);
	if (zone->references == 0)
		zone_free(zone);
	*zonep = NULL;
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
	zone->setoptions |= option;
	UNLOCK(&zone->lock);
}

void
dns_zone_clearoption(dns_zone_t *zone, unsigned int option) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	zone->setoptions &= ~option;
	UNLOCK(&zone->lock);
}

void
dns_zone_getoptions(dns_zone_t *zone, unsigned int *options,
		    unsigned int *optionsmask)
{
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(options != NULL);
	REQUIRE(optionsmask != NULL);

	LOCK(&zone->lock);
	*options = zone->options;
	*optionsmask = zone->setoptions;
	UNLOCK(&zone->lock);
}

dns_result_t
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
	return (DNS_R_SUCCESS);

 cleanup:
	if (new != NULL)
		isc_mem_put(zone->mctx, new,
			    (zone->db_argc + 1) * sizeof *new);
	UNLOCK(&zone->lock);
	return (DNS_R_NOMEMORY);
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

dns_result_t
dns_zone_setxfrsource(dns_zone_t *zone, isc_sockaddr_t *xfrsource) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	zone->xfrsource = *xfrsource;
	UNLOCK(&zone->lock);

	return (DNS_R_SUCCESS);
}

isc_sockaddr_t *
dns_zone_getxfrsource(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return (&zone->xfrsource);
}

dns_result_t
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
	return (DNS_R_SUCCESS);

 cleanup:
	UNLOCK(&zone->lock);
	return (DNS_R_NOMEMORY);
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

dns_result_t
dns_zone_addmaster(dns_zone_t *zone, isc_sockaddr_t *master) {
	isc_sockaddr_t *new;
	REQUIRE(DNS_ZONE_VALID(zone));
	
	LOCK(&zone->lock);
	new = isc_mem_get(zone->mctx, (zone->masterscnt + 1) * sizeof *new);
	if (new == NULL) {
		UNLOCK(&zone->lock);
		return (DNS_R_NOMEMORY);
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
	return (DNS_R_SUCCESS);
}

void
dns_zone_clearmasters(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	while (DNS_ZONE_FLAG(zone, DNS_ZONE_F_REFRESH)) {
		UNLOCK(&zone->lock);
		cancel_refresh(zone);
		LOCK(&zone->lock);
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

dns_result_t
dns_zone_getdb(dns_zone_t *zone, dns_db_t **dpb) {
	dns_result_t result = DNS_R_SUCCESS;

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->top == NULL)
		result = DNS_R_NOTLOADED;
	else
		dns_db_attach(zone->top, dpb);
	UNLOCK(&zone->lock);

	return (result);
}

/*
 * Co-ordinates the starting of routine jobs.
 */
 
void
dns_zone_maintenance(dns_zone_t *zone) {
	isc_stdtime_t now;

	REQUIRE(DNS_ZONE_VALID(zone));
	fprintf(stderr, "dns_zone_maintenance\n");

	if (isc_stdtime_get(&now) != ISC_R_SUCCESS)
		return;

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
			dns_zone_dump(zone, stdout);
		}
		UNLOCK(&zone->lock);
		break;
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
		dns_zone_dump(zone, stdout); /* XXX */
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

	if (isc_stdtime_get(&now) != ISC_R_SUCCESS)
		return;

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
#ifdef notyet
	soa_query(zone, refresh_callback);
#endif
}

dns_result_t
dns_zone_dump(dns_zone_t *zone, FILE *fd) {
	dns_dbiterator_t *dbiterator = NULL;
	dns_dbversion_t *version = NULL;
	dns_result_t result;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_rdatasetiter_t *rdsiter = NULL;
	dns_dbnode_t *node = NULL;
	isc_buffer_t text;
	isc_region_t region;
	char *buf = NULL;
	unsigned int buflen = 1024;
	dns_rdataset_t rdataset;
	dns_db_t *top = NULL;

	REQUIRE(DNS_ZONE_VALID(zone));

	dns_fixedname_init(&fname);
	name = dns_fixedname_name(&fname);

	dns_db_attach(zone->top, &top);
	dns_db_currentversion(top, &version);
	result = dns_db_createiterator(top, ISC_FALSE, &dbiterator);
	if (result == DNS_R_SUCCESS)
		result = dns_dbiterator_first(dbiterator);
	while (result == DNS_R_SUCCESS) {
		result = dns_dbiterator_current(dbiterator, &node, name);
		if (result != DNS_R_SUCCESS && result != DNS_R_NEWORIGIN)
			break;
		result = dns_db_allrdatasets(zone->top, node, version, 0,
					     &rdsiter);
		if (result != DNS_R_SUCCESS) {
			dns_db_detachnode(top, &node);
			break;
		}
		dns_rdataset_init(&rdataset);
		result = dns_rdatasetiter_first(rdsiter);
		while (result == DNS_R_SUCCESS) {
			dns_rdatasetiter_current(rdsiter, &rdataset);
 retry:
			if (buf == NULL)
				buf = isc_mem_get(zone->mctx, buflen);
			if (buf == NULL)
				result = DNS_R_NOMEMORY;
			isc_buffer_init(&text, buf, buflen,
					ISC_BUFFERTYPE_TEXT);
			if (result == DNS_R_SUCCESS)
				result = dns_rdataset_totext(&rdataset, name,
							     ISC_FALSE,
							     ISC_FALSE, &text);
			if (result == DNS_R_NOSPACE) {
				isc_mem_put(zone->mctx, buf, buflen);
				buf = NULL;
				buflen += 1024;
				goto retry;
			}
			isc_buffer_used(&text, &region);
			if (result == DNS_R_SUCCESS)
				fprintf(fd, "%.*s", (int)region.length,
					(char *)region.base);
			dns_rdataset_disassociate(&rdataset);
			if (result == DNS_R_SUCCESS)
				result = dns_rdatasetiter_next(rdsiter);
		}
		dns_rdatasetiter_destroy(&rdsiter);
		dns_db_detachnode(top, &node);
		if (result == DNS_R_NOMORE)
			result = dns_dbiterator_next(dbiterator);
	}
	if (buf != NULL)
		isc_mem_put(zone->mctx, buf, buflen);
	dns_dbiterator_destroy(&dbiterator);
	dns_db_closeversion(top, &version, ISC_FALSE);
	dns_db_detach(&top);
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
	dns_db_detach(&zone->top);
	zone->flags &= ~DNS_ZONE_F_LOADED;
}


void
dns_zone_unmount(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	/*XXX MPA*/
}

dns_result_t
dns_zone_manage(dns_zone_t *zone, isc_taskmgr_t *tmgr) {
#if 1
	(void)zone;
	(void)tmgr;
	return (DNS_R_NOTIMPLEMENTED);
#else
	isc_result_t iresult;
	dns_result_t result;

	/*
	 * XXXRTH  Zones do not have resolvers!!!!
	 */

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(zone->task == NULL);
	REQUIRE(zone->timgr == NULL);

	iresult = isc_task_create(tmgr, zone->mctx, 0, &zone->task);
	if (iresult != ISC_R_SUCCESS) {
		/* XXX */
		return (DNS_R_UNEXPECTED);
	}
	iresult = isc_task_onshutdown(zone->task, zone_shutdown, zone);
	if (iresult != ISC_R_SUCCESS) {
		/* XXX */
		return (DNS_R_UNEXPECTED);
	}
	iresult = isc_timermgr_create(zone->mctx, &zone->timgr);
	if (iresult != ISC_R_SUCCESS) {
		/* XXX */
		return (DNS_R_UNEXPECTED);
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
			      4096, 1000, 1000, 4, &dispatch) == DNS_R_SUCCESS);
		result = dns_resolver_create(zone->mctx, tmgr, 10, zone->timgr,
				             zone->rdclass, dispatch,
					     &zone->res); 
		if (result != DNS_R_SUCCESS)
			return (result);

		dns_dispatch_detach(&dispatch);
		isc_socket_detach(&s);
	}

	dns_zone_maintenance(zone);
	return (DNS_R_SUCCESS);
#endif
}

void
dns_zone_setrefresh(dns_zone_t *zone, isc_uint32_t refresh,
		    isc_uint32_t retry)
{
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->refresh = refresh;
	zone->retry = retry;
}

void
dns_zone_notify(dns_zone_t *zone) {
	unsigned int i;
	dns_name_t *origin = NULL;
	isc_sockaddr_t addr;
	dns_rdataset_t nsrdset;
	dns_rdataset_t ardset;
	dns_dbversion_t *version = NULL;
	dns_result_t result;
	dns_dbnode_t *node = NULL;
	dns_rdata_ns_t ns;
	dns_rdata_in_a_t a;
	dns_rdata_t rdata;

	REQUIRE(DNS_ZONE_VALID(zone));

	if (!DNS_ZONE_OPTION(zone, DNS_ZONE_O_NOTIFY))
		return;

	origin = &zone->origin;

	/*
	 * Enqueue notify request.
	 */
	for (i = 0; i < zone->notifycnt; i++) {
		(void)dns_notify(origin, &zone->notify[i], dns_rdatatype_soa,
			         zone->rdclass, &zone->xfrsource, zone->mctx);
	}

	dns_db_currentversion(zone->top, &version);
	result = dns_db_findnode(zone->top, origin, ISC_FALSE, &node);
	if (result != DNS_R_SUCCESS)
		goto cleanup1;

	dns_rdataset_init(&nsrdset);
	result = dns_db_findrdataset(zone->top, node, version,
				     dns_rdatatype_ns,
				     dns_rdatatype_none, 0, &nsrdset, NULL);
	if (result != DNS_R_SUCCESS)
		goto cleanup2;
	
	result = dns_rdataset_first(&nsrdset);
	while (result == DNS_R_SUCCESS) {
		dns_rdataset_current(&nsrdset, &rdata);
		result = dns_rdata_tostruct(&rdata, &ns, zone->mctx);
		if (result != DNS_R_SUCCESS)
			continue;
		/*
		 * Look up address records.
		 */
		/* XXX MPA */

		if (result == DNS_R_NOTFOUND) {
			/*
			 * Query for address.
			 * Arrange for notify to be sent when
			 * we have it.
			 */
			/* XXX MPA*/

			result = dns_rdataset_next(&nsrdset);
			continue;
		} else if (result != DNS_R_SUCCESS) {
			result = dns_rdataset_next(&nsrdset);
			continue;
		}
		result = dns_rdataset_first(&ardset);
		while (result == DNS_R_SUCCESS) {
			dns_rdataset_current(&ardset, &rdata);
			result = dns_rdata_tostruct(&rdata, &a, zone->mctx);
			if (result != DNS_R_SUCCESS)
				continue;
			/*
			 * Remove duplicates w/ notify list.
			 */
			isc_sockaddr_fromin(&addr, &a.in_addr, 0);
			for (i = 0; i < zone->notifycnt; i++) {
				if (isc_sockaddr_equal(&zone->notify[i], &addr))
					break;
			}
			if (i == zone->notifycnt) {
				(void)dns_notify(origin, &addr,
						 dns_rdatatype_soa,
						 zone->rdclass,
						 &zone->xfrsource, zone->mctx);
			}
			result = dns_rdataset_next(&ardset);
		}
		result = dns_rdataset_next(&nsrdset);
	}

	dns_rdataset_disassociate(&nsrdset);
 cleanup2:
	dns_db_detachnode(zone->top, &node);
 cleanup1:
	dns_db_closeversion(zone->top, &version, ISC_FALSE);
}

/***
 *** Private
 ***/

static void
refresh_callback(isc_task_t *task, isc_event_t *event) {
#if 1
	(void)task;
	(void)event;
#else
	dns_fetchevent_t *devent = (dns_fetchevent_t *)event;
	dns_zone_t *zone;
	dns_message_t *msg = NULL;
	isc_uint32_t soacnt, cnamecnt, soacount, nscount;
	isc_stdtime_t now;
	char *master;
	char *unknown = "<UNKNOWN>";
	dns_rdataset_t *rdataset;
	dns_rdata_t rdata;
	dns_rdata_soa_t soa;
	dns_result_t result;
	isc_uint32_t serial;

	zone = devent->arg;
	INSIST(DNS_ZONE_VALID(zone));

	/*
	 * if timeout log and next master;
	 */

	master = isc_sockaddr_totext(&zone->masters[zone->curmaster],
				     zone->mctx);
	if (master == NULL)
		master = unknown;
		
	if (devent->result != DNS_R_SUCCESS) {
		dns_zone_logerror(zone, "refresh: failure for %s: %s",
				   master, dns_result_totext(devent->result));
		goto next_master;
	}

	dns_resolver_getanswer(event, &msg);

	/*
	 * Unexpected rcode.
	 */
	if (msg->rcode != dns_rcode_noerror) {
		char rcode[128];
		isc_buffer_t rb;

		isc_buffer_init(&rb, rcode, sizeof rcode, ISC_BUFFERTYPE_TEXT);
		dns_rcode_totext(msg->rcode, &rb);

		dns_zone_logerror(zone,
				   "refresh: unexpected rcode (%.*s) from %s\n",
			           rb.used, rcode, master);
		goto next_master;
	}
	/*
	 * if non-auth log and next master;
	 */
	if ((msg->flags & DNS_MESSAGEFLAG_AA) == 0) {
		dns_zone_logerror(zone,
			"refresh: non-authorative answer from %s", master);
		goto next_master;
	}
	/*
	 * There should not be a CNAME record at top of zone.
	 */
	cnamecnt = message_count(msg, DNS_SECTION_ANSWER, dns_rdatatype_cname);
	soacnt = message_count(msg, DNS_SECTION_ANSWER, dns_rdatatype_soa);

	if (cnamecnt != 0) {
		dns_zone_logerror(zone,
			"refresh: CNAME discovered: master %s", master);
		goto next_master;
	}

	if (soacnt != 1) {
		dns_zone_logerror(zone,
				   "refresh: SOA count (%d) != 1: master %s",
				   soacnt, master);
		goto next_master;
	}

	nscount = message_count(msg, DNS_SECTION_AUTHORITY, dns_rdatatype_ns);
	soacount = message_count(msg, DNS_SECTION_AUTHORITY, dns_rdatatype_soa);

	/*
	 * if referral log and next master;
	 */
	if (soacnt == 0 && soacount == 0 && nscount != 0) {
		dns_zone_logerror(zone,
			"refresh: referral: master %s", master);
		goto next_master;
	}

	/*
	 * if nodata log and next master;
	 */
	if (soacnt == 0 && nscount == 0) {
		dns_zone_logerror(zone, "refresh: NODATA: master %s", master);
		goto next_master;
	}

	/*
	 * Extract serial
	 */
	rdataset = NULL;
	result = dns_message_findname(msg, DNS_SECTION_ANSWER, &zone->origin,
				      dns_rdatatype_soa, dns_rdatatype_none,
				      NULL, &rdataset);
	if (result != DNS_R_SUCCESS) {
		dns_zone_logerror(zone, "refresh: unable to get soa record");
		goto next_master;
	}

	result = dns_rdataset_first(rdataset);
	if (result != DNS_R_SUCCESS) {
		dns_zone_logerror(zone, "refresh: dns_rdataset_first failed");
		goto next_master;
	}

	dns_rdataset_current(rdataset, &rdata);
	result = dns_rdata_tostruct(&rdata, &soa, zone->mctx);
	if (result != DNS_R_SUCCESS) {
		dns_zone_logerror(zone, "refresh: dns_rdata_tostruct failed");
		goto next_master;
	}

	serial = soa.serial;
	dns_rdata_freestruct(&soa);

	if (!DNS_ZONE_FLAG(zone, DNS_ZONE_F_LOADED) ||
	    isc_serial_gt(serial, zone->serial)) {
		dns_zone_transfer_in(zone);
		isc_event_free(&event);
		dns_resolver_destroyfetch(zone->res, &zone->fetch);
	} else if (isc_serial_eq(soa.serial, zone->serial)) {
		dns_zone_uptodate(zone);
		goto next_master;
	} else {
		goto next_master;
	}
	if (master != unknown)
		isc_mem_put(zone->mctx, master, strlen(master) + 1);
	return;

 next_master:
	LOCK(&zone->lock);
	if (master != unknown)
		isc_mem_put(zone->mctx, master, strlen(master) + 1);
	isc_event_free(&event);
	dns_resolver_destroyfetch(zone->res, &zone->fetch);
	zone->curmaster++;
	if (zone->curmaster >= zone->masterscnt) {
		zone->flags &= ~DNS_ZONE_F_REFRESH;

		if (isc_stdtime_get(&now) != ISC_R_SUCCESS)
			return;
		zone_settimer(zone, now);
		UNLOCK(&zone->lock);
		return;
	}
	UNLOCK(&zone->lock);
	soa_query(zone, refresh_callback);
	return;
#endif
}

#ifdef notyet
static void
soa_query(dns_zone_t *zone, isc_taskaction_t callback) {
	dns_name_t *zonename;
	dns_result_t result;

	zonename = &zone->origin;
	LOCK(&zone->lock);
	result = dns_resolver_createfetch(zone->res, zonename,
					  dns_rdatatype_soa,
					  NULL, NULL, NULL,
					  DNS_FETCHOPT_UNSHARED,
					  zone->task, callback, zone,
					  &zone->fetch);
	UNLOCK(&zone->lock);
	if (result != DNS_R_SUCCESS)
		cancel_refresh(zone);
}
#endif

static void
zone_shutdown(isc_task_t *task, isc_event_t *event) {
	dns_zone_t *zone = (dns_zone_t *)event->arg;
	isc_event_free(&event);
	task = task; /* XXX */
	zone = zone; /* XXX */
}

static void
zone_timer(isc_task_t *task, isc_event_t *event) {
	dns_zone_t *zone = (dns_zone_t *)event->arg;
	fprintf(stderr, "zone_timer\n");
	dns_zone_maintenance(zone);
	isc_event_free(&event);
	task = task; /* XXX */
}

static dns_result_t
zone_settimer(dns_zone_t *zone, isc_stdtime_t now) {
	isc_stdtime_t next = 0;
	isc_time_t expires;
	isc_interval_t interval;
	isc_result_t iresult;

	REQUIRE(DNS_ZONE_VALID(zone));

	switch (zone->type) {
	case dns_zone_master:
		if (DNS_ZONE_FLAG(zone, DNS_ZONE_F_NEEDDUMP))
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
	case dns_zone_stub:
		if (!DNS_ZONE_FLAG(zone, DNS_ZONE_F_REFRESH))
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
	fprintf(stdout, "settimer %d %d = %d seconds\n",
		next, now, next - now);

	if (next == 0) {
		if (zone->timer != NULL)
			isc_timer_detach(&zone->timer);
	} else {
		isc_time_settoepoch(&expires);

		if (next <= now)
			isc_interval_set(&interval, 0, 1);
		else 
			isc_interval_set(&interval, next - now, 0);

		if (zone->timer != NULL) {
			iresult = isc_timer_reset(zone->timer,
						  isc_timertype_once,
						  &expires, &interval,
						  ISC_TRUE);

		} else {
			iresult = isc_timer_create(zone->timgr,
						   isc_timertype_once,
						   &expires, &interval,
						   zone->task, zone_timer,
						   zone, &zone->timer);
		}
		if (iresult != ISC_R_SUCCESS) {
			/* XXX */
			return (DNS_R_UNEXPECTED);
		}
	}
	return (DNS_R_SUCCESS);
}

void
cancel_refresh(dns_zone_t *zone) {
	isc_stdtime_t now;

	REQUIRE(DNS_ZONE_VALID(zone));
	/* XXX MPA*/
	LOCK(&zone->lock);
	zone->flags &= ~DNS_ZONE_F_REFRESH;
	UNLOCK(&zone->lock);

	if (isc_stdtime_get(&now) != ISC_R_SUCCESS)
		return;
	if (!DNS_ZONE_FLAG(zone, DNS_ZONE_F_EXITING))
		zone_settimer(zone, now);
}

static dns_result_t
dns_notify(dns_name_t *name, isc_sockaddr_t *addr, dns_rdatatype_t type,
	   dns_rdataclass_t rdclass, isc_sockaddr_t *source, isc_mem_t *mctx)
{
	dns_message_t *msg = NULL;
	dns_result_t result;
	isc_buffer_t target;
	/* dns_rdatalist_t *rdatalist = NULL; */
	dns_rdatalist_t rdatalist;
	dns_rdataset_t *rdataset = NULL;
	char buf[512];

	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &msg);
	if (result != DNS_R_SUCCESS)
		return (result);

	msg->opcode = dns_opcode_notify;
	msg->rdclass = rdclass;
	msg->id = htons(3456); /* XXX */

	/* result = dns_message_gettemprdatalist(msg, &rdatalist); */
	ISC_LIST_INIT(rdatalist.rdata);
	ISC_LINK_INIT(&rdatalist, link);
	rdatalist.type = type;
	rdatalist.rdclass = rdclass;
	rdatalist.ttl = 0;

	result = dns_message_gettemprdataset(msg, &rdataset);
	if (result != DNS_R_SUCCESS)
		goto cleanup;
	dns_rdataset_init(rdataset);
	dns_rdatalist_tordataset(&rdatalist, rdataset);
	ISC_LIST_APPEND(name->list, rdataset, link);
	dns_message_addname(msg, name, DNS_SECTION_QUESTION);
	isc_buffer_init(&target, buf, sizeof buf,  ISC_BUFFERTYPE_BINARY);
	result = dns_message_renderbegin(msg, &target);
	if (result != DNS_R_SUCCESS)
		goto cleanup;
	result = dns_message_rendersection(msg, DNS_SECTION_QUESTION, 0, 0);
	if (result != DNS_R_SUCCESS)
		goto cleanup;
	result = dns_message_rendersection(msg, DNS_SECTION_ANSWER, 0, 0);
	if (result != DNS_R_SUCCESS)
		goto cleanup;
	result = dns_message_rendersection(msg, DNS_SECTION_AUTHORITY, 0, 0);
	if (result != DNS_R_SUCCESS)
		goto cleanup;
	result = dns_message_rendersection(msg, DNS_SECTION_ADDITIONAL, 0, 0);
	if (result != DNS_R_SUCCESS)
		goto cleanup;

	/* XXX TSIG here */
	result = dns_message_renderend(msg);
	if (result != DNS_R_SUCCESS)
		goto cleanup;

	/* XXX Queue for sending */
	addr = addr; /* XXX */
	source = source; /* XXX */
 cleanup:
	dns_message_destroy(&msg);
	return (result);
}

dns_result_t
dns_zone_notifyreceive(dns_zone_t *zone, isc_sockaddr_t *from,
		       dns_message_t *msg)
{
	unsigned int i;
	dns_rdata_soa_t soa;
	dns_rdataset_t *rdataset = NULL;
	dns_rdata_t rdata;
	dns_result_t result;

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
	 * completes. Return DNS_R_SUCCESS.
	 *
	 * Otherwise initiate a refresh check using 'from' as the
	 * first address to check.  Return DNS_R_SUCCESS.
	 */

	/*
	 *  We only handle NOTIFY (SOA) at the present.
	 */
	LOCK(&zone->lock);
	if (msg->counts[DNS_SECTION_QUESTION] != 0 ||
	    dns_message_findname(msg, DNS_SECTION_QUESTION, &zone->origin,
				 dns_rdatatype_soa, dns_rdatatype_none,
				 NULL, NULL) != DNS_R_SUCCESS) {
		UNLOCK(&zone->lock);
		return (DNS_R_REFUSED);
	}

	for (i = 0; i < zone->masterscnt; i++)
		if (isc_sockaddr_equal(from, &zone->masters[i]))
			break;

	if (i >= zone->masterscnt) {
		UNLOCK(&zone->lock);
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
		if (result == DNS_R_SUCCESS)
			result = dns_rdataset_first(rdataset);
		if (result == DNS_R_SUCCESS) {
			isc_uint32_t serial = 0;

			dns_rdataset_current(rdataset, &rdata);
			result = dns_rdata_tostruct(&rdata, &soa, zone->mctx);
			if (result == DNS_R_SUCCESS) {
				serial = soa.serial;
				dns_rdata_freestruct(&soa);
				if (isc_serial_le(serial, zone->serial))
					return (DNS_R_SUCCESS);
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
		return (DNS_R_SUCCESS);
	}
	UNLOCK(&zone->lock);
	dns_zone_refresh(zone);
	return (DNS_R_SUCCESS);
}

/*
 *	Copy / translate zone configuration data to dns_zone_t.
 */
dns_result_t
dns_zone_copy(isc_log_t *lctx, dns_c_ctx_t *ctx, dns_c_zone_t *czone,
	      dns_zone_t *zone) {
	isc_result_t iresult;
	dns_result_t result;
	isc_boolean_t boolean;
	const char *filename = NULL;
	const char *ixfr = NULL;
	dns_c_ipmatchlist_t *acl = 0;
	dns_c_severity_t severity;
	dns_c_iplist_t *iplist = NULL;
	dns_c_pubkey_t *pubkey = NULL;
	isc_uint32_t i;
	isc_sockaddr_t sockaddr;
	isc_int32_t size;
	isc_int32_t xfrtime;
	in_port_t port;
	const char *origin;
	char *o;
	isc_sockaddr_t sockaddr_any;

	ctx = ctx;	/* unused */

	isc_sockaddr_fromin6(&sockaddr_any, &in6addr_any, 0);
	dns_zone_setclass(zone, czone->zclass);

	origin = NULL;
	result = dns_c_zone_getname(lctx, czone, &origin);
	if (result != DNS_R_SUCCESS)
		return (result);

	o = isc_mem_strdup(zone->mctx, origin);
	if (o == NULL)
		return (DNS_R_NOMEMORY);

	result = dns_zone_setorigin(zone, o);
	isc_mem_free(zone->mctx, o);
	if (result != DNS_R_SUCCESS)
		return (result);

	/* XXX needs to be an zone option */
	result = dns_zone_setdbtype(zone, "rbt");
	if (result != DNS_R_SUCCESS)
		return (result);

	switch (czone->ztype) {
	case dns_c_zone_master:
		dns_zone_settype(zone, dns_zone_master);
		iresult = dns_c_zone_getfile(lctx, czone, &filename);
		if (iresult != ISC_R_SUCCESS)
			return (iresult);

		result = dns_zone_setdatabase(zone, filename);
		if (result != DNS_R_SUCCESS)
			return (iresult);

		iresult = dns_c_zone_getchecknames(lctx, czone, &severity);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setchecknames(zone, severity);
		else
			dns_zone_setchecknames(zone, dns_c_severity_fail);

		iresult = dns_c_zone_getallowupd(lctx, czone, &acl);
		if (iresult == ISC_R_SUCCESS) {
			dns_zone_setupdateacl(zone, acl);
			dns_c_ipmatchlist_delete(lctx, &acl);
		} else
			dns_zone_clearupdateacl(zone);

		iresult = dns_c_zone_getallowquery(lctx, czone, &acl);
		if (iresult == ISC_R_SUCCESS) {
			dns_zone_setqueryacl(zone, acl);
			dns_c_ipmatchlist_delete(lctx, &acl);
		} else
			dns_zone_clearqueryacl(zone);

		iresult = dns_c_zone_getallowtransfer(lctx, czone, &acl);
		if (iresult == ISC_R_SUCCESS) {
			dns_zone_setxfracl(zone, acl);
			dns_c_ipmatchlist_delete(lctx, &acl);
		} else
			dns_zone_clearxfracl(zone);

		iresult = dns_c_zone_getdialup(lctx, czone, &boolean);
		if (iresult == ISC_R_SUCCESS)  
			dns_zone_setoption(zone, DNS_ZONE_O_DIALUP, boolean);
		else
			dns_zone_clearoption(zone, DNS_ZONE_O_DIALUP);

		iresult = dns_c_zone_getnotify(lctx, czone, &boolean);
		if (iresult == ISC_R_SUCCESS)  
			dns_zone_setoption(zone, DNS_ZONE_O_NOTIFY, boolean);
		else
			dns_zone_clearoption(zone, DNS_ZONE_O_NOTIFY);

		iresult = dns_c_zone_getalsonotify(lctx, czone, &iplist);
		if (iresult == ISC_R_SUCCESS) {
			for (i = 0; i < iplist->nextidx; i++) {
				result = dns_zone_addnotify(zone,
							    &iplist->ips[i]);
				if (result != DNS_R_SUCCESS)
					return (result);
			}
		} else
			dns_zone_clearnotify(zone);

		iresult = dns_c_zone_getixfrbase(lctx, czone, &ixfr);
		if (iresult == ISC_R_SUCCESS) {
			result = dns_zone_setixfrlog(zone, ixfr);
			if (result != DNS_R_SUCCESS)
				return (result);
			zone->diff_on_reload = ISC_TRUE;
		} else
			zone->diff_on_reload = ISC_FALSE;

		czone->u.mzone.ixfr_tmp;	/*XXX*/
		iresult = dns_c_zone_getmaxixfrlog(lctx, czone, &size);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setixfrlogsize(zone, size);

		iresult = dns_c_zone_getmaintixfrbase(lctx, czone, &boolean);
		if (result == ISC_R_SUCCESS)
			zone->diff_on_reload = boolean;
		else
			zone->diff_on_reload = ISC_TRUE;

		iresult = dns_c_zone_getpubkey(lctx, czone, &pubkey);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setpubkey(zone, pubkey);
		else
			dns_zone_setpubkey(zone, NULL);
		break;

	case dns_c_zone_forward:
#ifdef notyet
		/*
		 * forward zones are still in a state of flux
		 */
		czone->u.fzone.check_names; /* XXX unused in BIND 8 */
		czone->u.fzone.forward; /* XXX*/
		czone->u.fzone.forwarders; /* XXX*/
#endif
		break;

	case dns_c_zone_slave:
		dns_zone_settype(zone, dns_zone_slave);
		iresult = dns_c_zone_getfile(lctx, czone, &filename);
		if (iresult != ISC_R_SUCCESS)
			return (iresult);
		result = dns_zone_setdatabase(zone, filename);
		if (result != DNS_R_SUCCESS)
			return (iresult);

		iresult = dns_c_zone_getchecknames(lctx, czone, &severity);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setchecknames(zone, severity);
		else
			dns_zone_setchecknames(zone, dns_c_severity_warn);

		iresult = dns_c_zone_getallowquery(lctx, czone, &acl);
		if (iresult == ISC_R_SUCCESS) {
			dns_zone_setqueryacl(zone, acl);
			dns_c_ipmatchlist_delete(lctx, &acl);
		} else
			dns_zone_clearqueryacl(zone);

		iresult = dns_c_zone_getpubkey(lctx, czone, &pubkey);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setpubkey(zone, pubkey);
		else
			dns_zone_setpubkey(zone, NULL);

		iresult = dns_c_zone_getmasterport(lctx, czone, &port);
		if (iresult != ISC_R_SUCCESS)
			port = 53;
		dns_zone_setmasterport(zone, port);

		iresult = dns_c_zone_getmasterips(lctx, czone, &iplist);
		if (iresult == ISC_R_SUCCESS) {
			for (i = 0; i < iplist->nextidx; i++) {
				result = dns_zone_addmaster(zone,
							    &iplist->ips[i]);
				if (result != DNS_R_SUCCESS)
					return (result);
			}
		} else 
			dns_zone_clearmasters(zone);

		iresult = dns_c_zone_getmaintixfrbase(lctx, czone, &boolean);
		if (result == ISC_R_SUCCESS)
			zone->diff_on_reload = boolean;
		else
			zone->diff_on_reload = ISC_FALSE;

		iresult = dns_c_zone_getmaxtranstimein(lctx, czone, &xfrtime);
		if (result == ISC_R_SUCCESS)
			zone->xfrtime = xfrtime;
		else
			zone->xfrtime = MAX_XFER_TIME;

		iresult = dns_c_zone_gettransfersource(lctx, czone, &sockaddr);
		if (iresult == ISC_R_SUCCESS)
			zone->xfrsource = sockaddr;
		else
			zone->xfrsource = sockaddr_any;

		break;

	case dns_c_zone_stub:
		dns_zone_settype(zone, dns_zone_stub);
		iresult = dns_c_zone_getfile(lctx, czone, &filename);
		if (iresult != ISC_R_SUCCESS)
			return (iresult);
		result = dns_zone_setdatabase(zone, filename);
		if (result != DNS_R_SUCCESS)
			return (iresult);

		iresult = dns_c_zone_getchecknames(lctx, czone, &severity);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setchecknames(zone, severity);
		else
			dns_zone_setchecknames(zone, dns_c_severity_warn);

		iresult = dns_c_zone_getallowquery(lctx, czone, &acl);
		if (iresult == ISC_R_SUCCESS) {
			dns_zone_setqueryacl(zone, acl);
			dns_c_ipmatchlist_delete(lctx, &acl);
		} else
			dns_zone_clearqueryacl(zone);

		iresult = dns_c_zone_getpubkey(lctx, czone, &pubkey);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setpubkey(zone, pubkey);
		else
			dns_zone_setpubkey(zone, NULL);

		iresult = dns_c_zone_getmasterport(lctx, czone, &port);
		if (iresult != ISC_R_SUCCESS)
			port = 53;
		dns_zone_setmasterport(zone, port);

		iresult = dns_c_zone_getmasterips(lctx, czone, &iplist);
		if (iresult == ISC_R_SUCCESS) {
			for (i = 0; i < iplist->nextidx; i++) {
				result = dns_zone_addmaster(zone,
							    &iplist->ips[i]);
				if (result != DNS_R_SUCCESS)
					return (result);
			}
		} else 
			dns_zone_clearmasters(zone);

		iresult = dns_c_zone_getmaxtranstimein(lctx, czone, &xfrtime);
		if (result == ISC_R_SUCCESS)
			zone->xfrtime = xfrtime;
		else
			zone->xfrtime = MAX_XFER_TIME;

		iresult = dns_c_zone_gettransfersource(lctx, czone, &sockaddr);
		if (iresult == ISC_R_SUCCESS)
			zone->xfrsource = sockaddr;
		else
			zone->xfrsource = sockaddr_any;

		break;

	case dns_c_zone_hint:
		dns_zone_settype(zone, dns_zone_hint);
		iresult = dns_c_zone_getfile(lctx, czone, &filename);
		if (iresult != ISC_R_SUCCESS)
			return (iresult);
		result = dns_zone_setdatabase(zone, filename);
		if (result != DNS_R_SUCCESS)
			return (result);

		iresult = dns_c_zone_getchecknames(lctx, czone, &severity);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setchecknames(zone, severity);
		else
			dns_zone_setchecknames(zone, dns_c_severity_fail);

		iresult = dns_c_zone_getpubkey(lctx, czone, &pubkey);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setpubkey(zone, pubkey);
		else
			dns_zone_setpubkey(zone, NULL);
		break;
	}

	return (DNS_R_SUCCESS);
}

void
dns_zone_setqueryacl(dns_zone_t *zone, dns_c_ipmatchlist_t *acl) {

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->query_acl != NULL)
		dns_c_ipmatchlist_delete(NULL /* isc_log_t */,
					 &zone->query_acl);
	zone->query_acl = dns_c_ipmatchlist_attach(NULL /* isc_log_t */,
						   acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_setupdateacl(dns_zone_t *zone, dns_c_ipmatchlist_t *acl) {

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->update_acl != NULL)
		dns_c_ipmatchlist_delete(NULL /* isc_log_t */,
					 &zone->update_acl);
	zone->update_acl = dns_c_ipmatchlist_attach(NULL /* isc_log_t */,
						    acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_setxfracl(dns_zone_t *zone, dns_c_ipmatchlist_t *acl) {

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->xfr_acl != NULL)
		dns_c_ipmatchlist_delete(NULL /* isc_log_t */,
					 &zone->xfr_acl);
	zone->xfr_acl = dns_c_ipmatchlist_attach(NULL /* isc_log_t */,
						 acl);
	UNLOCK(&zone->lock);
}

dns_c_ipmatchlist_t *
dns_zone_getqueryacl(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->query_acl);
}

dns_c_ipmatchlist_t *
dns_zone_getupdateacl(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->update_acl);
}

dns_c_ipmatchlist_t *
dns_zone_getxfracl(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->xfr_acl);
}

void
dns_zone_clearupdateacl(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->update_acl != NULL)
		dns_c_ipmatchlist_delete(NULL /* isc_log_t */,
					 &zone->update_acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_clearqueryacl(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->query_acl != NULL)
		dns_c_ipmatchlist_delete(NULL /* isc_log_t */,
					 &zone->query_acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_clearxfracl(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK(&zone->lock);
	if (zone->xfr_acl != NULL)
		dns_c_ipmatchlist_delete(NULL /* isc_log_t */,
					 &zone->xfr_acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_setchecknames(dns_zone_t *zone, dns_c_severity_t severity) {

	REQUIRE(DNS_ZONE_VALID(zone));

	zone->check_names = severity;
}

dns_c_severity_t
dns_zone_getchecknames(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->check_names);
}

void
dns_zone_setpubkey(dns_zone_t *zone, dns_c_pubkey_t *pubkey) {

	REQUIRE(DNS_ZONE_VALID(zone));

	zone->pubkey = pubkey;		/* XXX should be an attach */
}

dns_c_pubkey_t *
dns_zone_getpubkey(dns_zone_t *zone) {

	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->pubkey);
}

void
dns_zone_setixfrlogsize(dns_zone_t *zone, isc_int32_t size) {
	
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->ixfrlogsize = size;
}

isc_int32_t
dns_zone_getixfrlogsize(dns_zone_t *zone) {
	
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->ixfrlogsize);
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
dns_zone_logerror(dns_zone_t *zone, const char *fmt, ...) {
	va_list ap;
	char message[4096];
	char namebuf[1024];
	isc_buffer_t buffer;
	int len;
	dns_result_t result;

	isc_buffer_init(&buffer, namebuf, sizeof namebuf, ISC_BUFFERTYPE_TEXT);
	result = dns_name_totext(&zone->origin, ISC_TRUE, &buffer);
	if (result == DNS_R_SUCCESS)
		len = buffer.used;
	else
		len = 0;

	va_start(ap, fmt);
	vsnprintf(message, sizeof message, fmt, ap);
	va_end(ap);
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
		      DNS_LOGMODULE_ZONE, ISC_LOG_ERROR,
		      "zone %.*s: %s", len, namebuf, message);
}

static int
message_count(dns_message_t *msg, dns_section_t section, dns_rdatatype_t type) {
	dns_result_t result;
	dns_name_t *name;
	dns_rdataset_t *curr;
	int res = 0;

	result = dns_message_firstname(msg, section);
	while (result == DNS_R_SUCCESS) {
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
dns_zone_setxfrtime(dns_zone_t *zone, isc_uint32_t xfrtime) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(xfrtime != 0);
	zone->xfrtime = xfrtime;
}

isc_uint32_t
dns_zone_getxfrtime(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->xfrtime);
}

void
dns_zone_transfer_in(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	fprintf(stdout, "dns_zone_transfer_in\n");
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

	return (zone->database);
}

const char *
dns_zone_getixfrlog(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return (zone->ixfrlog);
}

#if 0
/*
 * XXX should become isc_sockaddr_fromaddr() once dns_c_addr_t -> isc
 */
static void
sockaddr_fromaddr(isc_sockaddr_t *sockaddr, dns_c_addr_t *a,
		  in_port_t port) {
	switch (a->type.sa.sa_family) {
	case AF_INET:
		isc_sockaddr_fromin(sockaddr, &a->type.sin.sin_addr, port);
		break;
	case AF_INET6:
		isc_sockaddr_fromin6(sockaddr, &a->type.sin6.sin6_addr, port);
		break;
	default:
		INSIST(0);
	}
}
#endif

static void
record_serial() {
}

isc_boolean_t
dns_zone_equal(dns_zone_t *oldzone, dns_zone_t *newzone) {
	unsigned int i;

	REQUIRE(DNS_ZONE_VALID(oldzone));
	REQUIRE(DNS_ZONE_VALID(newzone));

	LOCK(&oldzone->lock);
	LOCK(&newzone->lock);
	if (oldzone->type != newzone->type ||
	    oldzone->xfrtime != newzone->xfrtime ||
	    oldzone->rdclass != newzone->rdclass ||
	    oldzone->db_argc != newzone->db_argc ||
	    oldzone->notifycnt != newzone->notifycnt ||
	    oldzone->masterscnt != newzone->masterscnt ||
	    oldzone->masterport != newzone->masterport ||
	    oldzone->check_names != newzone->check_names ||
	    oldzone->diff_on_reload != newzone->diff_on_reload ||
	    oldzone->ixfrlogsize != newzone->ixfrlogsize)
		goto false;

	if (!dns_name_equal(&oldzone->origin, &newzone->origin))
		goto false;

	if ((oldzone->updatelog == NULL && newzone->updatelog != NULL) ||
	    (oldzone->updatelog != NULL && newzone->updatelog == NULL) ||
	    (oldzone->updatelog != NULL &&
	     strcmp(oldzone->updatelog, newzone->updatelog) != 0))
		goto false;

	if ((oldzone->journal == NULL && newzone->journal != NULL) ||
	    (oldzone->journal != NULL && newzone->journal == NULL) ||
	    (oldzone->journal != NULL &&
	     strcmp(oldzone->journal, newzone->journal) != 0))
		goto false;

	if ((oldzone->ixfrlog == NULL && newzone->ixfrlog != NULL) ||
	    (oldzone->ixfrlog != NULL && newzone->ixfrlog == NULL) ||
	    (oldzone->ixfrlog != NULL &&
	     strcmp(oldzone->ixfrlog, newzone->ixfrlog) != 0))
		goto false;

	if ((oldzone->options & oldzone->setoptions) !=
	    (newzone->options & newzone->setoptions))
		goto false;

	if ((oldzone->db_type == NULL && newzone->db_type != NULL) ||
	    (oldzone->db_type != NULL && newzone->db_type == NULL) ||
	    (oldzone->db_type != NULL &&
	     strcmp(oldzone->db_type, newzone->db_type) != 0))
		goto false;

	for (i = 0; i < oldzone->db_argc; i++)
		if (strcmp(oldzone->db_argv[i], newzone->db_argv[i]) != 0)
			goto false;

	if (!isc_sockaddr_equal(&oldzone->xfrsource, &newzone->xfrsource))
		goto false;

	for (i = 0; i < oldzone->notifycnt; i++)
		if (!isc_sockaddr_equal(&oldzone->notify[i],
					&newzone->notify[i]))
			goto false;

	for (i = 0; i < oldzone->masterscnt; i++)
		if (!isc_sockaddr_equal(&oldzone->masters[i],
					&newzone->masters[i]))
			goto false;

	if (!dns_c_ipmatchlist_equal(oldzone->update_acl, newzone->update_acl))
			goto false;

	if (!dns_c_ipmatchlist_equal(oldzone->query_acl, newzone->query_acl))
			goto false;

	if (!dns_c_ipmatchlist_equal(oldzone->xfr_acl, newzone->xfr_acl))
			goto false;

	if (!dns_c_pubkey_equal(oldzone->pubkey, newzone->pubkey))
			goto false;

	UNLOCK(&newzone->lock);
	UNLOCK(&oldzone->lock);
	return(ISC_TRUE);	/* XXX should be ISC_TRUE once acl/pubkey
				   checks are done. */

 false:
	UNLOCK(&newzone->lock);
	UNLOCK(&oldzone->lock);
	return (ISC_FALSE);
}


dns_result_t
dns_zone_replacedb(dns_zone_t *zone, dns_db_t *db, isc_boolean_t dump) {
	dns_result_t result;
	
	REQUIRE(DNS_ZONE_VALID(zone));
	LOCK(&zone->lock);
	result = replacedb(zone, db, dump);
	UNLOCK(&zone->lock);
	return (result);
}

static dns_result_t
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
	if (zone->top != NULL && zone->ixfrlog != NULL &&
	    zone->diff_on_reload) {
		printf("generating diffs\n");
		result = dns_db_diff(zone->mctx, 
					db, ver,
					zone->top, NULL /* XXX */,
					zone->ixfrlog);
		if (result != DNS_R_SUCCESS)
			goto fail;
	} else {
		if (dump) {
			printf("dumping new version\n");
			/* XXX should use temporary file and rename */
			result = dns_db_dump(db, ver, zone->database);
			if (result != DNS_R_SUCCESS)
				goto fail;
		}
		if (zone->ixfrlog != NULL) {
			/* XXXRTH log instead: printf("unlinking journal\n"); */
			(void) remove(zone->ixfrlog);
		}
	}
	dns_db_closeversion(db, &ver, ISC_FALSE);

#if 0
	printf("replacing database...\n");
#endif
	if (zone->top != NULL)
		dns_db_detach(&zone->top);
	dns_db_attach(db, &zone->top);
	zone->flags |= DNS_ZONE_F_LOADED;
	return (DNS_R_SUCCESS);
	
 fail:
	dns_db_closeversion(db, &ver, ISC_FALSE);
	return (result);
}

/***
 ***	Zone manager. 
 ***/

static void
xfrin_start_temporary_kludge(dns_zone_t *zone) {
	isc_sockaddr_t sa;
	in_port_t port;
	if (zone->masterscnt < 1)
		return;
	port = zone->masterport; 
	if (port == 0)
		port = 53; /* XXX is this the right place? */
	isc_sockaddr_fromin(&sa, &zone->masters[0].type.sin.sin_addr,
			    port);
#ifdef notyet
	ns_xfrin_start(zone, &sa);
#endif
}

isc_result_t
dns_zonemgr_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		   isc_timermgr_t *timermgr, dns_zonemgr_t **zmgrp)
{
	dns_zonemgr_t *zmgr;
	isc_result_t result;

	zmgr = isc_mem_get(mctx, sizeof *zmgr);
	if (zmgr == NULL)
		return (ISC_R_NOMEMORY);
	zmgr->mctx = mctx;
	zmgr->taskmgr = taskmgr;
	zmgr->timermgr = timermgr;
	zmgr->zonetasks = NULL;
	zmgr->soaquery.task = NULL;
	ISC_LIST_INIT(zmgr->zones);

	/* Create the zone task pool. */
	result = isc_taskpool_create(taskmgr, mctx, 
				     8 /* XXX */, 0, &zmgr->zonetasks);
	if (result != ISC_R_SUCCESS)
		goto failure;

	/* Create a single task for queueing of SOA queries. */
	result = isc_task_create(taskmgr, mctx, 1, &zmgr->soaquery.task);
	if (result != ISC_R_SUCCESS)
		goto failure;

	*zmgrp = zmgr;
	return (ISC_R_SUCCESS);
 failure:
	dns_zonemgr_destroy(&zmgr);
	return (result);
}

isc_result_t
dns_zonemgr_managezone(dns_zonemgr_t *zmgr, dns_zone_t *zone) {
	isc_result_t result;
	
	REQUIRE(zone->task == NULL);
	REQUIRE(zone->timer == NULL);

	isc_taskpool_gettask(zmgr->zonetasks,
			     dns_name_hash(dns_zone_getorigin(zone),
					   ISC_FALSE),
			     &zone->task);
#ifdef notyet
	result = isc_timer_create(zmgr->timermgr, isc_timertype_inactive,
				  NULL, NULL,
				  zmgr->soaquery.task, soa_query_wanted, zone,
				  &zone->timer);
#else
	result = ISC_R_SUCCESS;
#endif
	ISC_LIST_APPEND(zmgr->zones, zone, link);

	/* XXX more? */
	if (result != ISC_R_SUCCESS)
		goto failure;

 failure:
	return (result);
}


isc_result_t
dns_zonemgr_forcemaint(dns_zonemgr_t *zmgr) {
	dns_zone_t *p;
	for (p = ISC_LIST_HEAD(zmgr->zones);
	     p != NULL;
	     p = ISC_LIST_NEXT(p, link))
	{
		if (p->type == dns_zone_slave)
			xfrin_start_temporary_kludge(p);
	}
	return (ISC_R_SUCCESS);
}

void
dns_zonemgr_destroy(dns_zonemgr_t **zmgrp) {
	dns_zonemgr_t *zmgr = *zmgrp;
	if (zmgr->soaquery.task != NULL)
		isc_task_destroy(&zmgr->soaquery.task);
	if (zmgr->zonetasks != NULL)
		isc_taskpool_destroy(&zmgr->zonetasks);
	isc_mem_put(zmgr->mctx, zmgr, sizeof *zmgr);
	*zmgrp = NULL;
}
