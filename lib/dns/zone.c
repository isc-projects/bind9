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

 /* $Id: zone.c,v 1.13 1999/09/24 05:57:54 gson Exp $ */

#include <config.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <../isc/util.h> /* XXX MPA */
#include <isc/timer.h>
#include <isc/print.h>
#include <isc/serial.h>

#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/master.h>
#include <dns/message.h>
#include <dns/rdata.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatastruct.h>
#include <dns/rdatalist.h>
#include <dns/rcode.h>

/* XXX remove once config changes are in place */
#define dns_zone_uptodate(x) dns_zone_logerror(x, "dns_zone_uptodate")
#define referral(x) ISC_FALSE

#include <dns/zone.h>
#include <dns/confparser.h>
#include <dns/resolver.h>
#include <dns/dispatch.h>

#include <stdarg.h>

#define ZONE_MAGIC_USED	0x5a4f4e45U
#define ZONE_MAGIC_FREE	0x7a6f6e65U
#define CHECKSERVERS_MAGIC 0x43484346U

#define VALID_ZONE(zone) \
	((zone) != NULL && (zone)->magic == ZONE_MAGIC_USED)
#define VALID_ZONE_FREE(zone) \
	((zone) != NULL && (zone)->magic == ZONE_MAGIC_FREE)
#define VALID_CHECKSERVERS(server) \
	((server != NULL) && (server)->magic == CHECKSERVERS_MAGIC)

#ifndef DNS_GLOBAL_OPTION	/* XXX MPA */
#define DNS_GLOBAL_OPTION(o) 0
#endif

#define DEFAULT_REFRESH	900	/*XXX*/
#define DEFAULT_RETRY 300	/*XXX*/
#define MAX_XFER_TIME 3600	/*XXX*/

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
	isc_timermgr_t		*timgr;
	isc_timer_t		*timer;
	unsigned int		references;
	dns_fixedname_t		origin;
	char 			*database;
	char 			*ixfrlog;	/*
						 * XXX merge w/ updatelog to
						 * locate transaction log
						 */
	char 			*updatelog;
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
	isc_int16_t		masterport;
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
static void sockaddr_fromaddr(isc_sockaddr_t *sockaddr, dns_c_addr_t *a,
			      unsigned int port);
static void add_address_tocheck(dns_message_t *msg,
				dns_zone_checkservers_t *checkservers,
				dns_rdatatype_t type);
extern void dns_zone_transfer_in(dns_zone_t *zone);
static void record_serial(void);



/***
 ***	Public functions.
 ***/

dns_result_t
dns_zone_create(dns_zone_t **zonep, isc_mem_t *mctx) {
	isc_result_t iresult;
	dns_zone_t *zone;

	REQUIRE(zonep != NULL && *zonep == NULL);
	REQUIRE(mctx != NULL);

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
	zone->timgr = NULL;
	zone->references = 1;		/* Implicit attach. */
	dns_fixedname_init(&zone->origin);
	zone->database = NULL;
	zone->ixfrlog = NULL;
	zone->ixfrlogsize = -1;
	zone->updatelog = NULL;
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
#ifdef notyet
	/* XXX */
	zone->xfrsource = isc_sockaddr_any;
#endif
	zone->xfrtime = MAX_XFER_TIME;
	zone->magic = ZONE_MAGIC_USED;
	*zonep = zone;
	return (DNS_R_SUCCESS);
}

static void
zone_free(dns_zone_t *zone) {

	REQUIRE(VALID_ZONE(zone));
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
		dns_resolver_destroyfetch(&zone->fetch, zone->task);
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
	REQUIRE(VALID_ZONE(zone));
	REQUIRE(rdclass != dns_rdataclass_none);
	REQUIRE(zone->rdclass == dns_rdataclass_none ||
		zone->rdclass == rdclass);
	zone->rdclass = rdclass;
}

/*
 *	Single shot.
 */
void
dns_zone_settype(dns_zone_t *zone, dns_zonetype_t type) {
	REQUIRE(VALID_ZONE(zone));
	REQUIRE(type != dns_zone_none);
	REQUIRE(zone->type == dns_zone_none || zone->type == type);
	zone->type = type;
}

dns_result_t
dns_zone_setdbtype(dns_zone_t *zone, char *db_type) {
	REQUIRE(VALID_ZONE(zone));

	if (zone->db_type != NULL)
		isc_mem_free(zone->mctx, zone->db_type);
	zone->db_type = isc_mem_strdup(zone->mctx, db_type);
	if (zone->db_type == NULL)
		return (DNS_R_NOMEMORY);
	return (DNS_R_SUCCESS);
}

dns_result_t
dns_zone_setorigin(dns_zone_t *zone, char *origin) {
	isc_buffer_t buffer;

	REQUIRE(VALID_ZONE(zone));
	REQUIRE(origin != NULL);

	dns_fixedname_init(&zone->origin);
	isc_buffer_init(&buffer, origin, strlen(origin), ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&buffer, strlen(origin));
	return (dns_name_fromtext(dns_fixedname_name(&zone->origin),
			  	  &buffer, dns_rootname, ISC_FALSE, NULL));
}

dns_result_t
dns_zone_setdatabase(dns_zone_t *zone, const char *database) {
	REQUIRE(VALID_ZONE(zone));
	REQUIRE(database != NULL);

	if (zone->database != NULL)
		isc_mem_free(zone->mctx, zone->database);
	zone->database = isc_mem_strdup(zone->mctx, database);
	if (zone->database == NULL)
		return (DNS_R_NOMEMORY);
	return (DNS_R_SUCCESS);
}

dns_result_t
dns_zone_setupdatelog(dns_zone_t *zone, char *updatelog) {
	REQUIRE(VALID_ZONE(zone));
	REQUIRE(updatelog != NULL);

	if (zone->updatelog != NULL)
		isc_mem_free(zone->mctx, zone->updatelog);
	zone->updatelog = isc_mem_strdup(zone->mctx, updatelog);
	if (zone->updatelog == NULL)
		return (DNS_R_NOMEMORY);
	return (DNS_R_SUCCESS);
}

dns_result_t
dns_zone_setixfrlog(dns_zone_t *zone, const char *ixfrlog) {
	REQUIRE(VALID_ZONE(zone));
	REQUIRE(ixfrlog != NULL);

	if (zone->ixfrlog != NULL)
		isc_mem_free(zone->mctx, zone->ixfrlog);
	zone->ixfrlog = isc_mem_strdup(zone->mctx, ixfrlog);
	if (zone->ixfrlog == NULL)
		return (DNS_R_NOMEMORY);
	return (DNS_R_SUCCESS);
}

void
dns_zone_validate(dns_zone_t *zone) {
	REQUIRE(VALID_ZONE(zone));
	REQUIRE(dns_name_countlabels(dns_fixedname_name(&zone->origin)) != 0);
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

	REQUIRE(VALID_ZONE(zone));

	if (isc_stdtime_get(&now) != ISC_R_SUCCESS) {
		/*XXX*/
		return (DNS_R_UNEXPECTED);
	}

	switch (zone->type) {
	case dns_zone_forward:
	case dns_zone_none:
		return (DNS_R_SUCCESS);
	case dns_zone_master:
	case dns_zone_slave:
	case dns_zone_stub:
	case dns_zone_hint:
		cache = ISC_FALSE;
		break;
	case dns_zone_cache:
		cache = ISC_TRUE;
		break;
	}

	result = dns_db_create(zone->mctx, zone->db_type,
			       dns_fixedname_name(&zone->origin),
			       cache, zone->rdclass,
			       zone->db_argc, zone->db_argv, &zone->top);

	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_db_load(zone->top, zone->database);
	/*
	 * XXX Initiate zone transfer?  We may need a error code that
	 * indicates that the "permanent" form does not exist.
	 */
	if (result != DNS_R_SUCCESS)
		return (result);
	/*
	 * XXX apply update log to zone.
	 */

	/*
	 * Obtain ns and soa counts for top of zone.
	 */
	nscount = 0;
	soacount = 0;
	dns_db_currentversion(zone->top, &version);
	result = dns_db_findnode(zone->top, dns_fixedname_name(&zone->origin),
				 ISC_FALSE, &node);

	if (result == DNS_R_SUCCESS) {
		dns_rdataset_init(&rdataset);
		result = dns_db_findrdataset(zone->top, node, version,
					     dns_rdatatype_ns,
					     dns_rdatatype_none, 0, &rdataset,
					     NULL);
		if (result == DNS_R_SUCCESS) {
			result = dns_rdataset_first(&rdataset);
			while (result == DNS_R_SUCCESS) {
				nscount++;
				result = dns_rdataset_next(&rdataset);
			}
		}

		dns_rdataset_disassociate(&rdataset);
		result = dns_db_findrdataset(zone->top, node, version,
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
		}
		dns_rdataset_disassociate(&rdataset);
		dns_rdataset_invalidate(&rdataset);
	}
	dns_db_detachnode(zone->top, &node);
	dns_db_closeversion(zone->top, &version, ISC_FALSE);

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
			if (soacount != 0)
				dns_rdata_freestruct(&soa);
			return (DNS_R_BADZONE);
		}
		zone->serial = soa.serial;
		zone->refresh = soa.refresh;
		zone->retry = soa.retry;
		zone->expire = soa.expire;
		zone->minimum = soa.minimum;
		if (zone->type == dns_zone_slave ||
		    zone->type == dns_zone_stub) {
			zone->expiretime = now /*XXX*/ + zone->expire;
			zone->refreshtime = now + zone->refresh /*XXX*/;
		}
		break;
	case dns_zone_hint:
		if (nscount == 0) {
			if (soacount != 0)
				dns_rdata_freestruct(&soa);
			return (DNS_R_BADZONE);
		}
		break;
	case dns_zone_cache:
		break;
	default:
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "unexpected zone type %d", zone->type);
		if (soacount != 0)
			dns_rdata_freestruct(&soa);
		return (DNS_R_UNEXPECTED);
	}
	zone->flags |= DNS_ZONE_F_LOADED;
	if (soacount != 0)
		dns_rdata_freestruct(&soa);
	return (DNS_R_SUCCESS);
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

	REQUIRE(VALID_ZONE(zone));
	/* XXX MPA */

	/*
	 * get NS list from database, add in notify also list
	 */
	zonename = dns_fixedname_name(&zone->origin);
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

	REQUIRE(VALID_CHECKSERVERS(checkservers));
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
void
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
				      dns_fixedname_name(&zone->origin),
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
	result = dns_db_find(zone->top, dns_fixedname_name(&zone->origin),
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

	REQUIRE(VALID_ZONE(zone));
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
	REQUIRE(VALID_ZONE(zone));
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
	REQUIRE(VALID_ZONE(zone));
	/*
	 * For each glue record in this zone, check with an authorative
	 * server for the zone to ensure that there have not been any
	 * changes.
	 */
}

void
dns_zone_attach(dns_zone_t *source, dns_zone_t **target) {
	REQUIRE(VALID_ZONE(source));
	REQUIRE(target != NULL && *target == NULL);

	LOCK(&source->lock);
	REQUIRE(source->references > 0);
	source->references++;
	INSIST(source->references != 0xffffffffU);
	UNLOCK(&source->lock);
	*target = source;
}

void
dns_zone_detach(dns_zone_t **zonep) {
	dns_zone_t *zone;

	REQUIRE(zonep != NULL && VALID_ZONE(*zonep));

	zone = *zonep;
	LOCK(&zone->lock);
	REQUIRE(zone->references > 0);
	zone->references--;
	UNLOCK(&zone->lock);
	if (zone->references == 0)
		zone_free(zone);
	*zonep = NULL;
}

void
dns_zone_setflag(dns_zone_t *zone, unsigned int flags, isc_boolean_t value) {
	REQUIRE(VALID_ZONE(zone));

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
	REQUIRE(VALID_ZONE(zone));

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
	REQUIRE(VALID_ZONE(zone));

	LOCK(&zone->lock);
	zone->setoptions &= ~option;
	UNLOCK(&zone->lock);
}

void
dns_zone_getoptions(dns_zone_t *zone, unsigned int *options,
		    unsigned int *optionsmask)
{
	REQUIRE(VALID_ZONE(zone));
	REQUIRE(options != NULL);
	REQUIRE(optionsmask != NULL);
	*options = zone->options;
	*optionsmask = zone->setoptions;
}

dns_result_t
dns_zone_adddbarg(dns_zone_t *zone, char *arg) {
	char **new;
	REQUIRE(VALID_ZONE(zone));
	REQUIRE(arg != NULL);

	/*
	 * Allocate new 'db_argv' and set last to be copy of 'arg'.
	 */
	new = isc_mem_get(zone->mctx, (zone->db_argc + 1) * sizeof *new);
	if (new == NULL)
		return (DNS_R_NOMEMORY);
	new[zone->db_argc] = isc_mem_strdup(zone->mctx, arg);
	if (new[zone->db_argc] == NULL) {
		isc_mem_put(zone->mctx, new,
			    (zone->db_argc + 1) * sizeof *new);
		return (DNS_R_NOMEMORY);
	}

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
	return (DNS_R_SUCCESS);
}

void
dns_zone_cleardbargs(dns_zone_t *zone) {
	unsigned int i;

	REQUIRE(VALID_ZONE(zone));

	if (zone->db_argc) {
		for (i = 0 ; i < zone->db_argc; i++)
			isc_mem_free(zone->mctx, zone->db_argv[i]);
		isc_mem_put(zone->mctx, zone->db_argv,
			    zone->db_argc * sizeof *zone->db_argv);
		zone->db_argc = 0;
		zone->db_argv = NULL;
	}
}

dns_result_t
dns_zone_setxfrsource(dns_zone_t *zone, isc_sockaddr_t *xfrsource) {
	REQUIRE(VALID_ZONE(zone));
	zone->xfrsource = *xfrsource;
	return (DNS_R_SUCCESS);
}

isc_sockaddr_t *
dns_zone_getxfrsource(dns_zone_t *zone) {
	REQUIRE(VALID_ZONE(zone));
	return (&zone->xfrsource);
}

dns_result_t
dns_zone_addnotify(dns_zone_t *zone, isc_sockaddr_t *notify) {
	isc_sockaddr_t *new;
	REQUIRE(VALID_ZONE(zone));
	
	new = isc_mem_get(zone->mctx, (zone->notifycnt + 1) * sizeof *new);
	if (new == NULL)
		return (DNS_R_NOMEMORY);
	new[zone->notifycnt] = *notify;
	if (zone->notifycnt > 0) {
		memcpy(new, zone->notify, zone->notifycnt * sizeof *new);
		isc_mem_put(zone->mctx, zone->notify,
			    zone->notifycnt * sizeof *new);
	}
	zone->notify = new;
	zone->notifycnt++;
	return (DNS_R_SUCCESS);
}

void
dns_zone_clearnotify(dns_zone_t *zone) {
	REQUIRE(VALID_ZONE(zone));

	if (zone->notify == NULL)
		return;

	isc_mem_put(zone->mctx, zone->notify,
		    zone->notifycnt * sizeof *zone->notify);
	zone->notify = NULL;
	zone->notifycnt = 0;
}

dns_result_t
dns_zone_addmaster(dns_zone_t *zone, isc_sockaddr_t *master) {
	isc_sockaddr_t *new;
	REQUIRE(VALID_ZONE(zone));
	
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
	REQUIRE(VALID_ZONE(zone));

	LOCK(&zone->lock);
	while (DNS_ZONE_FLAG(zone, DNS_ZONE_F_REFRESH)) {
		UNLOCK(&zone->lock);
		cancel_refresh(zone);
		LOCK(&zone->lock);
	}
	if (zone->masters == NULL) {
		UNLOCK(&zone->lock);
		return;
	}

	isc_mem_put(zone->mctx, zone->masters,
		    zone->masterscnt * sizeof *zone->masters);
	zone->masters = NULL;
	zone->masterscnt = 0;
	zone->curmaster = 0;
	UNLOCK(&zone->lock);
}

dns_db_t *
dns_zone_getdb(dns_zone_t *zone) {

	REQUIRE(VALID_ZONE(zone));

	return (zone->top);
}

/*
 * Co-ordinates the starting of routine jobs.
 */
 
void
dns_zone_maintenance(dns_zone_t *zone) {
	isc_stdtime_t now;

	REQUIRE(VALID_ZONE(zone));
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
			dns_zone_expire(zone);
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
		if (now >= zone->refreshtime &&
		    !DNS_ZONE_FLAG(zone, DNS_ZONE_F_REFRESH))
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
	REQUIRE(VALID_ZONE(zone));

	if (DNS_ZONE_FLAG(zone, DNS_ZONE_F_NEEDDUMP))
		dns_zone_dump(zone, stdout); /* XXX */
	zone->flags |= DNS_ZONE_F_EXPIRED;
	dns_zone_setrefresh(zone, DEFAULT_REFRESH, DEFAULT_RETRY);
	dns_zone_unload(zone);
}

void
dns_zone_refresh(dns_zone_t *zone) {
	isc_stdtime_t now;

	REQUIRE(VALID_ZONE(zone));
	REQUIRE(zone->masterscnt > 0);

	if (isc_stdtime_get(&now) != ISC_R_SUCCESS)
		return;

	/*
	 * Set DNS_ZONE_F_REFRESH so that there is only one refresh operation
	 * in progress at the one time.
	 */

	LOCK(&zone->lock);
	zone->flags |= DNS_ZONE_F_REFRESH;
	UNLOCK(&zone->lock);

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

	REQUIRE(VALID_ZONE(zone));

	dns_fixedname_init(&fname);
	name = dns_fixedname_name(&fname);

	dns_db_currentversion(zone->top, &version);
	result = dns_db_createiterator(zone->top, ISC_FALSE, &dbiterator);
	if (result == DNS_R_SUCCESS)
		result = dns_dbiterator_first(dbiterator);
	while (result == DNS_R_SUCCESS) {
		result = dns_dbiterator_current(dbiterator, &node, name);
		if (result != DNS_R_SUCCESS && result != DNS_R_NEWORIGIN)
			break;
		result = dns_db_allrdatasets(zone->top, node, version, 0,
					     &rdsiter);
		if (result != DNS_R_SUCCESS) {
			dns_db_detachnode(zone->top, &node);
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
		dns_db_detachnode(zone->top, &node);
		if (result == DNS_R_NOMORE)
			result = dns_dbiterator_next(dbiterator);
	}
	if (buf != NULL)
		isc_mem_put(zone->mctx, buf, buflen);
	dns_dbiterator_destroy(&dbiterator);
	dns_db_closeversion(zone->top, &version, ISC_FALSE);
	return (result);
}

void
dns_zone_unload(dns_zone_t *zone) {
	REQUIRE(VALID_ZONE(zone));

	dns_db_detach(&zone->top);
	zone->flags &= ~DNS_ZONE_F_LOADED;
}

void
dns_zone_unmount(dns_zone_t *zone) {
	REQUIRE(VALID_ZONE(zone));
	/*XXX MPA*/
}

dns_result_t
dns_zone_manage(dns_zone_t *zone, isc_taskmgr_t *tmgr) {
	isc_result_t iresult;
	dns_result_t result;

	/*
	 * XXXRTH  Zones do not have resolvers!!!!
	 */

#if 0
	REQUIRE(VALID_ZONE(zone));
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

	return (DNS_R_NOTIMPLEMENTED);
}

void
dns_zone_setrefresh(dns_zone_t *zone, isc_uint32_t refresh,
		    isc_uint32_t retry)
{
	REQUIRE(VALID_ZONE(zone));
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

	REQUIRE(VALID_ZONE(zone));

	if (!DNS_ZONE_OPTION(zone, DNS_ZONE_O_NOTIFY))
		return;

	origin = dns_fixedname_name(&zone->origin);

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
	dns_fetchdoneevent_t *devent = (dns_fetchdoneevent_t *)event;
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
	INSIST(VALID_ZONE(zone));

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
	result = dns_message_findname(msg, DNS_SECTION_ANSWER, 
				      dns_fixedname_name(&zone->origin),
				      dns_rdatatype_soa,
				      dns_rdatatype_none, NULL, &rdataset);
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
		dns_resolver_destroyfetch(&zone->fetch, task);
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
	dns_resolver_destroyfetch(&zone->fetch, task);
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
#ifdef notyet
	soa_query(zone, refresh_callback);
#endif
	return;
}

#ifdef notyet
static void
soa_query(dns_zone_t *zone, isc_taskaction_t callback) {
	dns_name_t *zonename;
	dns_result_t result;

	zonename = dns_fixedname_name(&zone->origin);
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

	REQUIRE(VALID_ZONE(zone));

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

	REQUIRE(VALID_ZONE(zone));
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

	REQUIRE(VALID_ZONE(zone));

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
	    dns_message_findname(msg, DNS_SECTION_QUESTION,
				 dns_fixedname_name(&zone->origin),
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
					      dns_fixedname_name(&zone->origin),
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

isc_result_t
dns_zone_callback(dns_c_ctx_t *ctx, dns_c_zone_t *zone, void *uap) {
	
	/*
	 * Find zone in mount table.
	 */
	return (ISC_R_NOTIMPLEMENTED);
}
/*
 *	Copy / translate zone configuration data to dns_zone_t.
 */
dns_result_t
dns_zone_copy(dns_c_ctx_t *ctx, dns_c_zone_t *czone, dns_zone_t *zone) {
	isc_result_t iresult;
	dns_result_t result;
	isc_boolean_t boolean;
	const char *filename = NULL;
	const char *ixfr = NULL;
	dns_c_ipmatchlist_t *acl;
	dns_c_severity_t severity;
	dns_c_iplist_t *iplist = NULL;
	dns_c_pubkey_t *pubkey = NULL;
	isc_uint32_t i;
	dns_c_addr_t addr;
	isc_int32_t size;
	isc_int32_t port;
	isc_int32_t xfrtime;

	ctx = ctx;	/* unused */

	switch (czone->ztype) {
	case dns_c_zone_master:
		iresult = dns_c_zone_getfile(czone, &filename);
		if (iresult != ISC_R_SUCCESS)
			return (iresult);

		result = dns_zone_setdatabase(zone, filename);
		if (result != DNS_R_SUCCESS)
			return (iresult);

		iresult = dns_c_zone_getchecknames(czone, &severity);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setchecknames(zone, severity);
		else
			dns_zone_setchecknames(zone, dns_c_severity_fail);

		acl = NULL;
		iresult = dns_c_zone_getallowupd(czone, &acl);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setupdateacl(zone, acl);
		else
			dns_zone_clearupdateacl(zone);

		acl = NULL;
		iresult = dns_c_zone_getallowquery(czone, &acl);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setqueryacl(zone, acl);
		else
			dns_zone_clearqueryacl(zone);

		acl = NULL;
		iresult = dns_c_zone_getallowtransfer(czone, &acl);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setxfracl(zone, acl);
		else
			dns_zone_clearxfracl(zone);

		iresult = dns_c_zone_getdialup(czone, &boolean);
		if (iresult == ISC_R_SUCCESS)  
			dns_zone_setoption(zone, DNS_ZONE_O_DIALUP, boolean);
		else
			dns_zone_clearoption(zone, DNS_ZONE_O_DIALUP);

		iresult = dns_c_zone_getnotify(czone, &boolean);
		if (iresult == ISC_R_SUCCESS)  
			dns_zone_setoption(zone, DNS_ZONE_O_NOTIFY, boolean);
		else
			dns_zone_clearoption(zone, DNS_ZONE_O_NOTIFY);

		iresult = dns_c_zone_getalsonotify(czone, &iplist);
		if (iresult == ISC_R_SUCCESS) {
			for (i = 0; i < iplist->nextidx; i++) {
				isc_sockaddr_t s;

				sockaddr_fromaddr(&s, &iplist->ips[i], 0);
				result = dns_zone_addnotify(zone, &s);
				if (result != DNS_R_SUCCESS)
					return (result);
			}
		} else
			dns_zone_clearnotify(zone);

		iresult = dns_c_zone_getixfrbase(czone, &ixfr);
		if (iresult == ISC_R_SUCCESS) {
			result = dns_zone_setixfrlog(zone, ixfr);
			if (result != DNS_R_SUCCESS)
				return (result);
		}

		czone->u.mzone.ixfr_tmp;	/*XXX*/
		iresult = dns_c_zone_getmaxixfrlog(czone, &size);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setixfrlogsize(zone, size);
		czone->u.mzone.maint_ixfr_base;	/*XXX*/

		iresult = dns_c_zone_getpubkey(czone, &pubkey);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setpubkey(zone, pubkey);
		else
			dns_zone_setpubkey(zone, NULL);
		break;

	case dns_c_zone_slave:
		iresult = dns_c_zone_getfile(czone, &filename);
		if (iresult != ISC_R_SUCCESS)
			return (iresult);
		result = dns_zone_setdatabase(zone, filename);
		if (result != DNS_R_SUCCESS)
			return (iresult);

		iresult = dns_c_zone_getchecknames(czone, &severity);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setchecknames(zone, severity);
		else
			dns_zone_setchecknames(zone, dns_c_severity_warn);

		acl = NULL;
		iresult = dns_c_zone_getallowupd(czone, &acl);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setupdateacl(zone, acl);
		else
			dns_zone_clearupdateacl(zone);

		acl = NULL;
		iresult = dns_c_zone_getallowquery(czone, &acl);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setqueryacl(zone, acl);
		else
			dns_zone_clearqueryacl(zone);

		acl = NULL;
		iresult = dns_c_zone_getallowtransfer(czone, &acl);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setxfracl(zone, acl);
		else
			dns_zone_clearxfracl(zone);

		iresult = dns_c_zone_getdialup(czone, &boolean);
		if (iresult == ISC_R_SUCCESS)  
			dns_zone_setoption(zone, DNS_ZONE_O_DIALUP, boolean);
		else
			dns_zone_clearoption(zone, DNS_ZONE_O_DIALUP);

		/* notify is off by default for slave zones */
		iresult = dns_c_zone_getnotify(czone, &boolean);
		if (iresult == ISC_R_SUCCESS)  
			dns_zone_setoption(zone, DNS_ZONE_O_NOTIFY, boolean);
		else
			dns_zone_setoption(zone, DNS_ZONE_O_NOTIFY, ISC_FALSE);

		iresult = dns_c_zone_getalsonotify(czone, &iplist);
		if (iresult == ISC_R_SUCCESS) {
			for (i = 0; i < iplist->nextidx; i++) {
				isc_sockaddr_t s;

				sockaddr_fromaddr(&s, &iplist->ips[i], 0);
				result = dns_zone_addnotify(zone, &s);
				if (result != DNS_R_SUCCESS)
					return (result);
			}
		} else
			dns_zone_clearnotify(zone);

		iresult = dns_c_zone_getixfrbase(czone, &ixfr);
		if (iresult == ISC_R_SUCCESS) {
			result = dns_zone_setixfrlog(zone, ixfr);
			if (result != DNS_R_SUCCESS)
				return (result);
		}
		/* czone->u.szone.ixfr_tmp;	XXX*/
		iresult = dns_c_zone_getmaxixfrlog(czone, &size);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setixfrlogsize(zone, size);
		czone->u.szone.maint_ixfr_base;	/*XXX*/

		iresult = dns_c_zone_getpubkey(czone, &pubkey);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setpubkey(zone, pubkey);
		else
			dns_c_zone_getpubkey(czone, NULL);

		/*
		 * should master port be seperate or just applied to 
		 * isc_sockaddr_t's
		 */
		iresult = dns_c_zone_getmasterport(czone, &port);
		if (iresult != ISC_R_SUCCESS)
			port = 53;
		dns_zone_setmasterport(zone, port);

		iresult = dns_c_zone_getmasterips(czone, &iplist);
		if (iresult == ISC_R_SUCCESS) {
			for (i = 0; i < iplist->nextidx; i++) {
				isc_sockaddr_t s;

				sockaddr_fromaddr(&s, &iplist->ips[i], port);
				result = dns_zone_addmaster(zone, &s);
				if (result != DNS_R_SUCCESS)
					return (result);
			}
		} else
			dns_zone_clearmasters(zone);

		iresult = dns_c_zone_gettransfersource(czone, &addr);
		if (iresult == ISC_R_SUCCESS) {
			isc_sockaddr_t s;

			sockaddr_fromaddr(&s, &addr, 0);
			result = dns_zone_setxfrsource(zone, &s);
			if (result != DNS_R_SUCCESS)
				return (result);
		}

		iresult = dns_c_zone_getmaxtranstimein(czone, &xfrtime);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setxfrtime(zone, xfrtime);
		else
			dns_zone_setxfrtime(zone, MAX_XFER_TIME);
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

	case dns_c_zone_stub:
		iresult = dns_c_zone_getfile(czone, &filename);
		if (iresult != ISC_R_SUCCESS)
			return (iresult);
		result = dns_zone_setdatabase(zone, filename);
		if (result != DNS_R_SUCCESS)
			return (iresult);

		iresult = dns_c_zone_getchecknames(czone, &severity);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setchecknames(zone, severity);
		else
			dns_zone_setchecknames(zone, dns_c_severity_warn);

		acl = NULL;
		iresult = dns_c_zone_getallowquery(czone, &acl);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setqueryacl(zone, acl);
		else
			dns_zone_clearqueryacl(zone);

		iresult = dns_c_zone_getpubkey(czone, &pubkey);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setpubkey(zone, pubkey);
		else
			dns_zone_setpubkey(zone, NULL);

		iresult = dns_c_zone_getmasterport(czone, &port);
		if (iresult != ISC_R_SUCCESS)
			port = 53;
		dns_zone_setmasterport(zone, port);

		iresult = dns_c_zone_getmasterips(czone, &iplist);
		if (iresult == ISC_R_SUCCESS) {
			for (i = 0; i < iplist->nextidx; i++) {
				isc_sockaddr_t s;

				sockaddr_fromaddr(&s, &iplist->ips[i], port);
				result = dns_zone_addmaster(zone, &s);
				if (result != DNS_R_SUCCESS)
					return (result);
			}
		} else 
			dns_zone_clearmasters(zone);

		break;

	case dns_c_zone_hint:
		iresult = dns_c_zone_getfile(czone, &filename);
		if (iresult != ISC_R_SUCCESS)
			return (iresult);
		result = dns_zone_setdatabase(zone, filename);
		if (result != DNS_R_SUCCESS)
			return (result);

		iresult = dns_c_zone_getchecknames(czone, &severity);
		if (iresult == ISC_R_SUCCESS)
			dns_zone_setchecknames(zone, severity);
		else
			dns_zone_setchecknames(zone, dns_c_severity_fail);

		iresult = dns_c_zone_getpubkey(czone, &pubkey);
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

	REQUIRE(VALID_ZONE(zone));

	LOCK(&zone->lock);
	if (zone->query_acl != NULL)
		dns_c_ipmatchlist_delete(&zone->query_acl);
	zone->query_acl = dns_c_ipmatchlist_attach(acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_setupdateacl(dns_zone_t *zone, dns_c_ipmatchlist_t *acl) {

	REQUIRE(VALID_ZONE(zone));

	LOCK(&zone->lock);
	if (zone->update_acl != NULL)
		dns_c_ipmatchlist_delete(&zone->update_acl);
	zone->update_acl = dns_c_ipmatchlist_attach(acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_setxfracl(dns_zone_t *zone, dns_c_ipmatchlist_t *acl) {

	REQUIRE(VALID_ZONE(zone));

	LOCK(&zone->lock);
	if (zone->xfr_acl != NULL)
		dns_c_ipmatchlist_delete(&zone->xfr_acl);
	zone->xfr_acl = dns_c_ipmatchlist_attach(acl);
	UNLOCK(&zone->lock);
}

dns_c_ipmatchlist_t *
dns_zone_getqueryacl(dns_zone_t *zone) {

	REQUIRE(VALID_ZONE(zone));

	return (zone->query_acl);
}

dns_c_ipmatchlist_t *
dns_zone_getupdateacl(dns_zone_t *zone) {

	REQUIRE(VALID_ZONE(zone));

	return (zone->update_acl);
}

dns_c_ipmatchlist_t *
dns_zone_getxfracl(dns_zone_t *zone) {

	REQUIRE(VALID_ZONE(zone));

	return (zone->xfr_acl);
}

void
dns_zone_clearupdateacl(dns_zone_t *zone) {

	REQUIRE(VALID_ZONE(zone));

	LOCK(&zone->lock);
	if (zone->update_acl != NULL)
		dns_c_ipmatchlist_delete(&zone->update_acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_clearqueryacl(dns_zone_t *zone) {

	REQUIRE(VALID_ZONE(zone));

	LOCK(&zone->lock);
	if (zone->query_acl != NULL)
		dns_c_ipmatchlist_delete(&zone->query_acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_clearxfracl(dns_zone_t *zone) {

	REQUIRE(VALID_ZONE(zone));

	LOCK(&zone->lock);
	if (zone->xfr_acl != NULL)
		dns_c_ipmatchlist_delete(&zone->xfr_acl);
	UNLOCK(&zone->lock);
}

void
dns_zone_setchecknames(dns_zone_t *zone, dns_c_severity_t severity) {

	REQUIRE(VALID_ZONE(zone));

	zone->check_names = severity;
}

dns_c_severity_t
dns_zone_getchecknames(dns_zone_t *zone) {

	REQUIRE(VALID_ZONE(zone));

	return (zone->check_names);
}

void
dns_zone_setpubkey(dns_zone_t *zone, dns_c_pubkey_t *pubkey) {

	REQUIRE(VALID_ZONE(zone));

	zone->pubkey = pubkey;		/* XXX should be an attach */
}

dns_c_pubkey_t *
dns_zone_getpubkey(dns_zone_t *zone) {

	REQUIRE(VALID_ZONE(zone));

	return (zone->pubkey);
}

void
dns_zone_setixfrlogsize(dns_zone_t *zone, isc_int32_t size) {
	
	REQUIRE(VALID_ZONE(zone));

	zone->ixfrlogsize = size;
}

isc_int32_t
dns_zone_getixfrlogsize(dns_zone_t *zone) {
	
	REQUIRE(VALID_ZONE(zone));

	return (zone->ixfrlogsize);
}

void
dns_zone_setmasterport(dns_zone_t *zone,  isc_uint16_t port) {

	REQUIRE(VALID_ZONE(zone));

	zone->masterport = port;
}

isc_uint16_t
dns_zone_getmasterport(dns_zone_t *zone) {

	REQUIRE(VALID_ZONE(zone));

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
	LOCK(&zone->lock);
	result = dns_name_totext(dns_fixedname_name(&zone->origin), ISC_TRUE,
				 &buffer);
	UNLOCK(&zone->lock);
	if (result == DNS_R_SUCCESS)
		len = buffer.used;
	else
		len = 0;

	va_start(ap, fmt);
	vsnprintf(message, sizeof message, fmt, ap);
	va_end(ap);
	fprintf(stderr, "zone %.*s: %s\n", len, namebuf, message);
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
	REQUIRE(VALID_ZONE(zone));

	LOCK(&zone->lock);
	if (zone->res != NULL)
		dns_resolver_detach(&zone->res);
	dns_resolver_attach(resolver, &zone->res);
	UNLOCK(&zone->lock);
}

void
dns_zone_setxfrtime(dns_zone_t *zone, isc_uint32_t xfrtime) {
	REQUIRE(VALID_ZONE(zone));
	REQUIRE(xfrtime != 0);
	zone->xfrtime = xfrtime;
}

isc_uint32_t
dns_zone_getxfrtime(dns_zone_t *zone) {
	REQUIRE(VALID_ZONE(zone));

	return (zone->xfrtime);
}

void
dns_zone_transfer_in(dns_zone_t *zone) {
	REQUIRE(VALID_ZONE(zone));

	fprintf(stdout, "dns_zone_transfer_in\n");
}

dns_zonetype_t dns_zone_gettype(dns_zone_t *zone) {
	return (zone->type);
}

dns_name_t *dns_zone_getorigin(dns_zone_t *zone) {
	return (dns_fixedname_name(&zone->origin));
}

isc_task_t *dns_zone_gettask(dns_zone_t *zone) {
	return (zone->task);
}

const char *dns_zone_getdatabase(dns_zone_t *zone) {
	return (zone->database);
}

const char *dns_zone_getixfrlog(dns_zone_t *zone) {
	return (zone->ixfrlog);
}

/*
 * XXX should become isc_sockaddr_fromaddr() once dns_c_addr_t -> isc
 */
static void
sockaddr_fromaddr(isc_sockaddr_t *sockaddr, dns_c_addr_t *a,
		  unsigned int port) {
	switch (a->type.sa.sa_family) {
	case AF_INET:
		isc_sockaddr_fromin(sockaddr, &a->type.sin, port);
		break;
	case AF_INET6:
		isc_sockaddr_fromin6(sockaddr, &a->type.sin6, port);
		break;
	default:
		INSIST(0);
	}
}

static void
record_serial() {
}
