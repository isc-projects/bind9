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

#include <isc/assertions.h>

#include <dns/confzone.h>
#include <dns/confcommon.h>
#include <dns/log.h>

#include "confpvt.h"


/*
 * Bit positions in the dns_c_masterzone_t structure setflags field.
 */
#define MZ_CHECK_NAME_BIT		0
#define MZ_DIALUP_BIT			1
#define MZ_NOTIFY_BIT			2
#define MZ_MAINT_IXFR_BASE_BIT		3
#define MZ_MAX_IXFR_LOG_BIT		4
#define MZ_FORWARD_BIT			5
#define MZ_MAX_TRANS_TIME_OUT_BIT	6
#define MZ_MAX_TRANS_IDLE_OUT_BIT	7



/*
 * Bit positions in the dns_c_slavezone_t structure setflags field.
 */
#define SZ_CHECK_NAME_BIT		0
#define SZ_DIALUP_BIT			1
#define SZ_MASTER_PORT_BIT		2
#define SZ_TRANSFER_SOURCE_BIT		3
#define SZ_MAX_TRANS_TIME_IN_BIT	4
#define SZ_MAX_TRANS_TIME_OUT_BIT	5
#define SZ_MAX_TRANS_IDLE_IN_BIT	6
#define SZ_MAX_TRANS_IDLE_OUT_BIT	7
#define SZ_NOTIFY_BIT			8
#define SZ_MAINT_IXFR_BASE_BIT		9
#define SZ_MAX_IXFR_LOG_BIT		10
#define SZ_FORWARD_BIT			11



/* Bit positions of the stub zones */
#define TZ_CHECK_NAME_BIT		0
#define TZ_DIALUP_BIT			1
#define TZ_MASTER_PORT_BIT		2
#define TZ_TRANSFER_SOURCE_BIT		3
#define TZ_MAX_TRANS_TIME_IN_BIT	4
#define TZ_MAX_TRANS_TIME_OUT_BIT	5
#define TZ_MAX_TRANS_IDLE_IN_BIT	6
#define TZ_MAX_TRANS_IDLE_OUT_BIT	7
#define TZ_FORWARD_BIT			8


/*
 * Bit positions in the dns_c_forwardzone_t structure setflags field.
 */
#define FZ_CHECK_NAME_BIT		0
#define FZ_FORWARD_BIT			1


/*
 * Bit positions in the dns_c_hintzone_t structure setflags field.
 */
#define HZ_CHECK_NAME_BIT		0


typedef enum { zones_preopts, zones_postopts, zones_all } zone_print_type;

static isc_result_t master_zone_init(dns_c_masterzone_t *mzone);
static isc_result_t slave_zone_init(dns_c_slavezone_t *szone);
static isc_result_t stub_zone_init(dns_c_stubzone_t *szone);
static isc_result_t hint_zone_init(dns_c_hintzone_t *hzone);
static isc_result_t forward_zone_init(dns_c_forwardzone_t *fzone);
static isc_result_t zone_delete(dns_c_zone_t **zone);
static isc_result_t master_zone_clear(isc_mem_t *mem,
				      dns_c_masterzone_t *mzone);
static isc_result_t slave_zone_clear(isc_mem_t *mem,
				     dns_c_slavezone_t *szone);
static isc_result_t stub_zone_clear(isc_mem_t *mem,
				    dns_c_stubzone_t *szone);
static isc_result_t forward_zone_clear(isc_mem_t *mem,
				       dns_c_forwardzone_t *fzone);
static isc_result_t hint_zone_clear(isc_mem_t *mem,
				    dns_c_hintzone_t *hzone);

static void	master_zone_print(FILE *fp, int indent,
				  dns_c_masterzone_t *mzone);
static void	slave_zone_print(FILE *fp, int indent,
				 dns_c_slavezone_t *szone);
static void	stub_zone_print(FILE *fp, int indent,
				dns_c_stubzone_t *szone);
static void	hint_zone_print(FILE *fp, int indent,
				dns_c_hintzone_t *hzone);
static void	forward_zone_print(FILE *fp, int indent,
				   dns_c_forwardzone_t *fzone);
static isc_result_t set_iplist_field(isc_mem_t *mem,
				     dns_c_iplist_t **dest,
				     dns_c_iplist_t *src,
				     isc_boolean_t deepcopy);
static isc_result_t set_ipmatch_list_field(isc_mem_t *mem,
					   dns_c_ipmatchlist_t **dest,
					   dns_c_ipmatchlist_t *src,
					   isc_boolean_t deepcopy);

static void zone_list_print(zone_print_type zpt,
			    FILE *fp, int indent, dns_c_zonelist_t *list);



isc_result_t
dns_c_zonelist_new(isc_mem_t *mem, dns_c_zonelist_t **zlist)
{
	dns_c_zonelist_t *list;

	REQUIRE(zlist != NULL);

	list = isc_mem_get(mem, sizeof *list);
	if (list == NULL) {
		return (ISC_R_NOMEMORY);
	}

	list->mem = mem;
	list->magic = DNS_C_ZONELIST_MAGIC;

	ISC_LIST_INIT(list->zones);

	*zlist = list;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_zonelist_delete(dns_c_zonelist_t **zlist)
{
	dns_c_zonelist_t *list;
	dns_c_zonelem_t *zoneelem;
	dns_c_zonelem_t *tmpelem;
	dns_c_zone_t *zone;
	isc_result_t res;

	REQUIRE(zlist != NULL);
	REQUIRE(*zlist != NULL);

	list = *zlist;

	zoneelem = ISC_LIST_HEAD(list->zones);
	while (zoneelem != NULL) {
		tmpelem = ISC_LIST_NEXT(zoneelem, next);
		ISC_LIST_UNLINK(list->zones, zoneelem, next);

		zone = zoneelem->thezone;
		isc_mem_put(list->mem, zoneelem, sizeof *zoneelem);

		res = dns_c_zone_detach(&zone);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}

		zoneelem = tmpelem;
	}

	list->magic = 0;
	isc_mem_put(list->mem, list, sizeof *list);

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_zonelist_addzone(dns_c_zonelist_t *zlist,
		       dns_c_zone_t *zone)
{
	dns_c_zonelem_t *zoneelem;

	REQUIRE(DNS_C_ZONELIST_VALID(zlist));
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(zone->refcount > 0);

	zoneelem = isc_mem_get(zlist->mem, sizeof *zoneelem);
	if (zoneelem == NULL) {
		return (ISC_R_NOMEMORY);
	}
	
	zoneelem->thezone = zone;
	ISC_LINK_INIT(zoneelem, next);

	ISC_LIST_APPEND(zlist->zones, zoneelem, next);

	return (ISC_R_SUCCESS);
}
	
	

isc_result_t
dns_c_zonelist_find(dns_c_zonelist_t *zlist, const char *name,
		    dns_c_zone_t **retval)
{
	dns_c_zonelem_t *zoneelem;

	REQUIRE(DNS_C_ZONELIST_VALID(zlist));
	REQUIRE(name != NULL);
	REQUIRE(strlen(name) > 0);
	REQUIRE(retval != NULL);

	zoneelem = ISC_LIST_HEAD(zlist->zones);
	while (zoneelem != NULL) {
		REQUIRE(zoneelem->thezone != NULL);
		
		if (strcmp(name, zoneelem->thezone->name) == 0) {
			break;
		}
	}

	if (zoneelem != NULL) {
		*retval = zoneelem->thezone;
	}

	return (zoneelem == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zonelist_rmbyname(dns_c_zonelist_t *zlist,
			const char *name)
{
	dns_c_zonelem_t *zoneelem;
	isc_result_t res;

	REQUIRE(DNS_C_ZONELIST_VALID(zlist));
	REQUIRE(name != NULL);
	REQUIRE(strlen(name) > 0);

	zoneelem = ISC_LIST_HEAD(zlist->zones);
	while (zoneelem != NULL) {
		REQUIRE(zoneelem->thezone != NULL);
		
		if (strcmp(name, zoneelem->thezone->name) == 0) {
			break;
		}
	}

	if (zoneelem != NULL) {
		ISC_LIST_UNLINK(zlist->zones, zoneelem, next);
		res = dns_c_zone_detach(&zoneelem->thezone);
		isc_mem_put(zlist->mem, zoneelem, sizeof *zoneelem);
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_zonelist_rmzone(dns_c_zonelist_t *zlist,
		      dns_c_zone_t *zone)
{
	dns_c_zonelem_t *zoneelem;
	isc_result_t res;
	
	REQUIRE(zlist != NULL);
	REQUIRE(zone != NULL);

	zoneelem = ISC_LIST_HEAD(zlist->zones);
	while (zoneelem != NULL) {
		REQUIRE(zoneelem->thezone != NULL);
		
		if (zone == zoneelem->thezone) {
			break;
		}
	}

	if (zoneelem != NULL) {
		ISC_LIST_UNLINK(zlist->zones, zoneelem, next);
		res = dns_c_zone_detach(&zoneelem->thezone);
		isc_mem_put(zlist->mem, zoneelem, sizeof *zoneelem);
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


void
dns_c_zonelist_print(FILE *fp, int indent,
		     dns_c_zonelist_t *list)
{
	REQUIRE(DNS_C_ZONELIST_VALID(list));
	zone_list_print(zones_all, fp, indent, list);
}


void
dns_c_zonelist_printpreopts(FILE *fp, int indent,
			    dns_c_zonelist_t *list)
{
	REQUIRE(DNS_C_ZONELIST_VALID(list));
	zone_list_print(zones_preopts, fp, indent, list);
}


void
dns_c_zonelist_printpostopts(FILE *fp, int indent,
			     dns_c_zonelist_t *list)
{
	REQUIRE(DNS_C_ZONELIST_VALID(list));
	zone_list_print(zones_postopts, fp, indent, list);
}



static void
zone_list_print(zone_print_type zpt, FILE *fp, int indent,
		dns_c_zonelist_t *list) 
{
	dns_c_zonelem_t *zoneelem;
	
	REQUIRE(fp != NULL);
	REQUIRE(indent >= 0);

	if (list == NULL) {
		return;
	}

#define PRINTIT(zone, zpt)						  \
	(zpt == zones_all ||						  \
	 (zone->view == NULL &&						  \
	  ((zpt == zones_preopts && zone->afteropts == ISC_FALSE) ||	  \
	   ((zpt == zones_postopts && zone->afteropts == ISC_TRUE)))))
	
	zoneelem = ISC_LIST_HEAD(list->zones);
	while (zoneelem != NULL) {
		if (PRINTIT(zoneelem->thezone, zpt)) {
			dns_c_zone_print(fp, indent, zoneelem->thezone);
		}
		
		zoneelem = ISC_LIST_NEXT(zoneelem, next);
		if (zoneelem != NULL && PRINTIT(zoneelem->thezone, zpt)) {
			fprintf(fp, "\n");
		}
	}

#undef PRINTIT

	return;
}


/* ************************************************************************ */
/* ******************************** ZONEs ********************************* */
/* ************************************************************************ */

isc_result_t
dns_c_zone_new(isc_mem_t *mem,
	       dns_c_zonetype_t ztype, dns_rdataclass_t zclass,
	       const char *name, const char *internalname,
	       dns_c_zone_t **zone)
{
	dns_c_zone_t *newzone;
	isc_result_t res;

	REQUIRE(mem != NULL);
	REQUIRE(name != NULL);
	REQUIRE(strlen(name) > 0);

	newzone = isc_mem_get(mem, sizeof *newzone);
	if (newzone == NULL) {
		return (ISC_R_NOMEMORY);
	}

	newzone->magic = DNS_C_ZONE_MAGIC;
	newzone->mem = mem;
	newzone->refcount = 1;
	newzone->ztype = ztype;
	newzone->zclass = zclass;
	newzone->view = NULL;
	newzone->afteropts = ISC_FALSE;
	newzone->name = isc_mem_strdup(mem, name);
	newzone->internalname = (internalname == NULL ?
				 isc_mem_strdup(mem, name) :
				 isc_mem_strdup(mem, internalname));

	switch (ztype) {
	case dns_c_zone_master:
		res = master_zone_init(&newzone->u.mzone);
		break;
		
	case dns_c_zone_slave:
		res = slave_zone_init(&newzone->u.szone);
		break;

	case dns_c_zone_stub:
		res = stub_zone_init(&newzone->u.tzone);
		break;
		
	case dns_c_zone_hint:
		res = hint_zone_init(&newzone->u.hzone);
		break;
		
	case dns_c_zone_forward:
		res = forward_zone_init(&newzone->u.fzone);
		break;
	}
	
	*zone = newzone;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_detach(dns_c_zone_t **zone)
{
	dns_c_zone_t *zoneptr;
	isc_result_t res = ISC_R_SUCCESS;

	REQUIRE(zone != NULL);
	REQUIRE(DNS_C_ZONE_VALID(*zone));

	zoneptr = *zone;
	*zone = NULL;

	REQUIRE(zoneptr->refcount > 0);
	zoneptr->refcount--;

	if (zoneptr->refcount == 0) {
		res = zone_delete(&zoneptr);
	}

	return (res);
}


void
dns_c_zone_attach(dns_c_zone_t *source,
		  dns_c_zone_t **target)
{
	REQUIRE(DNS_C_ZONE_VALID(source));
	REQUIRE(target != NULL);

	source->refcount++;

	*target = source;
}
		


void
dns_c_zone_print(FILE *fp, int indent, dns_c_zone_t *zone)
{
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_ZONE_VALID(zone));

	dns_c_printtabs(fp, indent);
	fprintf(fp, "zone \"%s\"", zone->name);
	if (zone->zclass != dns_rdataclass_in) {
		fputc(' ', fp);
		dns_c_dataclass_tostream(fp, zone->zclass);
	}

	fprintf(fp, " {\n");

	switch (zone->ztype) {
	case dns_c_zone_master:
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "type master;\n");
		master_zone_print(fp, indent + 1, &zone->u.mzone);
		break;
		
	case dns_c_zone_slave:
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "type slave;\n");
		slave_zone_print(fp, indent + 1, &zone->u.szone);
		break;

	case dns_c_zone_stub:
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "type stub;\n");
		stub_zone_print(fp, indent + 1, &zone->u.tzone);
		break;
		
	case dns_c_zone_hint:
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "type hint;\n");
		hint_zone_print(fp, indent + 1, &zone->u.hzone);
		break;

	case dns_c_zone_forward:
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "type forward;\n");
		forward_zone_print(fp, indent + 1, &zone->u.fzone);
		break;
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");
}


isc_result_t
dns_c_zone_setfile(dns_c_zone_t *zone, const char *newfile)
{
	char **p = NULL;
	isc_result_t res;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(newfile != NULL);
	REQUIRE(strlen(newfile) > 0);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.file;
		break;

	case dns_c_zone_slave:
		p = &zone->u.szone.file;
		break;
		
	case dns_c_zone_stub:
		p = &zone->u.tzone.file;
		break;

	case dns_c_zone_hint:
		p = &zone->u.hzone.file;
		break;
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a file field");
		return (ISC_R_FAILURE);
	}

	if (*p != NULL) {
		isc_mem_free(zone->mem, *p);
		res = ISC_R_EXISTS;
	} else {
		res = ISC_R_SUCCESS;
	}

	*p = isc_mem_strdup(zone->mem, newfile);
	if (*p == NULL) {
		res = ISC_R_NOMEMORY;
	}

	return (res);
}


isc_result_t
dns_c_zone_setchecknames(dns_c_zone_t *zone,
			 dns_severity_t severity)
{
	dns_severity_t *p = NULL;
	dns_c_setbits_t *bits = NULL;
	int bit = 0;
	isc_result_t res;

	REQUIRE(DNS_C_ZONE_VALID(zone));

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.check_names;
		bits = &zone->u.mzone.setflags;
		bit = MZ_CHECK_NAME_BIT;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.check_names;
		bits = &zone->u.szone.setflags;
		bit = SZ_CHECK_NAME_BIT;
		break;
		
	case dns_c_zone_stub:
		p = &zone->u.tzone.check_names;
		bits = &zone->u.tzone.setflags;
		bit = TZ_CHECK_NAME_BIT;
		break;
		
	case dns_c_zone_hint:
		p = &zone->u.hzone.check_names;
		bits = &zone->u.hzone.setflags;
		bit = HZ_CHECK_NAME_BIT;
		break;
			
	case dns_c_zone_forward:
		p = &zone->u.fzone.check_names;
		bits = &zone->u.fzone.setflags;
		bit = FZ_CHECK_NAME_BIT;
		break;
	}

	if (DNS_C_CHECKBIT(bit, bits)) {
		res = ISC_R_EXISTS;
	} else {
		res = ISC_R_SUCCESS;
	}
	
	*p = severity;
	DNS_C_SETBIT(bit, bits);

	return (res);
}


isc_result_t
dns_c_zone_setallowupd(dns_c_zone_t *zone,
		       dns_c_ipmatchlist_t *ipml,
		       isc_boolean_t deepcopy)
{
	dns_c_ipmatchlist_t **p = NULL;
	isc_result_t res;
	isc_boolean_t existed;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(DNS_C_IPMLIST_VALID(ipml));

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.allow_update;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.allow_update;
		break;
		
	case dns_c_zone_stub:
		p = &zone->u.tzone.allow_update;
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have an allow_update field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have an "
			      "allow_update field");
		return (ISC_R_FAILURE);
	}

	existed = (*p != NULL ? ISC_TRUE : ISC_FALSE);
	
	res = set_ipmatch_list_field(zone->mem, p,
				     ipml, deepcopy);
	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}

	return (res);
}


isc_result_t
dns_c_zone_setallowquery(dns_c_zone_t *zone,
			 dns_c_ipmatchlist_t *ipml,
			 isc_boolean_t deepcopy)
{
	dns_c_ipmatchlist_t **p = NULL;
	isc_boolean_t existed;
	isc_result_t res;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(DNS_C_IPMLIST_VALID(ipml));

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.allow_query;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.allow_query;
		break;
		
	case dns_c_zone_stub:
		p = &zone->u.tzone.allow_query;
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have an allow_query field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have an "
			      "allow_query field");
		return (ISC_R_FAILURE);
	}

	existed = (*p != NULL ? ISC_TRUE : ISC_FALSE);
	
	res = set_ipmatch_list_field(zone->mem, p,
				     ipml, deepcopy);
	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}

	return (res);
}


isc_result_t
dns_c_zone_setallowtransfer(dns_c_zone_t *zone,
			    dns_c_ipmatchlist_t *ipml,
			    isc_boolean_t deepcopy)
{
	dns_c_ipmatchlist_t **p = NULL;
	isc_boolean_t existed;
	isc_result_t res;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(DNS_C_IPMLIST_VALID(ipml));

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.allow_transfer;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.allow_transfer;
		break;
		
	case dns_c_zone_stub:
		p = &zone->u.tzone.allow_transfer;
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have an "
			      "allow_transfer field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have an "
			      "allow_transfer field");
		return (ISC_R_FAILURE);
	}

	existed = (*p != NULL ? ISC_TRUE : ISC_FALSE);
	res = set_ipmatch_list_field(zone->mem, p,
				     ipml, deepcopy);

	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}

	return (res);
}


isc_result_t
dns_c_zone_setdialup(dns_c_zone_t *zone, isc_boolean_t newval)
{
	isc_boolean_t existed = ISC_FALSE;

	REQUIRE(DNS_C_ZONE_VALID(zone));

	switch (zone->ztype) {
	case dns_c_zone_master:
		zone->u.mzone.dialup = newval;
		existed = DNS_C_CHECKBIT(MZ_DIALUP_BIT,
					 &zone->u.mzone.setflags);
		DNS_C_SETBIT(MZ_DIALUP_BIT, &zone->u.mzone.setflags);
		break;

	case dns_c_zone_slave:
		zone->u.szone.dialup = newval;
		existed = DNS_C_CHECKBIT(SZ_DIALUP_BIT,
					 &zone->u.szone.setflags);
		DNS_C_SETBIT(SZ_DIALUP_BIT, &zone->u.szone.setflags);
		break;

	case dns_c_zone_stub:
		zone->u.tzone.dialup = newval;
		existed = DNS_C_CHECKBIT(TZ_DIALUP_BIT,
					 &zone->u.tzone.setflags);
		DNS_C_SETBIT(TZ_DIALUP_BIT, &zone->u.tzone.setflags);
		break;

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a dialup field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a dialup field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_setnotify(dns_c_zone_t *zone, isc_boolean_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));

	switch (zone->ztype) {
	case dns_c_zone_master:
		zone->u.mzone.notify = newval;
		existed = DNS_C_CHECKBIT(MZ_NOTIFY_BIT,
					 &zone->u.mzone.setflags);
		DNS_C_SETBIT(MZ_NOTIFY_BIT, &zone->u.mzone.setflags);
		break;
			
	case dns_c_zone_slave:
		zone->u.szone.notify = newval;
		existed = DNS_C_CHECKBIT(SZ_NOTIFY_BIT,
					 &zone->u.szone.setflags);
		DNS_C_SETBIT(SZ_NOTIFY_BIT, &zone->u.szone.setflags);
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a notify field");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a notify field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_setmaintixfrbase(dns_c_zone_t *zone,
			    isc_boolean_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));

	switch (zone->ztype) {
	case dns_c_zone_master:
		zone->u.mzone.maint_ixfr_base = newval;
		existed = DNS_C_CHECKBIT(MZ_MAINT_IXFR_BASE_BIT,
					 &zone->u.mzone.setflags);
		DNS_C_SETBIT(MZ_MAINT_IXFR_BASE_BIT, &zone->u.mzone.setflags);
		break;
			
	case dns_c_zone_slave:
		zone->u.szone.maint_ixfr_base = newval;
		existed = DNS_C_CHECKBIT(SZ_MAINT_IXFR_BASE_BIT,
					 &zone->u.szone.setflags);
		DNS_C_SETBIT(SZ_MAINT_IXFR_BASE_BIT, &zone->u.szone.setflags);
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a "
			      "maintain-xfer-base field");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a "
			      "maintain-xfer-base field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "maintain-xfer-base field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_setalsonotify(dns_c_zone_t *zone,
			 dns_c_iplist_t *newval,
			 isc_boolean_t deepcopy)
{
	isc_boolean_t existed;
	isc_result_t res;
	dns_c_iplist_t **p = NULL;

	REQUIRE(zone != NULL);
	REQUIRE(DNS_C_IPLIST_VALID(newval));
	
	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.also_notify ;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.also_notify ;
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a also_notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a also_notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a also_notify field");
		return (ISC_R_FAILURE);
	}

	existed = (*p != NULL ? ISC_TRUE : ISC_FALSE);
	res = set_iplist_field(zone->mem, p, newval, deepcopy);
	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}

	return (res);
}


isc_result_t
dns_c_zone_setixfrbase(dns_c_zone_t *zone, const char *newval)
{
	isc_boolean_t existed ;
	char **p = NULL;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(newval != NULL);
	REQUIRE(strlen(newval) > 0);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.ixfr_base;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.ixfr_base;
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a ixfr_base field");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a ixfr_base field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a file field");
		return (ISC_R_FAILURE);
	}

	if (*p != NULL) {
		existed = ISC_TRUE;
		isc_mem_free(zone->mem, *p);
	} else {
		existed = ISC_FALSE;
	}

	*p = isc_mem_strdup(zone->mem, newval);
	if (*p == NULL) {
		return (ISC_R_NOMEMORY);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_setixfrtmp(dns_c_zone_t *zone, const char *newval)
{
	isc_boolean_t existed;
	char **p = NULL;

	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(newval != NULL);
	REQUIRE(strlen(newval) > 0);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.ixfr_tmp;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.ixfr_tmp;
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a ixfr_tmp field");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a ixfr_tmp field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a file field");
		return (ISC_R_FAILURE);
	}

	if (*p != NULL) {
		existed = ISC_TRUE;
		isc_mem_free(zone->mem, *p);
	} else {
		existed = ISC_FALSE;
	}

	*p = isc_mem_strdup(zone->mem, newval);
	if (*p == NULL) {
		return (ISC_R_NOMEMORY);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_addpubkey(dns_c_zone_t *zone,
		     dns_c_pubkey_t *pubkey,
		     isc_boolean_t deepcopy)
{
	dns_c_pklist_t **p = NULL;
	isc_result_t res;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(DNS_C_PUBKEY_VALID(pubkey));

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.pubkeylist;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.pubkeylist;
		break;
		
	case dns_c_zone_stub:
		p = &zone->u.tzone.pubkeylist;
		break;
		
	case dns_c_zone_hint:
#if 1
		p = &zone->u.hzone.pubkeylist;
#else
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a pubkey field");
#endif 
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a pubkey field");
		return (ISC_R_FAILURE);
	}

	if (*p == NULL) {
		res = dns_c_pklist_new(zone->mem, p);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	res = dns_c_pklist_addpubkey(*p, pubkey, deepcopy);

	return (res);
}


isc_result_t
dns_c_zone_setmasterport(dns_c_zone_t *zone, in_port_t port)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));

	switch(zone->ztype) {
	case dns_c_zone_master:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "master_port field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		zone->u.szone.master_port = port;
		existed = DNS_C_CHECKBIT(SZ_MASTER_PORT_BIT,
					 &zone->u.szone.setflags);
		DNS_C_SETBIT(SZ_MASTER_PORT_BIT, &zone->u.szone.setflags);
		break;
		
	case dns_c_zone_stub:
		zone->u.tzone.master_port = port;
		existed = DNS_C_CHECKBIT(TZ_MASTER_PORT_BIT,
					 &zone->u.tzone.setflags);
		DNS_C_SETBIT(TZ_MASTER_PORT_BIT, &zone->u.tzone.setflags);
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a master_port field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "master_port field");
		return (ISC_R_FAILURE);
	}
		
	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_setmasterips(dns_c_zone_t *zone,
			dns_c_iplist_t *newval,
			isc_boolean_t deepcopy)
{
	isc_boolean_t existed;
	isc_result_t res = ISC_R_SUCCESS;
	dns_c_iplist_t **p;

	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(DNS_C_IPLIST_VALID(newval));
	
	switch (zone->ztype) {
	case dns_c_zone_master:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Master zones do not have a master_ips field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
	case dns_c_zone_stub:
		if (zone->ztype == dns_c_zone_slave) {
			p = &zone->u.szone.master_ips ;
		} else {
			p = &zone->u.tzone.master_ips ;
		}
		
		existed = (*p != NULL ? ISC_TRUE : ISC_FALSE);
		res = set_iplist_field(zone->mem, p,
				       newval, deepcopy);
		if (res == ISC_R_SUCCESS && existed) {
			res = ISC_R_EXISTS;
		}
		break;

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a master_ips field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a master_ips field");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_settransfersource(dns_c_zone_t *zone,
			     isc_sockaddr_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));

	switch (zone->ztype) {
	case dns_c_zone_master:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Master zones do not have a "
			      "transfer_source field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		zone->u.szone.transfer_source = newval ;
		existed = DNS_C_CHECKBIT(SZ_TRANSFER_SOURCE_BIT,
					 &zone->u.szone.setflags);
		DNS_C_SETBIT(SZ_TRANSFER_SOURCE_BIT, &zone->u.szone.setflags);
		break;
		
	case dns_c_zone_stub:
		zone->u.tzone.transfer_source = newval ;
		existed = DNS_C_CHECKBIT(TZ_TRANSFER_SOURCE_BIT,
					 &zone->u.tzone.setflags);
		DNS_C_SETBIT(TZ_TRANSFER_SOURCE_BIT, &zone->u.tzone.setflags);
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a master_ips field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a master_ips field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_setmaxtranstimein(dns_c_zone_t *zone,
			     isc_int32_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));

	switch (zone->ztype) {
	case dns_c_zone_master:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Master zones do not have a "
			      "max_trans_time_in field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		zone->u.szone.max_trans_time_in = newval ;
		existed = DNS_C_CHECKBIT(SZ_MAX_TRANS_TIME_IN_BIT,
					 &zone->u.szone.setflags);
		DNS_C_SETBIT(SZ_MAX_TRANS_TIME_IN_BIT,
			     &zone->u.szone.setflags);
		break;
		
	case dns_c_zone_stub:
		zone->u.tzone.max_trans_time_in = newval ;
		existed = DNS_C_CHECKBIT(TZ_MAX_TRANS_TIME_IN_BIT,
					 &zone->u.tzone.setflags);
		DNS_C_SETBIT(TZ_MAX_TRANS_TIME_IN_BIT,
			     &zone->u.tzone.setflags);
		break;

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a "
			      "max_trans_time_in field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "max_trans_time_in field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_setmaxtranstimeout(dns_c_zone_t *zone,
			      isc_int32_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));

	switch (zone->ztype) {
	case dns_c_zone_master:
		zone->u.mzone.max_trans_time_out = newval ;
		existed = DNS_C_CHECKBIT(MZ_MAX_TRANS_TIME_OUT_BIT,
					 &zone->u.mzone.setflags);
		DNS_C_SETBIT(MZ_MAX_TRANS_TIME_OUT_BIT,
			     &zone->u.mzone.setflags);
		break;
			
	case dns_c_zone_slave:
		zone->u.szone.max_trans_time_out = newval ;
		existed = DNS_C_CHECKBIT(SZ_MAX_TRANS_TIME_OUT_BIT,
					 &zone->u.szone.setflags);
		DNS_C_SETBIT(SZ_MAX_TRANS_TIME_OUT_BIT,
			     &zone->u.szone.setflags);
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a "
			      "max_trans_time_out field");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a "
			      "max_trans_time_out field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "max_trans_time_out field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_setmaxtransidlein(dns_c_zone_t *zone,
			     isc_int32_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));

	switch (zone->ztype) {
	case dns_c_zone_master:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Master zones do not have a "
			      "max_trans_idle_in field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		zone->u.szone.max_trans_idle_in = newval ;
		existed = DNS_C_CHECKBIT(SZ_MAX_TRANS_IDLE_IN_BIT,
					 &zone->u.szone.setflags);
		DNS_C_SETBIT(SZ_MAX_TRANS_IDLE_IN_BIT,
			     &zone->u.szone.setflags);
		break;
		
	case dns_c_zone_stub:
		zone->u.tzone.max_trans_idle_in = newval ;
		existed = DNS_C_CHECKBIT(TZ_MAX_TRANS_IDLE_IN_BIT,
					 &zone->u.tzone.setflags);
		DNS_C_SETBIT(TZ_MAX_TRANS_IDLE_IN_BIT,
			     &zone->u.tzone.setflags);
		break;

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a "
			      "max_trans_idle_in field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "max_trans_idle_in field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_setmaxtransidleout(dns_c_zone_t *zone,
			      isc_int32_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));

	switch (zone->ztype) {
	case dns_c_zone_master:
		zone->u.mzone.max_trans_idle_out = newval ;
		existed = DNS_C_CHECKBIT(MZ_MAX_TRANS_IDLE_OUT_BIT,
					 &zone->u.mzone.setflags);
		DNS_C_SETBIT(MZ_MAX_TRANS_IDLE_OUT_BIT,
			     &zone->u.mzone.setflags);
		break;
			
	case dns_c_zone_slave:
		zone->u.szone.max_trans_idle_out = newval ;
		existed = DNS_C_CHECKBIT(SZ_MAX_TRANS_IDLE_OUT_BIT,
					 &zone->u.szone.setflags);
		DNS_C_SETBIT(SZ_MAX_TRANS_IDLE_OUT_BIT,
			     &zone->u.szone.setflags);
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a "
			      "max_trans_idle_out field");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a "
			      "max_trans_idle_out field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "max_trans_idle_out field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_setmaxixfrlog(dns_c_zone_t *zone,
			 isc_int32_t newval)
{
	dns_c_setbits_t *bits = NULL;
	isc_int32_t *p = NULL;
	int bit = 0;
	isc_result_t res;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.max_ixfr_log;
		bits = &zone->u.mzone.setflags;
		bit = MZ_MAX_IXFR_LOG_BIT;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.max_ixfr_log;
		bits = &zone->u.mzone.setflags;
		bit = SZ_MAX_IXFR_LOG_BIT;
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a max-ixfr-log field");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a max-ixfr-log field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "max-ixfr-log field");
		return (ISC_R_FAILURE);
	}

	if (DNS_C_CHECKBIT(bit, bits)) {
		res = ISC_R_EXISTS;
	} else {
		res = ISC_R_SUCCESS;
	}
	
	*p = newval;
	DNS_C_SETBIT(bit, bits);

	return (res);
}


isc_result_t
dns_c_zone_setforward(dns_c_zone_t *zone, dns_c_forw_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
		
	switch (zone->ztype) {
	case dns_c_zone_master:
		zone->u.mzone.forward = newval;
		existed = DNS_C_CHECKBIT(MZ_FORWARD_BIT,
					 &zone->u.mzone.setflags);
		DNS_C_SETBIT(MZ_FORWARD_BIT, &zone->u.mzone.setflags);
		break;
			
	case dns_c_zone_slave:
		zone->u.szone.forward = newval;
		existed = DNS_C_CHECKBIT(SZ_FORWARD_BIT,
					 &zone->u.szone.setflags);
		DNS_C_SETBIT(SZ_FORWARD_BIT, &zone->u.szone.setflags);
		break;
		
	case dns_c_zone_stub:
		zone->u.tzone.forward = newval;
		existed = DNS_C_CHECKBIT(TZ_FORWARD_BIT,
					 &zone->u.tzone.setflags);
		DNS_C_SETBIT(TZ_FORWARD_BIT, &zone->u.tzone.setflags);
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a forward field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		zone->u.fzone.forward = newval;
		existed = DNS_C_CHECKBIT(FZ_FORWARD_BIT,
					 &zone->u.fzone.setflags);
		DNS_C_SETBIT(FZ_FORWARD_BIT, &zone->u.fzone.setflags);
		break;
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_setforwarders(dns_c_zone_t *zone,
			 dns_c_iplist_t *ipl,
			 isc_boolean_t deepcopy)
{
	isc_boolean_t existed = ISC_FALSE;
	isc_result_t res;
	dns_c_iplist_t **p = NULL;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(DNS_C_IPLIST_VALID(ipl));

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.forwarders;
		existed = (*p == NULL ? ISC_FALSE : ISC_TRUE);
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.forwarders;
		existed = (*p == NULL ? ISC_FALSE : ISC_TRUE);
		break;
		
	case dns_c_zone_stub:
		p = &zone->u.tzone.forwarders;
		existed = (*p == NULL ? ISC_FALSE : ISC_TRUE);
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a forwarders field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		p = &zone->u.fzone.forwarders;
		existed = (*p == NULL ? ISC_FALSE : ISC_TRUE);
		break;
	}

	res = set_iplist_field(zone->mem, p, ipl, deepcopy);
	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}

	return (res);
}


isc_result_t
dns_c_zone_getname(dns_c_zone_t *zone, const char **retval)
{
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	*retval = zone->name;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_getinternalname(dns_c_zone_t *zone,
			   const char **retval)
{
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	*retval = zone->internalname;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_getfile(dns_c_zone_t *zone, const char **retval)
{
	const char *p = NULL;
	isc_result_t res;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = zone->u.mzone.file;
		break;

	case dns_c_zone_slave:
		p = zone->u.szone.file;
		break;
		
	case dns_c_zone_stub:
		p = zone->u.tzone.file;
		break;
		
	case dns_c_zone_hint:
		p = zone->u.hzone.file;
		break;
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a file field");
		return (ISC_R_FAILURE);
	}

	if (p != NULL) {
		*retval = p;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_zone_getchecknames(dns_c_zone_t *zone,
			 dns_severity_t *retval)
{
	dns_severity_t *p = NULL;
	dns_c_setbits_t *bits = NULL;
	int bit = 0;
	isc_result_t res;

	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.check_names;
		bits = &zone->u.mzone.setflags;
		bit = MZ_CHECK_NAME_BIT;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.check_names;
		bits = &zone->u.szone.setflags;
		bit = SZ_CHECK_NAME_BIT;
		break;
		
	case dns_c_zone_stub:
		p = &zone->u.tzone.check_names;
		bits = &zone->u.tzone.setflags;
		bit = TZ_CHECK_NAME_BIT;
		break;
		
	case dns_c_zone_hint:
		p = &zone->u.hzone.check_names;
		bits = &zone->u.hzone.setflags;
		bit = HZ_CHECK_NAME_BIT;
		break;
			
	case dns_c_zone_forward:
		p = &zone->u.fzone.check_names;
		bits = &zone->u.fzone.setflags;
		bit = FZ_CHECK_NAME_BIT;
		break;
	}

	if (DNS_C_CHECKBIT(bit, bits)) {
		*retval = *p;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}
	
	return (res);
}


isc_result_t
dns_c_zone_getallowupd(dns_c_zone_t *zone,
		       dns_c_ipmatchlist_t **retval)
{
	dns_c_ipmatchlist_t *p = NULL;
	isc_result_t res;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = zone->u.mzone.allow_update;
		break;
			
	case dns_c_zone_slave:
		p = zone->u.szone.allow_update;
		break;
		
	case dns_c_zone_stub:
		p = zone->u.tzone.allow_update;
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have an allow_update field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have an "
			      "allow_update field");
		return (ISC_R_FAILURE);
	}

	if (p != NULL) {
		dns_c_ipmatchlist_attach(p, retval);
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_zone_getallowquery(dns_c_zone_t *zone,
			 dns_c_ipmatchlist_t **retval)
{
	dns_c_ipmatchlist_t *p = NULL;
	isc_result_t res;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = zone->u.mzone.allow_query;
		break;
			
	case dns_c_zone_slave:
		p = zone->u.szone.allow_query;
		break;
		
	case dns_c_zone_stub:
		p = zone->u.tzone.allow_query;
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have an allow_query field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have an "
			      "allow_query field");
		return (ISC_R_FAILURE);
	}

	if (p != NULL) {
		dns_c_ipmatchlist_attach(p, retval);
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_zone_getallowtransfer(dns_c_zone_t *zone,
			    dns_c_ipmatchlist_t **retval)
{
	dns_c_ipmatchlist_t *p = NULL;
	isc_result_t res;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = zone->u.mzone.allow_transfer;
		break;
			
	case dns_c_zone_slave:
		p = zone->u.szone.allow_transfer;
		break;
		
	case dns_c_zone_stub:
		p = zone->u.tzone.allow_transfer;
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have an "
			      "allow_transfer field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have an "
			      "allow_transfer field");
		return (ISC_R_FAILURE);
	}

	if (p != NULL) {
		dns_c_ipmatchlist_attach(p, retval);
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_zone_getdialup(dns_c_zone_t *zone,
		     isc_boolean_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		if (DNS_C_CHECKBIT(MZ_DIALUP_BIT, &zone->u.mzone.setflags)) {
			*retval = zone->u.mzone.dialup;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_slave:
		if (DNS_C_CHECKBIT(SZ_DIALUP_BIT, &zone->u.szone.setflags)) {
			*retval = zone->u.szone.dialup;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_stub:
		if (DNS_C_CHECKBIT(TZ_DIALUP_BIT, &zone->u.tzone.setflags)) {
			*retval = zone->u.tzone.dialup;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a dialup field");
		return (ISC_R_FAILURE);
		
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a dialup field");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_getnotify(dns_c_zone_t *zone,
		     isc_boolean_t *retval)
{
	isc_result_t res;
	dns_c_setbits_t *bits = NULL;
	isc_boolean_t val = ISC_FALSE;
	int bit = 0;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		val = zone->u.mzone.notify;
		bit = MZ_DIALUP_BIT;
		bits = &zone->u.mzone.setflags;
		break;
			
	case dns_c_zone_slave:
		val = zone->u.szone.notify;
		bit = SZ_DIALUP_BIT;
		bits = &zone->u.szone.setflags;
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a notify field");
		return (ISC_R_FAILURE);
	}

	if (DNS_C_CHECKBIT(bit,bits)) {
		*retval = val;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}
	
	return (res);
}


isc_result_t
dns_c_zone_getmaintixfrbase(dns_c_zone_t *zone,
			    isc_boolean_t *retval)
{
	isc_result_t res;
	dns_c_setbits_t *bits = NULL;
	isc_boolean_t val = ISC_FALSE;
	int bit = 0;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		val = zone->u.mzone.maint_ixfr_base;
		bit = MZ_MAINT_IXFR_BASE_BIT;
		bits = &zone->u.mzone.setflags;
		break;
			
	case dns_c_zone_slave:
		val = zone->u.szone.maint_ixfr_base;
		bit = SZ_MAINT_IXFR_BASE_BIT;
		bits = &zone->u.szone.setflags;
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a notify field");
		return (ISC_R_FAILURE);
	}

	if (DNS_C_CHECKBIT(bit,bits)) {
		*retval = val;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}
	
	return (res);
}


isc_result_t
dns_c_zone_getalsonotify(dns_c_zone_t *zone,
			 dns_c_iplist_t **retval)
{
	dns_c_iplist_t *p = NULL;
	isc_result_t res;

	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);
	
	switch (zone->ztype) {
	case dns_c_zone_master:
		p = zone->u.mzone.also_notify ;
		break;
			
	case dns_c_zone_slave:
		p = zone->u.szone.also_notify ;
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a also_notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a also_notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a also_notify field");
		return (ISC_R_FAILURE);
	}

	if (p != NULL) {
		*retval = p;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_zone_getixfrbase(dns_c_zone_t *zone,
		       const char **retval)
{
	char *p = NULL;
	isc_result_t res;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = zone->u.mzone.ixfr_base;
		break;
			
	case dns_c_zone_slave:
		p = zone->u.szone.ixfr_base;
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a ixfr_base field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a ixfr_base field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a file field");
		return (ISC_R_FAILURE);
	}

	if (p != NULL) {
		*retval = p;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_zone_getixfrtmp(dns_c_zone_t *zone, const char **retval)
{
	char *p = NULL;
	isc_result_t res;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = zone->u.mzone.ixfr_tmp;
		break;
			
	case dns_c_zone_slave:
		p = zone->u.szone.ixfr_tmp;
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a ixfr_tmp field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a ixfr_tmp field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a file field");
		return (ISC_R_FAILURE);
	}

	if (p != NULL) {
		*retval = p;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_zone_getpubkeylist(dns_c_zone_t *zone,
			 dns_c_pklist_t **retval)
{
	dns_c_pklist_t *p = NULL;
	isc_result_t res;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = zone->u.mzone.pubkeylist;
		break;
			
	case dns_c_zone_slave:
		p = zone->u.szone.pubkeylist;
		break;
		
	case dns_c_zone_stub:
		p = zone->u.tzone.pubkeylist;
		break;
		
	case dns_c_zone_hint:
#if 1
		p = zone->u.hzone.pubkeylist;
#else	
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a pubkey field");
#endif	
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a pubkey field");
		return (ISC_R_FAILURE);
	}

	if (p != NULL) {
		*retval = p;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}


isc_result_t
dns_c_zone_getmasterport(dns_c_zone_t *zone,
			 in_port_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch(zone->ztype) {
	case dns_c_zone_master:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "master_port field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		if (DNS_C_CHECKBIT(SZ_MASTER_PORT_BIT,
				   &zone->u.szone.setflags)) {
			*retval = zone->u.szone.master_port;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;

	case dns_c_zone_stub:
		if (DNS_C_CHECKBIT(TZ_MASTER_PORT_BIT,
				   &zone->u.tzone.setflags)) {
			*retval = zone->u.tzone.master_port;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a master_port field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "master_port field");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_getmasterips(dns_c_zone_t *zone,
			dns_c_iplist_t **retval)
{
	isc_result_t res = ISC_R_SUCCESS;

	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);
	
	switch (zone->ztype) {
	case dns_c_zone_master:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Master zones do not have a master_ips field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		if (zone->u.szone.master_ips != NULL) {
			*retval = zone->u.szone.master_ips;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_stub:
		if (zone->u.tzone.master_ips != NULL) {
			*retval = zone->u.tzone.master_ips;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a master_ips field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a master_ips field");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_gettransfersource(dns_c_zone_t *zone,
			     isc_sockaddr_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;

	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Master zones do not have a "
			      "transfer_source field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		if (DNS_C_CHECKBIT(SZ_TRANSFER_SOURCE_BIT,
				   &zone->u.szone.setflags)) {
			*retval = zone->u.szone.transfer_source ;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		
		break;
		
	case dns_c_zone_stub:
		if (DNS_C_CHECKBIT(TZ_TRANSFER_SOURCE_BIT,
				   &zone->u.tzone.setflags)) {
			*retval = zone->u.tzone.transfer_source ;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		
		break;

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a master_ips field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a master_ips field");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_getmaxtranstimein(dns_c_zone_t *zone,
			     isc_int32_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;

	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Master zones do not have a "
			      "max_trans_time_in field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		if (DNS_C_CHECKBIT(SZ_MAX_TRANS_TIME_IN_BIT,
				   &zone->u.szone.setflags)) {
			*retval = zone->u.szone.max_trans_time_in;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_stub:
		if (DNS_C_CHECKBIT(TZ_MAX_TRANS_TIME_IN_BIT,
				   &zone->u.tzone.setflags)) {
			*retval = zone->u.tzone.max_trans_time_in;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a "
			      "max_trans_time_in field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "max_trans_time_in field");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_getmaxtranstimeout(dns_c_zone_t *zone,
			     isc_int32_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;

	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		if (DNS_C_CHECKBIT(SZ_MAX_TRANS_TIME_OUT_BIT,
				   &zone->u.mzone.setflags)) {
			*retval = zone->u.mzone.max_trans_time_out;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
			
	case dns_c_zone_slave:
		if (DNS_C_CHECKBIT(SZ_MAX_TRANS_TIME_OUT_BIT,
				   &zone->u.szone.setflags)) {
			*retval = zone->u.szone.max_trans_time_out;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a "
			      "max_trans_time_out field");
		return (ISC_R_FAILURE);
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a "
			      "max_trans_time_out field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "max_trans_time_out field");
		return (ISC_R_FAILURE);
	}

	return (res);
}



isc_result_t
dns_c_zone_getmaxtransidlein(dns_c_zone_t *zone,
			     isc_int32_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;

	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Master zones do not have a "
			      "max_trans_idle_in field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		if (DNS_C_CHECKBIT(SZ_MAX_TRANS_IDLE_IN_BIT,
				   &zone->u.szone.setflags)) {
			*retval = zone->u.szone.max_trans_idle_in;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_stub:
		if (DNS_C_CHECKBIT(TZ_MAX_TRANS_IDLE_IN_BIT,
				   &zone->u.tzone.setflags)) {
			*retval = zone->u.tzone.max_trans_idle_in;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a "
			      "max_trans_idle_in field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "max_trans_idle_in field");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_getmaxtransidleout(dns_c_zone_t *zone,
			     isc_int32_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;

	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		if (DNS_C_CHECKBIT(SZ_MAX_TRANS_IDLE_OUT_BIT,
				   &zone->u.mzone.setflags)) {
			*retval = zone->u.mzone.max_trans_idle_out;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
			
	case dns_c_zone_slave:
		if (DNS_C_CHECKBIT(SZ_MAX_TRANS_IDLE_OUT_BIT,
				   &zone->u.szone.setflags)) {
			*retval = zone->u.szone.max_trans_idle_out;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a "
			      "max_trans_idle_out field");
		return (ISC_R_FAILURE);
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a "
			      "max_trans_idle_out field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "max_trans_idle_out field");
		return (ISC_R_FAILURE);
	}

	return (res);
}



isc_result_t
dns_c_zone_getmaxixfrlog(dns_c_zone_t *zone,
			 isc_int32_t *retval)
{
	isc_result_t res;
	dns_c_setbits_t *bits = NULL;
	int bit = 0;
	isc_int32_t *ptr = NULL;
	

	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		bits = &zone->u.mzone.setflags;
		bit = MZ_MAX_IXFR_LOG_BIT;
		ptr = &zone->u.mzone.max_ixfr_log;
		break;
			
	case dns_c_zone_slave:
		bits = &zone->u.szone.setflags;
		bit = SZ_MAX_IXFR_LOG_BIT;
		ptr = &zone->u.szone.max_ixfr_log;
		break;
		
	case dns_c_zone_stub:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Stub zones do not have a max_ixfr_log field");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a max_ixfr_log field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Forward zones do not have a "
			      "max_ixfr_log field");
		return (ISC_R_FAILURE);
	}

	if (DNS_C_CHECKBIT(bit, bits)) {
		*retval = *ptr;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}
	
	return (res);
}


isc_result_t
dns_c_zone_getforward(dns_c_zone_t *zone,
		      dns_c_forw_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		if (DNS_C_CHECKBIT(MZ_FORWARD_BIT, &zone->u.mzone.setflags)) {
			*retval = zone->u.mzone.forward;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
			
	case dns_c_zone_slave:
		if (DNS_C_CHECKBIT(SZ_FORWARD_BIT, &zone->u.szone.setflags)) {
			*retval = zone->u.szone.forward;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;

	case dns_c_zone_stub:
		if (DNS_C_CHECKBIT(TZ_FORWARD_BIT, &zone->u.tzone.setflags)) {
			*retval = zone->u.tzone.forward;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;

	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a forward field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		if (DNS_C_CHECKBIT(FZ_FORWARD_BIT, &zone->u.fzone.setflags)) {
			*retval = zone->u.fzone.forward;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
	}

	return (res);
}


isc_result_t
dns_c_zone_getforwarders(dns_c_zone_t *zone,
			 dns_c_iplist_t **retval)
{
	isc_result_t res = ISC_R_SUCCESS;
	
	REQUIRE(DNS_C_ZONE_VALID(zone));
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		if (zone->u.mzone.forwarders != NULL &&
		    zone->u.mzone.forwarders->nextidx > 0) {
			*retval = zone->u.mzone.forwarders;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
			
	case dns_c_zone_slave:
		if (zone->u.szone.forwarders != NULL &&
		    zone->u.szone.forwarders->nextidx > 0) {
			*retval = zone->u.szone.forwarders;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_stub:
		if (zone->u.tzone.forwarders != NULL &&
		    zone->u.tzone.forwarders->nextidx > 0) {
			*retval = zone->u.tzone.forwarders;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
		
	case dns_c_zone_hint:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Hint zones do not have a forwarders field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		if (zone->u.fzone.forwarders != NULL &&
		    zone->u.fzone.forwarders->nextidx > 0) {
			*retval = zone->u.fzone.forwarders;
			res = ISC_R_SUCCESS;
		} else {
			res = ISC_R_NOTFOUND;
		}
		break;
	}

	return (res);
}


/*
 * Zone privates
 */

static void
master_zone_print(FILE *fp, int indent,
		  dns_c_masterzone_t *mzone)
{
	REQUIRE(mzone != NULL);
	
	if (mzone->file != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "file \"%s\";\n", mzone->file);
	}

	if (DNS_C_CHECKBIT(MZ_CHECK_NAME_BIT, &mzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "check-names %s;\n",
			dns_c_nameseverity2string(mzone->check_names,
						  ISC_TRUE));
	}

	if (mzone->allow_update != NULL &&
	    !ISC_LIST_EMPTY(mzone->allow_update->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-update ");
		dns_c_ipmatchlist_print(fp, indent + 1,
					mzone->allow_update);
		fprintf(fp, ";\n");
	}

	if (mzone->allow_query != NULL &&
	    !ISC_LIST_EMPTY(mzone->allow_query->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-query ");
		dns_c_ipmatchlist_print(fp, indent + 1,
					mzone->allow_query);
		fprintf(fp, ";\n");
	}

	if (mzone->allow_transfer != NULL &&
	    !ISC_LIST_EMPTY(mzone->allow_transfer->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-transfer ");
		dns_c_ipmatchlist_print(fp, indent + 1,
					mzone->allow_transfer);
		fprintf(fp, ";\n");
	}

	if (DNS_C_CHECKBIT(MZ_DIALUP_BIT, &mzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "dialup %s;\n",
			(mzone->dialup ? "true" : "false"));
	}

	if (DNS_C_CHECKBIT(MZ_MAINT_IXFR_BASE_BIT, &mzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "maintain-ixfr-base %s;\n",
			(mzone->maint_ixfr_base ? "true" : "false"));
	}

	if (DNS_C_CHECKBIT(MZ_NOTIFY_BIT, &mzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "notify %s;\n",
			(mzone->notify ? "true" : "false"));
	}

	if (mzone->also_notify != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "also-notify ");
		dns_c_iplist_print(fp, indent + 1, mzone->also_notify);
		fprintf(fp, ";\n");
	}

	if (mzone->ixfr_base != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "ixfr-base \"%s\";\n", mzone->ixfr_base);
	}

	if (mzone->ixfr_tmp != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "ixfr-tmp-file \"%s\";\n", mzone->ixfr_tmp);
	}

	if (DNS_C_CHECKBIT(MZ_MAX_TRANS_IDLE_OUT_BIT, &mzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "max-transfer-idle-out %d;\n",
			mzone->max_trans_idle_out / 60);
	}

	if (DNS_C_CHECKBIT(MZ_MAX_TRANS_TIME_OUT_BIT, &mzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "max-transfer-time-out %d;\n",
			mzone->max_trans_time_out / 60);
	}
	
	if (mzone->pubkeylist != NULL) {
		fprintf(fp, "\n");
		dns_c_pklist_print(fp, indent, mzone->pubkeylist);
	}

	if (DNS_C_CHECKBIT(MZ_FORWARD_BIT, &mzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "forward %s;\n",
			dns_c_forward2string(mzone->forward, ISC_TRUE));
	}

	if (mzone->forwarders != NULL && mzone->forwarders->nextidx > 0) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "forwarders ");
		dns_c_iplist_print(fp, indent + 1,
				   mzone->forwarders);
		fprintf(fp, ";\n");
	}
}


static void
slave_zone_print(FILE *fp, int indent,
		 dns_c_slavezone_t *szone)
{
	REQUIRE(szone != NULL);
	
	if (szone->file != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "file \"%s\";\n", szone->file);
	}

	if (szone->ixfr_base != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "ixfr-base \"%s\";\n", szone->ixfr_base);
	}

	if (szone->ixfr_tmp != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "ixfr-tmp-file \"%s\";\n", szone->ixfr_tmp);
	}

	if (DNS_C_CHECKBIT(SZ_MAINT_IXFR_BASE_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "maintain-ixfr-base %s;\n",
			(szone->maint_ixfr_base ? "true" : "false"));
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "masters ");
	if (DNS_C_CHECKBIT(SZ_MASTER_PORT_BIT, &szone->setflags)) {
		if (szone->master_port != 0) {
			fprintf(fp, "port %d ", szone->master_port);
		}
	}
	if (szone->master_ips == NULL ||
	    szone->master_ips->nextidx == 0) {
		fprintf(fp, "{ /* none defined */ }");
	} else {
		dns_c_iplist_print(fp, indent + 1, szone->master_ips);
	}
	fprintf(fp, ";\n");

	if (DNS_C_CHECKBIT(SZ_FORWARD_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "forward %s;\n",
			dns_c_forward2string(szone->forward, ISC_TRUE));
	}

	if (szone->forwarders != NULL && szone->forwarders->nextidx > 0) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "forwarders ");
		dns_c_iplist_print(fp, indent + 1,
				   szone->forwarders);
		fprintf(fp, ";\n");
	}

	if (DNS_C_CHECKBIT(SZ_CHECK_NAME_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "check-names %s;\n",
			dns_c_nameseverity2string(szone->check_names,
						  ISC_TRUE));
	}

	if (szone->allow_update != NULL &&
	    !ISC_LIST_EMPTY(szone->allow_update->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-update ");
		dns_c_ipmatchlist_print(fp, indent + 1,
					szone->allow_update);
		fprintf(fp, ";\n");
	}

	if (szone->allow_query != NULL &&
	    !ISC_LIST_EMPTY(szone->allow_query->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-query ");
		dns_c_ipmatchlist_print(fp, indent + 1,
					szone->allow_query);
		fprintf(fp, ";\n");
	}

	if (szone->allow_transfer != NULL &&
	    !ISC_LIST_EMPTY(szone->allow_transfer->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-transfer ");
		dns_c_ipmatchlist_print(fp, indent + 1,
					szone->allow_transfer);
		fprintf(fp, ";\n");
	}

	if (DNS_C_CHECKBIT(SZ_TRANSFER_SOURCE_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "transfer-source ");
		dns_c_print_ipaddr(fp, &szone->transfer_source);
		fprintf(fp, " ;\n");
	}

	if (DNS_C_CHECKBIT(SZ_MAX_TRANS_TIME_IN_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "max-transfer-time-in %d;\n",
			szone->max_trans_time_in / 60);
	}
	
	if (DNS_C_CHECKBIT(SZ_MAX_TRANS_TIME_OUT_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "max-transfer-time-out %d;\n",
			szone->max_trans_time_out / 60);
	}
	
	if (DNS_C_CHECKBIT(SZ_MAX_TRANS_IDLE_IN_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "max-transfer-idle-in %d;\n",
			szone->max_trans_idle_in / 60);
	}
	
	if (DNS_C_CHECKBIT(SZ_MAX_TRANS_IDLE_OUT_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "max-transfer-idle-out %d;\n",
			szone->max_trans_idle_out / 60);
	}
	
	if (DNS_C_CHECKBIT(SZ_DIALUP_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "dialup %s;\n",
			(szone->dialup ? "true" : "false"));
	}

	if (DNS_C_CHECKBIT(SZ_NOTIFY_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "notify %s;\n",
			(szone->notify ? "true" : "false"));
	}

	if (szone->also_notify != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "also-notify ");
		dns_c_iplist_print(fp, indent + 1, szone->also_notify);
		fprintf(fp, ";\n");
	}

	if (szone->pubkeylist != NULL) {
		fprintf(fp, "\n");
		dns_c_pklist_print(fp, indent, szone->pubkeylist);
	}
}


static void
stub_zone_print(FILE *fp, int indent, dns_c_stubzone_t *tzone)
{
	REQUIRE(tzone != NULL);
	
	if (tzone->file != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "file \"%s\";\n", tzone->file);
	}


	dns_c_printtabs(fp, indent);
	fprintf(fp, "masters ");
	if (DNS_C_CHECKBIT(TZ_MASTER_PORT_BIT, &tzone->setflags)) {
		if (tzone->master_port != 0) {
			fprintf(fp, "port %d ", tzone->master_port);
		}
	}
	if (tzone->master_ips == NULL ||
	    tzone->master_ips->nextidx == 0) {
		fprintf(fp, "{ /* none defined */ }");
	} else {
		dns_c_iplist_print(fp, indent + 1, tzone->master_ips);
	}
	fprintf(fp, ";\n");

	if (DNS_C_CHECKBIT(TZ_FORWARD_BIT, &tzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "forward %s;\n",
			dns_c_forward2string(tzone->forward, ISC_TRUE));
	}

	if (tzone->forwarders != NULL && tzone->forwarders->nextidx > 0) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "forwarders ");
		dns_c_iplist_print(fp, indent + 1,
				   tzone->forwarders);
		fprintf(fp, ";\n");
	}

	if (DNS_C_CHECKBIT(TZ_CHECK_NAME_BIT, &tzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "check-names %s;\n",
			dns_c_nameseverity2string(tzone->check_names,
						  ISC_TRUE));
	}

	if (tzone->allow_update != NULL &&
	    !ISC_LIST_EMPTY(tzone->allow_update->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-update ");
		dns_c_ipmatchlist_print(fp, indent + 1,
					tzone->allow_update);
		fprintf(fp, ";\n");
	}

	if (tzone->allow_query != NULL &&
	    !ISC_LIST_EMPTY(tzone->allow_query->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-query ");
		dns_c_ipmatchlist_print(fp, indent + 1,
					tzone->allow_query);
		fprintf(fp, ";\n");
	}

	if (tzone->allow_transfer != NULL &&
	    !ISC_LIST_EMPTY(tzone->allow_transfer->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-transfer ");
		dns_c_ipmatchlist_print(fp, indent + 1,
					tzone->allow_transfer);
		fprintf(fp, ";\n");
	}

	if (DNS_C_CHECKBIT(TZ_DIALUP_BIT, &tzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "dialup %s;\n",
			(tzone->dialup ? "true" : "false"));
	}

	if (DNS_C_CHECKBIT(TZ_TRANSFER_SOURCE_BIT, &tzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "transfer-source ");
		dns_c_print_ipaddr(fp, &tzone->transfer_source);
		fprintf(fp, ";\n");
	}

	if (DNS_C_CHECKBIT(TZ_MAX_TRANS_TIME_IN_BIT, &tzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "max-transfer-time-in %d;\n",
			tzone->max_trans_time_in / 60);
	}
	
	if (DNS_C_CHECKBIT(TZ_MAX_TRANS_IDLE_IN_BIT, &tzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "max-transfer-idle-in %d;\n",
			tzone->max_trans_idle_in / 60);
	}
	
	if (tzone->pubkeylist != NULL) {
		fprintf(fp, "\n");
		dns_c_pklist_print(fp, indent, tzone->pubkeylist);
	}
}


static void
hint_zone_print(FILE *fp, int indent, dns_c_hintzone_t *hzone)
{
	REQUIRE(hzone != NULL);
	
	if (hzone->file != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "file \"%s\";\n", hzone->file);
	}

	if (DNS_C_CHECKBIT(HZ_CHECK_NAME_BIT, &hzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "check-names %s;\n",
			dns_c_nameseverity2string(hzone->check_names,
						  ISC_TRUE));
	}

	if (hzone->pubkeylist != NULL) {
		fprintf(fp, "\n");
		dns_c_pklist_print(fp, indent, hzone->pubkeylist);
	}
}


static void
forward_zone_print(FILE *fp, int indent,
		   dns_c_forwardzone_t *fzone)
{
	REQUIRE(fzone != NULL);
	
	if (DNS_C_CHECKBIT(FZ_FORWARD_BIT, &fzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "forward %s;\n",
			dns_c_forward2string(fzone->forward, ISC_TRUE));
	}

	if (fzone->forwarders != NULL && fzone->forwarders->nextidx > 0) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "forwarders ");
		dns_c_iplist_print(fp, indent + 1,
				   fzone->forwarders);
		fprintf(fp, ";\n");
	}

	if (DNS_C_CHECKBIT(FZ_CHECK_NAME_BIT, &fzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "check-names %s;\n",
			dns_c_nameseverity2string(fzone->check_names,
						  ISC_TRUE));
	}
}


static isc_result_t
master_zone_init(dns_c_masterzone_t *mzone)
{
	REQUIRE(mzone != NULL);
	
	mzone->file = NULL;
	mzone->allow_update = NULL;
	mzone->allow_query = NULL;
	mzone->allow_transfer = NULL;
	mzone->also_notify = NULL;
	mzone->ixfr_base = NULL;
	mzone->ixfr_tmp = NULL;
	mzone->pubkeylist = NULL;
	mzone->forwarders = NULL;

	memset(&mzone->setflags, 0x0, sizeof (mzone->setflags));

	return (ISC_R_SUCCESS);
}


static isc_result_t
slave_zone_init(dns_c_slavezone_t *szone)
{
	REQUIRE(szone != NULL);

	szone->file = NULL;
	szone->ixfr_base = NULL;
	szone->ixfr_tmp = NULL;
	szone->master_ips = NULL;
	szone->allow_update = NULL;
	szone->allow_query = NULL;
	szone->allow_transfer = NULL;
	szone->also_notify = NULL;
	szone->pubkeylist = NULL;
	szone->forwarders = NULL;

	memset(&szone->setflags, 0x0, sizeof (szone->setflags));

	return (ISC_R_SUCCESS);
}


static isc_result_t
stub_zone_init(dns_c_stubzone_t *tzone)
{
	REQUIRE(tzone != NULL);

	tzone->file = NULL;
	tzone->master_ips = NULL;
	tzone->allow_update = NULL;
	tzone->allow_query = NULL;
	tzone->allow_transfer = NULL;
	tzone->pubkeylist = NULL;
	tzone->forwarders = NULL;

	memset(&tzone->setflags, 0x0, sizeof (tzone->setflags));

	return (ISC_R_SUCCESS);
}


static isc_result_t
hint_zone_init(dns_c_hintzone_t *hzone)
{
	REQUIRE(hzone != NULL);

	hzone->file = NULL;
	hzone->pubkeylist = NULL;
	memset(&hzone->setflags, 0x0, sizeof (hzone->setflags));

	return (ISC_R_SUCCESS);
}


static isc_result_t
forward_zone_init(dns_c_forwardzone_t *fzone)
{
	REQUIRE(fzone != NULL);

	fzone->forwarders = NULL;
	memset(&fzone->setflags, 0x0, sizeof (fzone->setflags));

	return (ISC_R_SUCCESS);
}


static isc_result_t
zone_delete(dns_c_zone_t **zone)
{
	dns_c_zone_t *z;
	isc_result_t res = ISC_R_SUCCESS;
	
	REQUIRE(zone != NULL);
	REQUIRE(DNS_C_ZONE_VALID(*zone));

	z = *zone;

	isc_mem_free(z->mem, z->name);
	isc_mem_free(z->mem, z->internalname);
	
	switch(z->ztype) {
	case dns_c_zone_master:
		res = master_zone_clear(z->mem, &z->u.mzone);
		break;

	case dns_c_zone_slave:
		res = slave_zone_clear(z->mem, &z->u.szone);
		break;
		
	case dns_c_zone_stub:
		res = stub_zone_clear(z->mem, &z->u.tzone);
		break;
		
	case dns_c_zone_hint:
		res = hint_zone_clear(z->mem, &z->u.hzone);
		break;
		
	case dns_c_zone_forward:
		res = forward_zone_clear(z->mem, &z->u.fzone);
		break;
	}

	z->magic = 0;
	z->view = NULL;
	isc_mem_put(z->mem, z, sizeof *z);

	return (res);
}


static isc_result_t
master_zone_clear(isc_mem_t *mem, dns_c_masterzone_t *mzone)
{
	REQUIRE(mzone != NULL);
	
	if (mzone == NULL) {
		return (ISC_R_SUCCESS);
	}

	if (mzone->file != NULL) {
		isc_mem_free(mem, mzone->file);
	}

	if (mzone->allow_update != NULL)
		dns_c_ipmatchlist_detach(&mzone->allow_update);

	if (mzone->allow_query != NULL)
		dns_c_ipmatchlist_detach(&mzone->allow_query);

	if (mzone->allow_transfer != NULL)
		dns_c_ipmatchlist_detach(&mzone->allow_transfer);

	if (mzone->also_notify != NULL)
		dns_c_iplist_detach(&mzone->also_notify);
	
	if (mzone->ixfr_base != NULL) {
		isc_mem_free(mem, mzone->ixfr_base);
	}
		
	if (mzone->ixfr_tmp != NULL) {
		isc_mem_free(mem, mzone->ixfr_tmp);
	}

	if (mzone->pubkeylist != NULL)
		dns_c_pklist_delete(&mzone->pubkeylist);

	if (mzone->forwarders != NULL)
		dns_c_iplist_detach(&mzone->forwarders);

	return (ISC_R_SUCCESS);
}


static isc_result_t
slave_zone_clear(isc_mem_t *mem, dns_c_slavezone_t *szone)
{
	REQUIRE(szone != NULL);
	
	if (szone == NULL) {
		return (ISC_R_SUCCESS);
	}

	if (szone->file != NULL) {
		isc_mem_free(mem, szone->file);
	}

	if (szone->ixfr_base != NULL) {
		isc_mem_free(mem, szone->ixfr_base);
	}
		
	if (szone->ixfr_tmp != NULL) {
		isc_mem_free(mem, szone->ixfr_tmp);
	}
		
	if (szone->master_ips != NULL)
		dns_c_iplist_detach(&szone->master_ips);
	
	if (szone->allow_update != NULL)
		dns_c_ipmatchlist_detach(&szone->allow_update);
	
	if (szone->allow_query != NULL)
		dns_c_ipmatchlist_detach(&szone->allow_query);
	
	if (szone->allow_transfer != NULL)
		dns_c_ipmatchlist_detach(&szone->allow_transfer);
	
	if (szone->also_notify != NULL)
		dns_c_iplist_detach(&szone->also_notify);
	
	if (szone->forwarders != NULL)
		dns_c_iplist_detach(&szone->forwarders);
	
	if (szone->pubkeylist != NULL)
		dns_c_pklist_delete(&szone->pubkeylist);

	return (ISC_R_SUCCESS);
}



static isc_result_t
stub_zone_clear(isc_mem_t *mem, dns_c_stubzone_t *tzone)
{
	REQUIRE(tzone != NULL);
	
	if (tzone == NULL) {
		return (ISC_R_SUCCESS);
	}

	if (tzone->file != NULL) {
		isc_mem_free(mem, tzone->file);
	}

	if (tzone->master_ips != NULL)
		dns_c_iplist_detach(&tzone->master_ips);
	
	if (tzone->allow_update != NULL)
		dns_c_ipmatchlist_detach(&tzone->allow_update);
	
	if (tzone->allow_query != NULL)
		dns_c_ipmatchlist_detach(&tzone->allow_query);
	
	if (tzone->allow_transfer != NULL)
		dns_c_ipmatchlist_detach(&tzone->allow_transfer);
	
	if (tzone->forwarders != NULL)
		dns_c_iplist_detach(&tzone->forwarders);
	
	if (tzone->pubkeylist != NULL)
		dns_c_pklist_delete(&tzone->pubkeylist);
	
	return (ISC_R_SUCCESS);
}


static isc_result_t
forward_zone_clear(isc_mem_t *mem, dns_c_forwardzone_t *fzone)
{
	REQUIRE(fzone != NULL);
	
	if (fzone == NULL) {
		return (ISC_R_SUCCESS);
	}

	(void) mem;			/* lint happiness */
	
	if (fzone->forwarders != NULL)
		dns_c_iplist_detach(&fzone->forwarders);
	
	return (ISC_R_SUCCESS);
}


static isc_result_t
hint_zone_clear(isc_mem_t *mem, dns_c_hintzone_t *hzone)
{
	REQUIRE(hzone != NULL);
	
	if (hzone == NULL) {
		return (ISC_R_SUCCESS);
	}

	if (hzone->file != NULL) {
		isc_mem_free(mem, hzone->file);
	}
	
	if (hzone->pubkeylist != NULL)
		dns_c_pklist_delete(&hzone->pubkeylist);
	
	return (ISC_R_SUCCESS);
}


/**************************************************/

static isc_result_t
set_ipmatch_list_field(isc_mem_t *mem,
		       dns_c_ipmatchlist_t **dest, dns_c_ipmatchlist_t *src,
		       isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	if (*dest != NULL) {
		res = dns_c_ipmatchlist_detach(dest);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	if (deepcopy) {
		res = dns_c_ipmatchlist_copy(mem, dest, src);
	} else {
		*dest = src;
		res = ISC_R_SUCCESS;
	}

	return (res);
}


static isc_result_t
set_iplist_field(isc_mem_t *mem,
		 dns_c_iplist_t **dest, dns_c_iplist_t *src,
		 isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	if (*dest != NULL) {
		res = dns_c_iplist_detach(dest);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	if (deepcopy) {
		res = dns_c_iplist_copy(mem, dest, src);
	} else {
		*dest = src;
		res = ISC_R_SUCCESS;
	}

	return (res);
}

