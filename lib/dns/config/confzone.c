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

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <isc/assertions.h>

#include <dns/confzone.h>
#include <dns/confcommon.h>
#include "confpvt.h"


/*
 * Bit positions in the dns_c_master_zone_t structure setflags field.
 */
#define MZ_CHECK_NAME_BIT		0
#define MZ_DIALUP_BIT			1
#define MZ_NOTIFY_BIT			2
#define MZ_MAINT_IXFR_BASE_BIT		3
#define MZ_MAX_IXFR_LOG_BIT		4


/*
 * Bit positions in the dns_c_slave_zone_t structure setflags field.
 */
#define SZ_CHECK_NAME_BIT		0
#define SZ_DIALUP_BIT			1
#define SZ_MASTER_PORT_BIT		2
#define SZ_TRANSFER_SOURCE_BIT		3
#define SZ_MAX_TRANS_TIME_IN_BIT	4
#define SZ_NOTIFY_BIT			5
#define SZ_MAINT_IXFR_BASE_BIT		6
#define SZ_MAX_IXFR_LOG_BIT		7


#define TZ_CHECK_NAME_BIT		0
#define TZ_DIALUP_BIT			1
#define TZ_MASTER_PORT_BIT		2
#define TZ_TRANSFER_SOURCE_BIT		3
#define TZ_MAX_TRANS_TIME_IN_BIT	4


/*
 * Bit positions in the dns_c_forward_zone_t structure setflags field.
 */
#define FZ_CHECK_NAME_BIT		0
#define FZ_FORWARD_BIT			1


/*
 * Bit positions in the dns_c_hint_zone_t structure setflags field.
 */
#define HZ_CHECK_NAME_BIT		0


typedef enum { zones_preopts, zones_postopts, zones_all } zone_print_type;

static isc_result_t master_zone_init(dns_c_master_zone_t *mzone);
static isc_result_t slave_zone_init(dns_c_slave_zone_t *szone);
static isc_result_t stub_zone_init(dns_c_stub_zone_t *szone);
static isc_result_t hint_zone_init(dns_c_hint_zone_t *hzone);
static isc_result_t forward_zone_init(dns_c_forward_zone_t *fzone);
static isc_result_t zone_delete(dns_c_zone_t **zone);
static isc_result_t master_zone_clear(isc_mem_t *mem,
				      dns_c_master_zone_t *mzone);
static isc_result_t slave_zone_clear(isc_mem_t *mem,
				     dns_c_slave_zone_t *szone);
static isc_result_t stub_zone_clear(isc_mem_t *mem,
				     dns_c_stub_zone_t *szone);
static isc_result_t forward_zone_clear(isc_mem_t *mem,
				       dns_c_forward_zone_t *fzone);
static isc_result_t hint_zone_clear(isc_mem_t *mem,
				    dns_c_hint_zone_t *hzone);

static void	master_zone_print(FILE *fp, int indent,
				  dns_c_master_zone_t *mzone);
static void	slave_zone_print(FILE *fp, int indent,
				 dns_c_slave_zone_t *szone);
static void	stub_zone_print(FILE *fp, int indent,
				 dns_c_stub_zone_t *szone);
static void	hint_zone_print(FILE *fp, int indent,
				dns_c_hint_zone_t *hzone);
static void	forward_zone_print(FILE *fp, int indent,
				   dns_c_forward_zone_t *fzone);
static isc_result_t set_iplist_field(isc_mem_t *mem,
				     dns_c_iplist_t **dest,
				     dns_c_iplist_t *src,
				     isc_boolean_t deepcopy);
static isc_result_t set_ipmatch_list_field(isc_mem_t *mem,
					   dns_c_ipmatch_list_t **dest,
					   dns_c_ipmatch_list_t *src,
					   isc_boolean_t deepcopy);

static void zone_list_print(zone_print_type zpt, FILE *fp, int indent,
			    dns_c_zone_list_t *list);



isc_result_t
dns_c_zone_list_new(isc_mem_t *mem, dns_c_zone_list_t **zlist)
{
	dns_c_zone_list_t *list;

	REQUIRE(zlist != NULL);

	list = isc_mem_get(mem, sizeof *list);
	if (list == NULL) {
		return (ISC_R_NOMEMORY);
	}

	list->mem = mem;

	ISC_LIST_INIT(list->zones);

	*zlist = list;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_list_delete(dns_c_zone_list_t **zlist)
{
	dns_c_zone_list_t *list;
	dns_c_zone_t *zone, *tmpzone;
	isc_result_t res;

	REQUIRE(zlist != NULL);

	list = *zlist;
	if (list == NULL) {
		return (ISC_R_SUCCESS);
	}

	zone = ISC_LIST_HEAD(list->zones);
	while (zone != NULL) {
		tmpzone = ISC_LIST_NEXT(zone, next);
		ISC_LIST_UNLINK(list->zones, zone, next);

		res = zone_delete(&zone);
		if (res != NULL) {
			return (res);
		}

		zone = tmpzone;
	}

	isc_mem_put(list->mem, list, sizeof *list);

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_list_find(dns_c_zone_list_t *zlist, const char *name,
		     dns_c_zone_t **retval)
{
	dns_c_zone_t *zone;

	REQUIRE(zlist != NULL);
	REQUIRE(name != NULL);
	REQUIRE(strlen(name) > 0);
	REQUIRE(retval != NULL);

	zone = ISC_LIST_HEAD(zlist->zones);
	while (zone != NULL) {
		if (strcmp(name, zone->name) == 0) {
			break;
		}
	}

	if (zone != NULL) {
		*retval = zone;
	}

	return (zone == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_list_rmbyname(dns_c_zone_list_t *zlist, const char *name)
{
	dns_c_zone_t *zone;
	isc_result_t res;

	res = dns_c_zone_list_find(zlist, name, &zone);
	if (res == ISC_R_SUCCESS) {
		ISC_LIST_UNLINK(zlist->zones, zone, next);
		res = zone_delete(&zone);
	}

	return (res);
}


isc_result_t
dns_c_zone_list_rmzone(dns_c_zone_list_t *zlist, dns_c_zone_t *zone)
{
	isc_result_t res;
	
	REQUIRE(zlist != NULL);
	REQUIRE(zone != NULL);

	ISC_LIST_UNLINK(zlist->zones, zone, next);
	res = zone_delete(&zone);

	return (res);
}


void
dns_c_zone_list_print(FILE *fp, int indent, dns_c_zone_list_t *list)
{
	zone_list_print(zones_all, fp, indent, list);
}


void
dns_c_zone_list_print_preopts(FILE *fp, int indent, dns_c_zone_list_t *list)
{
	zone_list_print(zones_preopts, fp, indent, list);
}


void
dns_c_zone_list_print_postopts(FILE *fp, int indent, dns_c_zone_list_t *list)
{
	zone_list_print(zones_postopts, fp, indent, list);
}



static void
zone_list_print(zone_print_type zpt, FILE *fp, int indent,
		dns_c_zone_list_t *list) 
{
	dns_c_zone_t *zone;
	
	REQUIRE(fp != NULL);
	REQUIRE(indent >= 0);

	if (list == NULL) {
		return;
	}

#define PRINTIT(zone, zpt)						\
	((zpt == zones_preopts && zone->afteropts == ISC_FALSE) ||	\
	 (zpt == zones_postopts && zone->afteropts == ISC_TRUE) ||	\
	 zpt == zones_all)
			    
	zone = ISC_LIST_HEAD(list->zones);
	while (zone != NULL) {
		if (PRINTIT(zone, zpt)) {
			dns_c_zone_print(fp, indent, zone);
		}
		
		zone = ISC_LIST_NEXT(zone, next);
		if (zone != NULL && PRINTIT(zone, zpt)) {
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
dns_c_zone_new(dns_c_zone_list_t *zlist, dns_c_zonetype_t ztype,
	       dns_rdataclass_t zclass, const char *name, dns_c_zone_t **zone)
{
	dns_c_zone_t *newzone;
	isc_result_t res;

	REQUIRE(zlist != NULL);
	REQUIRE(name != NULL);
	REQUIRE(strlen(name) > 0);

	newzone = isc_mem_get(zlist->mem, sizeof *newzone);
	if (newzone == NULL) {
		return (ISC_R_NOMEMORY);
	}

	newzone->mylist = zlist;
	newzone->ztype = ztype;
	newzone->zclass = zclass;
	newzone->afteropts = ISC_FALSE;
	newzone->name = isc_mem_strdup(zlist->mem, name);

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
	
	ISC_LIST_APPEND(zlist->zones, newzone, next);
	
	*zone = newzone;

	return (ISC_R_SUCCESS);
}


void
dns_c_zone_print(FILE *fp, int indent, dns_c_zone_t *zone)
{
	REQUIRE(fp != NULL);

	if(zone == NULL) {
		return;
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "zone \"%s\"", zone->name);
	if (zone->zclass != dns_rdataclass_in) {
		fputc(' ', fp);
		dns_c_dataclass_to_stream(fp, zone->zclass);
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
dns_c_zone_set_file(dns_c_zone_t *zone, const char *newfile)
{
	char **p = NULL;
	isc_result_t res;
	
	REQUIRE(zone != NULL);

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
		dns_c_error(0, "Forward zones do not have a file field\n");
		return (ISC_R_FAILURE);
	}

	if (*p != NULL) {
		isc_mem_free(zone->mylist->mem, *p);
		res = ISC_R_EXISTS;
	} else {
		res = ISC_R_SUCCESS;
	}

	*p = isc_mem_strdup(zone->mylist->mem, newfile);
	if (*p == NULL) {
		res = ISC_R_NOMEMORY;
	}

	return (res);
}


isc_result_t
dns_c_zone_set_checknames(dns_c_zone_t *zone, dns_c_severity_t severity)
{
	dns_c_severity_t *p = NULL;
	dns_setbits_t *bits = NULL;
	int bit = 0;
	isc_result_t res;
	
	REQUIRE(zone != NULL);

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
dns_c_zone_set_allow_upd(dns_c_zone_t *zone, dns_c_ipmatch_list_t *ipml,
			 isc_boolean_t deepcopy)
{
	dns_c_ipmatch_list_t **p = NULL;
	isc_result_t res;
	isc_boolean_t existed;
	
	REQUIRE(zone != NULL);
	REQUIRE(ipml != NULL);

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
		dns_c_error(0, "Hint zones do not have an allow_update field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0,
			    "Forward zones do not have an allow_update field");
		return (ISC_R_FAILURE);
	}

	existed = (*p != NULL ? ISC_TRUE : ISC_FALSE);
	
	res = set_ipmatch_list_field(zone->mylist->mem, p, ipml, deepcopy);
	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}

	return (res);
}


isc_result_t
dns_c_zone_set_allow_query(dns_c_zone_t *zone, dns_c_ipmatch_list_t *ipml,
			   isc_boolean_t deepcopy)
{
	dns_c_ipmatch_list_t **p = NULL;
	isc_boolean_t existed;
	isc_result_t res;
	
	REQUIRE(zone != NULL);
	REQUIRE(ipml != NULL);

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
		dns_c_error(0, "Hint zones do not have an allow_query field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0,
			    "Forward zones do not have an allow_query field");
		return (ISC_R_FAILURE);
	}

	existed = (*p != NULL ? ISC_TRUE : ISC_FALSE);
	
	res = set_ipmatch_list_field(zone->mylist->mem, p, ipml, deepcopy);
	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}

	return (res);
}


isc_result_t
dns_c_zone_set_allow_transfer(dns_c_zone_t *zone, dns_c_ipmatch_list_t *ipml,
			      isc_boolean_t deepcopy)
{
	dns_c_ipmatch_list_t **p = NULL;
	isc_boolean_t existed;
	isc_result_t res;
	
	REQUIRE(zone != NULL);
	REQUIRE(ipml != NULL);

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
		dns_c_error(0,
			    "Hint zones do not have an allow_transfer field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0,
			 "Forward zones do not have an allow_transfer field");
		return (ISC_R_FAILURE);
	}

	existed = (*p != NULL ? ISC_TRUE : ISC_FALSE);
	res = set_ipmatch_list_field(zone->mylist->mem, p, ipml, deepcopy);

	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}

	return (res);
}


isc_result_t
dns_c_zone_set_dialup(dns_c_zone_t *zone, isc_boolean_t newval)
{
	isc_boolean_t existed = ISC_FALSE;

	REQUIRE(zone != NULL);

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
		dns_c_error(0, "Hint zones do not have a dialup field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a dialup field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_set_notify(dns_c_zone_t *zone, isc_boolean_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(zone != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		zone->u.mzone.notify = newval;
		existed = DNS_C_CHECKBIT(MZ_DIALUP_BIT,
					 &zone->u.mzone.setflags);
		DNS_C_SETBIT(MZ_DIALUP_BIT, &zone->u.mzone.setflags);
		break;
			
	case dns_c_zone_slave:
		zone->u.szone.notify = newval;
		existed = DNS_C_CHECKBIT(SZ_DIALUP_BIT,
					 &zone->u.szone.setflags);
		DNS_C_SETBIT(SZ_DIALUP_BIT, &zone->u.szone.setflags);
		break;
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a notify field");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a notify field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_set_maint_ixfr_base(dns_c_zone_t *zone, isc_boolean_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(zone != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		zone->u.mzone.maint_ixfr_base = newval;
		existed = DNS_C_CHECKBIT(MZ_MAINT_IXFR_BASE_BIT,
					 &zone->u.mzone.setflags);
		DNS_C_SETBIT(MZ_MAINT_IXFR_BASE_BIT, &zone->u.mzone.setflags);
		break;
			
	case dns_c_zone_slave:
		zone->u.szone.notify = newval;
		existed = DNS_C_CHECKBIT(SZ_MAINT_IXFR_BASE_BIT,
					 &zone->u.szone.setflags);
		DNS_C_SETBIT(SZ_MAINT_IXFR_BASE_BIT, &zone->u.szone.setflags);
		break;
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a "
			    "maintain-xfer-base field");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a "
			    "maintain-xfer-base field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a "
			    "maintain-xfer-base field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_set_also_notify(dns_c_zone_t *zone, dns_c_iplist_t *newval,
			   isc_boolean_t deepcopy)
{
	isc_boolean_t existed;
	isc_result_t res;
	dns_c_iplist_t **p = NULL;

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.also_notify ;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.also_notify ;
		break;
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a also_notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a also_notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0,
			    "Forward zones do not have a also_notify field");
		return (ISC_R_FAILURE);
	}

	existed = (*p != NULL ? ISC_TRUE : ISC_FALSE);
	res = set_iplist_field(zone->mylist->mem, p, newval, deepcopy);
	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}

	return (res);
}


isc_result_t
dns_c_zone_set_ixfr_base(dns_c_zone_t *zone, const char *newval)
{
	isc_boolean_t existed ;
	char **p = NULL;
	
	REQUIRE(zone != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.ixfr_base;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.ixfr_base;
		break;
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a ixfr_base field\n");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a ixfr_base field\n");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a file field\n");
		return (ISC_R_FAILURE);
	}

	if (*p != NULL) {
		existed = ISC_TRUE;
		isc_mem_free(zone->mylist->mem, *p);
	} else {
		existed = ISC_FALSE;
	}

	*p = isc_mem_strdup(zone->mylist->mem, newval);
	if (*p == NULL) {
		return (ISC_R_NOMEMORY);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_set_ixfr_tmp(dns_c_zone_t *zone, const char *newval)
{
	isc_boolean_t existed;
	char **p = NULL;
	
	REQUIRE(zone != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.ixfr_tmp;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.ixfr_tmp;
		break;
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a ixfr_tmp field\n");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a ixfr_tmp field\n");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a file field\n");
		return (ISC_R_FAILURE);
	}

	if (*p != NULL) {
		existed = ISC_TRUE;
		isc_mem_free(zone->mylist->mem, *p);
	} else {
		existed = ISC_FALSE;
	}

	*p = isc_mem_strdup(zone->mylist->mem, newval);
	if (*p == NULL) {
		return (ISC_R_NOMEMORY);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_set_pubkey(dns_c_zone_t *zone, dns_c_pubkey_t *pubkey,
		      isc_boolean_t deepcopy)
{
	isc_boolean_t existed;
	dns_c_pubkey_t **p = NULL;
	isc_result_t res;
	
	REQUIRE(zone != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = &zone->u.mzone.pubkey;
		break;
			
	case dns_c_zone_slave:
		p = &zone->u.szone.pubkey;
		break;
		
	case dns_c_zone_stub:
		p = &zone->u.tzone.pubkey;
		break;
		
	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a pubkey field\n");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a pubkey field\n");
		return (ISC_R_FAILURE);
	}

	if (*p != NULL) {
		existed = ISC_TRUE;
		dns_c_pubkey_delete(p);
	} else {
		existed = ISC_FALSE;
	}

	if (deepcopy) {
		res = dns_c_pubkey_copy(zone->mylist->mem, p, pubkey);
	} else {
		*p = pubkey;
		res = ISC_R_SUCCESS;
	}

	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}
	
	return (res);
}


isc_result_t
dns_c_zone_set_master_port(dns_c_zone_t *zone, isc_int32_t port)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(zone != NULL);

	switch(zone->ztype) {
	case dns_c_zone_master:
		dns_c_error(0,
			    "Forward zones do not have a master_port field\n");
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
		dns_c_error(0, "Hint zones do not have a master_port field\n");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0,
			    "Forward zones do not have a master_port field\n");
		return (ISC_R_FAILURE);
	}
		
	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_set_master_ips(dns_c_zone_t *zone, dns_c_iplist_t *newval,
			  isc_boolean_t deepcopy)
{
	isc_boolean_t existed;
	isc_result_t res = ISC_R_SUCCESS;
	dns_c_iplist_t **p;

	switch (zone->ztype) {
	case dns_c_zone_master:
		dns_c_error(0, "Master zones do not have a master_ips field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
	case dns_c_zone_stub:
		if (zone->ztype == dns_c_zone_slave) {
			p = &zone->u.szone.master_ips ;
		} else {
			p = &zone->u.tzone.master_ips ;
		}
		
		existed = (*p != NULL ? ISC_TRUE : ISC_FALSE);
		res = set_iplist_field(zone->mylist->mem, p,
				       newval, deepcopy);
		if (res == ISC_R_SUCCESS && existed) {
			res = ISC_R_EXISTS;
		}
		break;

	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a master_ips field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a master_ips field");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_set_transfer_source(dns_c_zone_t *zone, dns_c_addr_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(zone != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		dns_c_error(0,
			 "Master zones do not have a transfer_source field");
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
		dns_c_error(0, "Hint zones do not have a master_ips field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a master_ips field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_set_max_trans_time_in(dns_c_zone_t *zone,
				 isc_int32_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(zone != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		dns_c_error(0,
			 "Master zones do not have a max_trans_time_in field");
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
		dns_c_error(0,
			 "Hint zones do not have a max_trans_time_in field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
	       dns_c_error(0,
			"Forward zones do not have a max_trans_time_in field");
		return (ISC_R_FAILURE);
	}

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_set_max_ixfr_log(dns_c_zone_t *zone, isc_int32_t newval)
{
	dns_setbits_t *bits = NULL;
	isc_int32_t *p = NULL;
	int bit = 0;
	isc_result_t res;
	
	REQUIRE(zone != NULL);

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
		dns_c_error(0,
			    "Stub zones do not have a max-ixfr-log field\n");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		dns_c_error(0,
			    "Hint zones do not have a max-ixfr-log field\n");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0,
			 "Forward zones do not have a max-ixfr-log field\n");
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
dns_c_zone_set_forward(dns_c_zone_t *zone, dns_c_forw_t newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(zone != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		dns_c_error(0, "Master zones do not have a forward field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		dns_c_error(0, "Slave zones do not have a forward field");
		return (ISC_R_FAILURE);
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a forward field");
		return (ISC_R_FAILURE);
		
	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a forward field");
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
dns_c_zone_set_forwarders(dns_c_zone_t *zone, dns_c_iplist_t *ipl,
			  isc_boolean_t deepcopy)
{
	isc_boolean_t existed = ISC_FALSE;
	isc_result_t res;
	dns_c_iplist_t **p = NULL;
	
	REQUIRE(zone != NULL);
	REQUIRE(ipl != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		dns_c_error(0, "Master zones do not have a forwarders field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		dns_c_error(0, "Slave zones do not have a forwarders field");
		return (ISC_R_FAILURE);
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a forwarders field");
		return (ISC_R_FAILURE);
		
	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a forwarders field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		p = &zone->u.fzone.forwarders;
		existed = (*p == NULL ? ISC_FALSE : ISC_TRUE);
		break;
	}

	res = set_iplist_field(zone->mylist->mem, p, ipl, deepcopy);
	if (res == ISC_R_SUCCESS && existed) {
		res = ISC_R_EXISTS;
	}

	return (res);
}


isc_result_t
dns_c_zone_get_name(dns_c_zone_t *zone, const char **retval)
{
	REQUIRE(zone != NULL);
	REQUIRE(retval != NULL);

	*retval = zone->name;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_zone_get_file(dns_c_zone_t *zone, const char **retval)
{
	const char *p = NULL;
	isc_result_t res;
	
	REQUIRE(zone != NULL);
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
		dns_c_error(0, "Forward zones do not have a file field\n");
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
dns_c_zone_get_checknames(dns_c_zone_t *zone, dns_c_severity_t *retval)
{
	dns_c_severity_t *p = NULL;
	dns_setbits_t *bits = NULL;
	int bit = 0;
	isc_result_t res;
	
	REQUIRE(zone != NULL);
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
dns_c_zone_get_allow_upd(dns_c_zone_t *zone, dns_c_ipmatch_list_t **retval)
{
	dns_c_ipmatch_list_t *p = NULL;
	isc_result_t res;
	
	REQUIRE(zone != NULL);
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
		dns_c_error(0, "Hint zones do not have an allow_update field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0,
			    "Forward zones do not have an allow_update field");
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
dns_c_zone_get_allow_query(dns_c_zone_t *zone, dns_c_ipmatch_list_t **retval)
{
	dns_c_ipmatch_list_t *p = NULL;
	isc_result_t res;
	
	REQUIRE(zone != NULL);
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
		dns_c_error(0, "Hint zones do not have an allow_query field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0,
			    "Forward zones do not have an allow_query field");
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
dns_c_zone_get_allow_transfer(dns_c_zone_t *zone,
			      dns_c_ipmatch_list_t **retval)
{
	dns_c_ipmatch_list_t *p = NULL;
	isc_result_t res;
	
	REQUIRE(zone != NULL);
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
		dns_c_error(0,
			    "Hint zones do not have an allow_transfer field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0,
			 "Forward zones do not have an allow_transfere field");
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
dns_c_zone_get_dialup(dns_c_zone_t *zone, isc_boolean_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;
	
	REQUIRE(zone != NULL);
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
		dns_c_error(0, "Hint zones do not have a dialup field");
		return (ISC_R_FAILURE);
		
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a dialup field");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_get_notify(dns_c_zone_t *zone, isc_boolean_t *retval)
{
	isc_result_t res;
	dns_setbits_t *bits = NULL;
	isc_boolean_t val = ISC_FALSE;
	int bit = 0;
	
	REQUIRE(zone != NULL);
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
		dns_c_error(0, "Stub zones do not have a notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a notify field");
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
dns_c_zone_get_maint_ixfr_base(dns_c_zone_t *zone, isc_boolean_t *retval)
{
	isc_result_t res;
	dns_setbits_t *bits = NULL;
	isc_boolean_t val = ISC_FALSE;
	int bit = 0;
	
	REQUIRE(zone != NULL);
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		val = zone->u.mzone.maint_ixfr_base;
		bit = MZ_MAINT_IXFR_BASE_BIT;
		bits = &zone->u.mzone.setflags;
		break;
			
	case dns_c_zone_slave:
		val = zone->u.szone.notify;
		bit = SZ_MAINT_IXFR_BASE_BIT;
		bits = &zone->u.szone.setflags;
		break;
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a notify field");
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
dns_c_zone_get_also_notify(dns_c_zone_t *zone, dns_c_iplist_t **retval)
{
	dns_c_iplist_t *p = NULL;
	isc_result_t res;

	REQUIRE(zone != NULL);
	REQUIRE(retval != NULL);
	
	switch (zone->ztype) {
	case dns_c_zone_master:
		p = zone->u.mzone.also_notify ;
		break;
			
	case dns_c_zone_slave:
		p = zone->u.szone.also_notify ;
		break;
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a also_notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a also_notify field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0,
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
dns_c_zone_get_ixfr_base(dns_c_zone_t *zone, const char **retval)
{
	char *p = NULL;
	isc_result_t res;
	
	REQUIRE(zone != NULL);
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = zone->u.mzone.ixfr_base;
		break;
			
	case dns_c_zone_slave:
		p = zone->u.szone.ixfr_base;
		break;
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a ixfr_base field\n");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a ixfr_base field\n");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a file field\n");
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
dns_c_zone_get_ixfr_tmp(dns_c_zone_t *zone, const char **retval)
{
	char *p = NULL;
	isc_result_t res;
	
	REQUIRE(zone != NULL);
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = zone->u.mzone.ixfr_tmp;
		break;
			
	case dns_c_zone_slave:
		p = zone->u.szone.ixfr_tmp;
		break;
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a ixfr_tmp field\n");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a ixfr_tmp field\n");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a file field\n");
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
dns_c_zone_get_pubkey(dns_c_zone_t *zone, dns_c_pubkey_t **retval)
{
	dns_c_pubkey_t *p = NULL;
	isc_result_t res;
	
	REQUIRE(zone != NULL);
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		p = zone->u.mzone.pubkey;
		break;
			
	case dns_c_zone_slave:
		p = zone->u.szone.pubkey;
		break;
		
	case dns_c_zone_stub:
		p = zone->u.tzone.pubkey;
		break;
		
	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a pubkey field\n");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a pubkey field\n");
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
dns_c_zone_get_master_port(dns_c_zone_t *zone, isc_int32_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;
	
	REQUIRE(zone != NULL);
	REQUIRE(retval != NULL);

	switch(zone->ztype) {
	case dns_c_zone_master:
		dns_c_error(0,
			    "Forward zones do not have a master_port field\n");
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
		dns_c_error(0, "Hint zones do not have a master_port field\n");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0,
			    "Forward zones do not have a master_port field\n");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_get_master_ips(dns_c_zone_t *zone, dns_c_iplist_t **retval)
{
	isc_result_t res = ISC_R_SUCCESS;

	switch (zone->ztype) {
	case dns_c_zone_master:
		dns_c_error(0, "Master zones do not have a master_ips field");
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
		dns_c_error(0, "Hint zones do not have a master_ips field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a master_ips field");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_get_transfer_source(dns_c_zone_t *zone, dns_c_addr_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;

	REQUIRE(zone != NULL);
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		dns_c_error(0,
			 "Master zones do not have a transfer_source field");
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
		dns_c_error(0, "Hint zones do not have a master_ips field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
		dns_c_error(0, "Forward zones do not have a master_ips field");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_get_max_trans_time_in(dns_c_zone_t *zone, isc_int32_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;

	REQUIRE(zone != NULL);
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		dns_c_error(0,
			 "Master zones do not have a max_trans_time_in field");
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
		dns_c_error(0,
			 "Hint zones do not have a max_trans_time_in field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
	       dns_c_error(0,
			"Forward zones do not have a max_trans_time_in field");
		return (ISC_R_FAILURE);
	}

	return (res);
}


isc_result_t
dns_c_zone_get_max_ixfr_log(dns_c_zone_t *zone, isc_int32_t *retval)
{
	isc_result_t res;
	dns_setbits_t *bits = NULL;
	int bit = 0;
	isc_int32_t *ptr = NULL;
	

	REQUIRE(zone != NULL);
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
		dns_c_error(0,
			    "Stub zones do not have a max_ixfr_log field");
		return (ISC_R_FAILURE);

	case dns_c_zone_hint:
		dns_c_error(0,
			    "Hint zones do not have a max_ixfr_log field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_forward:
	       dns_c_error(0,
			   "Forward zones do not have a max_ixfr_log field");
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
dns_c_zone_get_forward(dns_c_zone_t *zone, dns_c_forw_t *retval)
{
	isc_result_t res = ISC_R_SUCCESS;
	
	REQUIRE(zone != NULL);
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		dns_c_error(0, "Master zones do not have a forward field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		dns_c_error(0, "Slave zones do not have a forward field");
		return (ISC_R_FAILURE);
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a forward field");
		return (ISC_R_FAILURE);
		
	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a forward field");
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
dns_c_zone_get_forwarders(dns_c_zone_t *zone, dns_c_iplist_t **retval)
{
	isc_result_t res = ISC_R_SUCCESS;
	
	REQUIRE(zone != NULL);
	REQUIRE(retval != NULL);

	switch (zone->ztype) {
	case dns_c_zone_master:
		dns_c_error(0, "Master zones do not have a forwarders field");
		return (ISC_R_FAILURE);
			
	case dns_c_zone_slave:
		dns_c_error(0, "Slave zones do not have a forwarders field");
		return (ISC_R_FAILURE);
		
	case dns_c_zone_stub:
		dns_c_error(0, "Stub zones do not have a forwarders field");
		return (ISC_R_FAILURE);
		
	case dns_c_zone_hint:
		dns_c_error(0, "Hint zones do not have a forwarders field");
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
master_zone_print(FILE *fp, int indent, dns_c_master_zone_t *mzone)
{
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
		dns_c_ipmatch_list_print(fp, indent + 1,
					 mzone->allow_update);
	}

	if (mzone->allow_query != NULL &&
	    !ISC_LIST_EMPTY(mzone->allow_query->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-query ");
		dns_c_ipmatch_list_print(fp, indent + 1,
					 mzone->allow_query);
	}

	if (mzone->allow_transfer != NULL &&
	    !ISC_LIST_EMPTY(mzone->allow_transfer->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-transfer ");
		dns_c_ipmatch_list_print(fp, indent + 1,
					 mzone->allow_transfer);
	}

	if (DNS_C_CHECKBIT(MZ_DIALUP_BIT, &mzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "dialup %s;\n",
			(mzone->dialup ? "true" : "false"));
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
	}

	if (mzone->ixfr_base != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "ixfr-base \"%s\";\n", mzone->ixfr_base);
	}

	if (mzone->ixfr_tmp != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "ixfr-tmp-file \"%s\";\n", mzone->ixfr_tmp);
	}

	if (mzone->pubkey != NULL) {
		dns_c_printtabs(fp, indent);
		dns_c_pubkey_print(fp, indent, mzone->pubkey);
	}
}


static void
slave_zone_print(FILE *fp, int indent, dns_c_slave_zone_t *szone)
{
	if (szone->file != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "file \"%s\";\n", szone->file);
	}

	if (DNS_C_CHECKBIT(SZ_CHECK_NAME_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "check-names %s;\n",
			dns_c_nameseverity2string(szone->check_names,
						  ISC_TRUE));
	}

	if (szone->ixfr_base != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "ixfr-base \"%s\";\n", szone->ixfr_base);
	}

	if (szone->ixfr_tmp != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "ixfr-tmp-file \"%s\";\n", szone->ixfr_tmp);
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "masters ");
	if (DNS_C_CHECKBIT(SZ_MASTER_PORT_BIT, &szone->setflags)) {
		if (ntohs(szone->master_port) != 0) {
			fprintf(fp, "port %d ", ntohs(szone->master_port));
		}
	}
	if (szone->master_ips == NULL ||
	    szone->master_ips->nextidx == 0) {
		fprintf(fp, "{ /* none defined */ };\n");
	} else {
		dns_c_iplist_print(fp, indent + 1, szone->master_ips);
	}

	if (szone->allow_update != NULL &&
	    !ISC_LIST_EMPTY(szone->allow_update->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-update ");
		dns_c_ipmatch_list_print(fp, indent + 1,
					 szone->allow_update);
	}

	if (szone->allow_query != NULL &&
	    !ISC_LIST_EMPTY(szone->allow_query->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-query ");
		dns_c_ipmatch_list_print(fp, indent + 1,
					 szone->allow_query);
	}

	if (szone->allow_transfer != NULL &&
	    !ISC_LIST_EMPTY(szone->allow_transfer->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-transfer ");
		dns_c_ipmatch_list_print(fp, indent + 1,
					 szone->allow_transfer);
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
			szone->max_trans_time_in);
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
	}


	if (szone->pubkey != NULL) {
		dns_c_printtabs(fp, indent);
		dns_c_pubkey_print(fp, indent, szone->pubkey);
	}
}


static void
stub_zone_print(FILE *fp, int indent, dns_c_stub_zone_t *szone)
{
	if (szone->file != NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "file \"%s\";\n", szone->file);
	}

	if (DNS_C_CHECKBIT(TZ_CHECK_NAME_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "check-names %s;\n",
			dns_c_nameseverity2string(szone->check_names,
						  ISC_TRUE));
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "masters ");
	if (DNS_C_CHECKBIT(TZ_MASTER_PORT_BIT, &szone->setflags)) {
		if (ntohs(szone->master_port) != 0) {
			fprintf(fp, "port %d ", ntohs(szone->master_port));
		}
	}
	if (szone->master_ips == NULL ||
	    szone->master_ips->nextidx == 0) {
		fprintf(fp, "{ /* none defined */ };\n");
	} else {
		dns_c_iplist_print(fp, indent + 1, szone->master_ips);
	}

	if (szone->allow_update != NULL &&
	    !ISC_LIST_EMPTY(szone->allow_update->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-update ");
		dns_c_ipmatch_list_print(fp, indent + 1,
					 szone->allow_update);
	}

	if (szone->allow_query != NULL &&
	    !ISC_LIST_EMPTY(szone->allow_query->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-query ");
		dns_c_ipmatch_list_print(fp, indent + 1,
					 szone->allow_query);
	}

	if (szone->allow_transfer != NULL &&
	    !ISC_LIST_EMPTY(szone->allow_transfer->elements)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "allow-transfer ");
		dns_c_ipmatch_list_print(fp, indent + 1,
					 szone->allow_transfer);
	}

	if (DNS_C_CHECKBIT(TZ_TRANSFER_SOURCE_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "transfer-source ;\n");
		dns_c_print_ipaddr(fp, &szone->transfer_source);
		fprintf(fp, ";\n");
	}

	if (DNS_C_CHECKBIT(TZ_MAX_TRANS_TIME_IN_BIT, &szone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "max-transfer-time-in %d;\n",
			szone->max_trans_time_in);
	}
	
	if (szone->pubkey != NULL) {
		dns_c_printtabs(fp, indent);
		dns_c_pubkey_print(fp, indent, szone->pubkey);
	}
}


static void
hint_zone_print(FILE *fp, int indent, dns_c_hint_zone_t *hzone)
{
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
}


static void
forward_zone_print(FILE *fp, int indent, dns_c_forward_zone_t *fzone)
{
	if (DNS_C_CHECKBIT(FZ_CHECK_NAME_BIT, &fzone->setflags)) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "check-names %s;\n",
			dns_c_nameseverity2string(fzone->check_names,
						  ISC_TRUE));
	}

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
	}
}


static isc_result_t
master_zone_init(dns_c_master_zone_t *mzone)
{
	mzone->file = NULL;
	mzone->allow_update = NULL;
	mzone->allow_query = NULL;
	mzone->allow_transfer = NULL;
	mzone->also_notify = NULL;
	mzone->ixfr_base = NULL;
	mzone->ixfr_tmp = NULL;
	mzone->pubkey = NULL;

	memset(&mzone->setflags, 0x0, sizeof (mzone->setflags));

	return (ISC_R_SUCCESS);
}


static isc_result_t
slave_zone_init(dns_c_slave_zone_t *szone)
{
	szone->file = NULL;
	szone->ixfr_base = NULL;
	szone->ixfr_tmp = NULL;
	szone->master_ips = NULL;
	szone->allow_update = NULL;
	szone->allow_query = NULL;
	szone->allow_transfer = NULL;
	szone->also_notify = NULL;
	szone->pubkey = NULL;

	memset(&szone->setflags, 0x0, sizeof (szone->setflags));

	return (ISC_R_SUCCESS);
}


static isc_result_t
stub_zone_init(dns_c_stub_zone_t *szone)
{
	szone->file = NULL;
	szone->master_ips = NULL;
	szone->allow_update = NULL;
	szone->allow_query = NULL;
	szone->allow_transfer = NULL;
	szone->pubkey = NULL;

	memset(&szone->setflags, 0x0, sizeof (szone->setflags));

	return (ISC_R_SUCCESS);
}


static isc_result_t
hint_zone_init(dns_c_hint_zone_t *hzone)
{
	hzone->file = NULL;
	memset(&hzone->setflags, 0x0, sizeof (hzone->setflags));

	return (ISC_R_SUCCESS);
}


static isc_result_t
forward_zone_init(dns_c_forward_zone_t *fzone)
{
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

	z = *zone;

	isc_mem_free(z->mylist->mem, z->name);
	switch(z->ztype) {
	case dns_c_zone_master:
		res = master_zone_clear(z->mylist->mem, &z->u.mzone);
		break;

	case dns_c_zone_slave:
		res = slave_zone_clear(z->mylist->mem, &z->u.szone);
		break;
		
	case dns_c_zone_stub:
		res = stub_zone_clear(z->mylist->mem, &z->u.tzone);
		break;
		
	case dns_c_zone_hint:
		res = hint_zone_clear(z->mylist->mem, &z->u.hzone);
		break;
		
	case dns_c_zone_forward:
		res = forward_zone_clear(z->mylist->mem, &z->u.fzone);
		break;
	}

	isc_mem_put(z->mylist->mem, z, sizeof *z);

	return (res);
}


static isc_result_t
master_zone_clear(isc_mem_t *mem, dns_c_master_zone_t *mzone)
{
	if (mzone == NULL) {
		return (ISC_R_SUCCESS);
	}

	if (mzone->file != NULL) {
		isc_mem_free(mem, mzone->file);
	}

	dns_c_ipmatch_list_delete(&mzone->allow_update);
	dns_c_ipmatch_list_delete(&mzone->allow_query);
	dns_c_ipmatch_list_delete(&mzone->allow_transfer);
	dns_c_iplist_delete(&mzone->also_notify);
	
	if (mzone->ixfr_base != NULL) {
		isc_mem_free(mem, mzone->ixfr_base);
	}
		
	if (mzone->ixfr_tmp != NULL) {
		isc_mem_free(mem, mzone->ixfr_tmp);
	}
		
	dns_c_pubkey_delete(&mzone->pubkey);

	return (ISC_R_SUCCESS);
}


static isc_result_t
slave_zone_clear(isc_mem_t *mem, dns_c_slave_zone_t *szone)
{
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
		
	dns_c_iplist_delete(&szone->master_ips);
	dns_c_ipmatch_list_delete(&szone->allow_update);
	dns_c_ipmatch_list_delete(&szone->allow_query);
	dns_c_ipmatch_list_delete(&szone->allow_transfer);
	dns_c_iplist_delete(&szone->also_notify);
	
	return (ISC_R_SUCCESS);
}



static isc_result_t
stub_zone_clear(isc_mem_t *mem, dns_c_stub_zone_t *szone)
{
	if (szone == NULL) {
		return (ISC_R_SUCCESS);
	}

	if (szone->file != NULL) {
		isc_mem_free(mem, szone->file);
	}

	dns_c_iplist_delete(&szone->master_ips);
	dns_c_ipmatch_list_delete(&szone->allow_update);
	dns_c_ipmatch_list_delete(&szone->allow_query);
	dns_c_ipmatch_list_delete(&szone->allow_transfer);
	
	return (ISC_R_SUCCESS);
}


static isc_result_t
forward_zone_clear(isc_mem_t *mem, dns_c_forward_zone_t *fzone)
{
	if (fzone == NULL) {
		return (ISC_R_SUCCESS);
	}

	(void) mem;			/* lint happiness */
	
	dns_c_iplist_delete(&fzone->forwarders);
	
	return (ISC_R_SUCCESS);
}


static isc_result_t
hint_zone_clear(isc_mem_t *mem, dns_c_hint_zone_t *hzone)
{
	if (hzone == NULL) {
		return (ISC_R_SUCCESS);
	}

	if (hzone->file != NULL) {
		isc_mem_free(mem, hzone->file);
	}
	
	return (ISC_R_SUCCESS);
}


/**************************************************/

static isc_result_t
set_ipmatch_list_field(isc_mem_t *mem,
		  dns_c_ipmatch_list_t **dest, dns_c_ipmatch_list_t *src,
		  isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	if (*dest != NULL) {
		res = dns_c_ipmatch_list_delete(dest);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}
	
	if (deepcopy) {
		res = dns_c_ipmatch_list_copy(mem, dest, src);
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
		res = dns_c_iplist_delete(dest);
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

