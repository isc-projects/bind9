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

#ifndef DNS_CONFIG_CONFSERV_H
#define DNS_CONFIG_CONFSERV_H 1

/*****
 ***** Module Info
 *****/

/*
 * 
 *
 * 
 *
 * 
 *
 * MP:
 *	
 *
 * Reliability:
 *	
 *
 * Resources:
 *	
 *
 * Security:
 *	
 *
 * Standards:
 *	
 */

/***
 *** Imports
 ***/

#include <config.h>

#include <sys/types.h>

#include <isc/mem.h>
#include <isc/net.h>

#include <dns/types.h>
#include <dns/confcommon.h>
#include <dns/confkeys.h>


#define DNS_C_SRVLIST_MAGIC	0x7365524c /* seRL */
#define DNS_C_SRV_MAGIC		0x53457276 /* SErv */

#define DNS_C_SRVLIST_VALID(ptr) ISC_MAGIC_VALID(ptr, DNS_C_SRVLIST_MAGIC)
#define DNS_C_SRV_VALID(ptr)	 ISC_MAGIC_VALID(ptr, DNS_C_SRV_MAGIC)


/***
 *** Types
 ***/

typedef struct dns_c_srv		dns_c_srv_t;
typedef struct dns_c_srv_list		dns_c_srvlist_t;

struct dns_c_srv_list
{
	isc_uint32_t		magic;
	
	isc_mem_t	       *mem;

	ISC_LIST(dns_c_srv_t) elements;
};


struct dns_c_srv 
{
	isc_uint32_t		magic;
	
	isc_mem_t	       *mem;

	isc_sockaddr_t		address;
	isc_boolean_t		bogus;
	dns_transfer_format_t	transfer_format;
	int			transfers;
	isc_boolean_t		support_ixfr;
	dns_c_kidlist_t	       *keys;

	dns_c_setbits_t		bitflags;
	
	ISC_LINK(dns_c_srv_t)	next;
};


/***
 *** Functions
 ***/

isc_result_t	dns_c_srvlist_new(isc_mem_t *mem,
				  dns_c_srvlist_t **list);
isc_result_t	dns_c_srvlist_delete(dns_c_srvlist_t **list);
void		dns_c_srvlist_print(FILE *fp, int indent,
				    dns_c_srvlist_t *servers);
isc_result_t	dns_c_srvlist_servbyaddr(dns_c_srvlist_t *servers,
					 isc_sockaddr_t addr,
					 dns_c_srv_t **retval);


isc_result_t	dns_c_srv_new(isc_mem_t *mem,
			      isc_sockaddr_t ipaddr,
			      dns_c_srv_t **server);
isc_result_t	dns_c_srv_delete(dns_c_srv_t **server);
void		dns_c_srv_print(FILE *fp, int indent,
				dns_c_srv_t *server);

isc_result_t	dns_c_srv_setbogus(dns_c_srv_t *server,
				   isc_boolean_t newval);
isc_result_t	dns_c_srv_getbogus(dns_c_srv_t *server,
				   isc_boolean_t *retval);
isc_result_t	dns_c_srv_setsupportixfr(dns_c_srv_t *server,
					 isc_boolean_t newval);
isc_result_t	dns_c_srv_getsupportixfr(dns_c_srv_t *server,
					 isc_boolean_t *retval);
isc_result_t	dns_c_srv_settransfers(dns_c_srv_t *server,
				       isc_int32_t newval);
isc_result_t	dns_c_srv_gettransfers(dns_c_srv_t *server,
				       isc_int32_t *retval);
isc_result_t	dns_c_srv_settransferformat(dns_c_srv_t *server,
					    dns_transfer_format_t newval);
isc_result_t	dns_c_srv_gettransferformat(dns_c_srv_t *server,
					    dns_transfer_format_t *retval);
isc_result_t	dns_c_srv_get_keylist(dns_c_srv_t *server,
				      dns_c_kidlist_t **keylist);

isc_result_t	dns_c_srv_settkeydomain(dns_c_srv_t *server,
					char *newval);
isc_result_t	dns_c_srv_gettkeydomain(dns_c_srv_t *server,
					char **retval);
isc_result_t	dns_c_srv_getkeys(dns_c_srv_t *server,
				  dns_c_kidlist_t **retval);
isc_result_t	dns_c_srv_setkeys(dns_c_srv_t *server,
				  dns_c_kidlist_t *newval);


#endif /* DNS_CONFIG_CONFSERV_H */
