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

#include <sys/types.h>	/* XXXRTH */

#include <string.h>

#include <isc/assertions.h>
#include <isc/magic.h>
#include <isc/net.h>

#include <dns/confserv.h>
#include <dns/confcommon.h>
#include "confpvt.h"


/*
 * Bit positions in the dns_c_srv_t structure flags field
 */
#define BOGUS_BIT			0
#define SERVER_TRANSFER_FORMAT_BIT	1
#define TRANSFERS_BIT			2
#define SUPPORT_IXFR_BIT		3

isc_result_t
dns_c_srvlist_new(isc_mem_t *mem, dns_c_srvlist_t **list)
{
	dns_c_srvlist_t *l;

	REQUIRE(list != NULL);

	l = isc_mem_get(mem, sizeof *l);
	if (l == NULL) {
		return (ISC_R_NOMEMORY);
	}
	
	ISC_LIST_INIT(l->elements);
	l->mem = mem;
	l->magic = DNS_C_SRVLIST_MAGIC;

	*list = l;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_srvlist_delete(dns_c_srvlist_t **list)
{
	dns_c_srvlist_t *l;
	dns_c_srv_t *server, *stmp;
	isc_result_t r;
	
	REQUIRE(list != NULL);
	REQUIRE(DNS_C_SRVLIST_VALID(*list));

	l = *list;

	server = ISC_LIST_HEAD(l->elements);
	while (server != NULL) {
		stmp = ISC_LIST_NEXT(server, next);
		ISC_LIST_UNLINK(l->elements, server, next);
		r = dns_c_srv_delete(&server);
		if (r != ISC_R_SUCCESS) {
			return (r);
		}
		
		server = stmp;
	}

	l->magic = 0;
	isc_mem_put(l->mem, l, sizeof *l);

	*list = NULL;

	return (ISC_R_SUCCESS);
}


void
dns_c_srvlist_print(FILE *fp, int indent,
		    dns_c_srvlist_t *servers)
{
	dns_c_srv_t *server;
	
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_SRVLIST_VALID(servers));

	server = ISC_LIST_HEAD(servers->elements);
	while (server != NULL) {
		dns_c_srv_print(fp, indent, server);
		server = ISC_LIST_NEXT(server, next);
		if (server != NULL) {
			fprintf(fp, "\n");
		}
	}

	return;
}


isc_result_t
dns_c_srvlist_servbyaddr(dns_c_srvlist_t *servers,
			 isc_sockaddr_t addr, dns_c_srv_t **retval)
{
	dns_c_srv_t *server;
	isc_result_t res;

	REQUIRE(retval != NULL);
	REQUIRE(DNS_C_SRVLIST_VALID(servers));

	server = ISC_LIST_HEAD(servers->elements);
	while (server != NULL) {
		if (isc_sockaddr_eqaddr(&addr, &server->address)) {
			break;
		}
		
		server = ISC_LIST_NEXT(server, next);
	}

	if (server != NULL) {
		*retval = server;
		res = ISC_R_SUCCESS;
	} else {
		res = ISC_R_NOTFOUND;
	}

	return (res);
}




isc_result_t
dns_c_srv_new(isc_mem_t *mem, isc_sockaddr_t addr,
	      dns_c_srv_t **server)
{
	dns_c_srv_t *serv;

	REQUIRE(server != NULL);

	serv = isc_mem_get(mem, sizeof *serv);
	if (serv == NULL) {
		return (ISC_R_NOMEMORY);
	}

	serv->magic = DNS_C_SRV_MAGIC;
	serv->address = addr;
	serv->mem = mem;
	serv->bogus = ISC_FALSE;
	serv->transfer_format = dns_one_answer;
	serv->transfers = 0;
	serv->support_ixfr = ISC_FALSE;
	serv->keys = NULL;

	memset(&serv->bitflags, 0x0, sizeof serv->bitflags);
	
	ISC_LINK_INIT(serv, next);

	*server = serv;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_srv_delete(dns_c_srv_t **server)
{
	dns_c_srv_t *serv;
	isc_mem_t *mem;
	
	REQUIRE(server != NULL);
	REQUIRE(DNS_C_SRV_VALID(*server));

	serv = *server;

	mem = serv->mem;
	serv->mem = NULL;
	serv->magic = 0;

	if (serv->keys != NULL)
		dns_c_kidlist_delete(&serv->keys);

	isc_mem_put(mem, serv, sizeof *serv);

	*server = NULL;

	return (ISC_R_SUCCESS);
}


void
dns_c_srv_print(FILE *fp, int indent, dns_c_srv_t *server)
{
	REQUIRE(DNS_C_SRV_VALID(server));
	REQUIRE(fp != NULL);

	dns_c_printtabs(fp, indent);
	fprintf(fp, "server ");
	dns_c_print_ipaddr(fp, &server->address);
	fprintf(fp, " {\n");

	if (DNS_C_CHECKBIT(BOGUS_BIT, &server->bitflags)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "bogus %s;\n",
			(server->bogus ? "true" : "false"));
	}

	if (DNS_C_CHECKBIT(SERVER_TRANSFER_FORMAT_BIT, &server->bitflags)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "transfer-format %s;\n",
			dns_c_transformat2string(server->transfer_format,
						 ISC_TRUE));
	}

	if (DNS_C_CHECKBIT(TRANSFERS_BIT, &server->bitflags)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "transfers %d;\n", server->transfers);
	}

	if (DNS_C_CHECKBIT(SUPPORT_IXFR_BIT,&server->bitflags)) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "support-ixfr %s;\n",
			(server->support_ixfr ? "true" : "false"));
	}

	if (server->keys != NULL) {
		dns_c_kidlist_print(fp, indent + 1, server->keys);
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");
}


isc_result_t
dns_c_srv_setbogus(dns_c_srv_t *server, isc_boolean_t newval)
{
	isc_boolean_t existed;
		
	REQUIRE(DNS_C_SRV_VALID(server));

	existed = DNS_C_CHECKBIT(BOGUS_BIT, &server->bitflags);
	
	server->bogus = newval;
	DNS_C_SETBIT(BOGUS_BIT, &server->bitflags);

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_srv_getbogus(dns_c_srv_t *server,
		   isc_boolean_t *retval)
{
	REQUIRE(DNS_C_SRV_VALID(server));
	REQUIRE(retval != NULL);

	if (DNS_C_CHECKBIT(BOGUS_BIT, &server->bitflags)) {
		*retval = server->bogus;
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_NOTFOUND);
	}
}


isc_result_t
dns_c_srv_setsupportixfr(dns_c_srv_t *server,
			 isc_boolean_t newval)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_SRV_VALID(server));

	existed = DNS_C_CHECKBIT(SUPPORT_IXFR_BIT, &server->bitflags);
	
	server->support_ixfr = newval;
	DNS_C_SETBIT(SUPPORT_IXFR_BIT, &server->bitflags);

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_srv_getsupportixfr(dns_c_srv_t *server,
			 isc_boolean_t *retval)
{
	REQUIRE(DNS_C_SRV_VALID(server));
	REQUIRE(retval != NULL);

	if (DNS_C_CHECKBIT(SUPPORT_IXFR_BIT, &server->bitflags)) {
		*retval = server->support_ixfr;
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_NOTFOUND);
	}
}


isc_result_t
dns_c_srv_settransfers(dns_c_srv_t *server,
		       isc_int32_t newval)
{
	isc_boolean_t existed;
	
	REQUIRE(DNS_C_SRV_VALID(server));

	existed = DNS_C_CHECKBIT(TRANSFERS_BIT, &server->bitflags);

	server->transfers = newval;
	DNS_C_SETBIT(TRANSFERS_BIT, &server->bitflags);

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_srv_gettransfers(dns_c_srv_t *server,
		       isc_int32_t *retval)
{
	REQUIRE(DNS_C_SRV_VALID(server));
	REQUIRE(retval != NULL);

	if (DNS_C_CHECKBIT(TRANSFERS_BIT, &server->bitflags)) {
		*retval = server->transfers;
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_NOTFOUND);
	}
}


isc_result_t
dns_c_srv_settransferformat(dns_c_srv_t *server,
			    dns_transfer_format_t newval)
{
	isc_boolean_t existed;

	REQUIRE(DNS_C_SRV_VALID(server));

	existed = DNS_C_CHECKBIT(SERVER_TRANSFER_FORMAT_BIT,
				 &server->bitflags);

	server->transfer_format = newval;
	DNS_C_SETBIT(SERVER_TRANSFER_FORMAT_BIT, &server->bitflags);

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


isc_result_t
dns_c_srv_gettransferformat(dns_c_srv_t *server,
			    dns_transfer_format_t *retval)
{
	REQUIRE(DNS_C_SRV_VALID(server));
	REQUIRE(retval != NULL);
	
	if (DNS_C_CHECKBIT(SERVER_TRANSFER_FORMAT_BIT, &server->bitflags)) {
		*retval = server->transfer_format;
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_NOTFOUND);
	}
}


isc_result_t
dns_c_srv_getkeys(dns_c_srv_t *server, dns_c_kidlist_t **retval)
{
	REQUIRE(DNS_C_SRV_VALID(server));
	REQUIRE(retval != NULL);
	
	*retval = server->keys;

	return (server->keys == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_srv_setkeys(dns_c_srv_t *server, dns_c_kidlist_t *newval)
{
	isc_boolean_t existed = ISC_FALSE;
	
	REQUIRE(DNS_C_SRV_VALID(server));
	REQUIRE(DNS_C_KEYIDLIST_VALID(newval));
	
	if (server->keys != NULL) {
		dns_c_kidlist_delete(&server->keys);
		existed = ISC_TRUE;
	}
	
	server->keys = newval;

	return (existed ? ISC_R_EXISTS : ISC_R_SUCCESS);
}


