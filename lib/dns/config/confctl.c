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

#include <isc/assertions.h>
#include <isc/net.h>
#include <isc/magic.h>

#include <dns/confctl.h>
#include <dns/confcommon.h>

#define CONFCTL_MAGIC	0x4363746cU
#define CONFCTLLIST_MAGIC 0x4354424cU

#define DNS_CONFCTLLIST_VALID(ctllist) \
	ISC_MAGIC_VALID(ctllist, CONFCTLLIST_MAGIC)
#define DNS_CONFCTL_VALID(ctl) ISC_MAGIC_VALID(ctl, CONFCTL_MAGIC)


isc_result_t
dns_c_ctrllist_new(isc_log_t *lctx,
		   isc_mem_t *mem, dns_c_ctrllist_t **newlist)
{
	dns_c_ctrllist_t *newl;
	
	REQUIRE(mem != NULL);
	REQUIRE (newlist != NULL);

	(void) lctx;
	
	newl = isc_mem_get(mem, sizeof *newl);
	if (newl == NULL) {
		/* XXXJAB logwrite */
		return (ISC_R_NOMEMORY);
	}

	newl->mem = mem;
	newl->magic = CONFCTLLIST_MAGIC;
	
	ISC_LIST_INIT(newl->elements);

	*newlist = newl;

	return (ISC_R_SUCCESS);
}
	
		
	
void
dns_c_ctrllist_print(isc_log_t *lctx,
		     FILE *fp, int indent, dns_c_ctrllist_t *cl)
{
	dns_c_ctrl_t *ctl;

	if (cl == NULL) {
		return;
	}

	REQUIRE(DNS_CONFCTLLIST_VALID(cl));
	
	if (ISC_LIST_EMPTY(cl->elements)) {
		return;
	}
	
	fprintf(fp, "controls {\n");
	ctl = ISC_LIST_HEAD(cl->elements);
	while (ctl != NULL) {
		dns_c_printtabs(lctx, fp, indent + 1);
		dns_c_ctrl_print(lctx, fp, indent + 1, ctl);
		ctl = ISC_LIST_NEXT(ctl, next);
	}
	fprintf(fp, "};\n");
}



isc_result_t
dns_c_ctrllist_delete(isc_log_t *lctx,
		      dns_c_ctrllist_t **list)
{
	dns_c_ctrl_t	       *ctrl;
	dns_c_ctrl_t	       *tmpctrl;
	dns_c_ctrllist_t      *clist;

	REQUIRE(list != NULL);
	
	clist = *list;
	if (clist == NULL) {
		return (ISC_R_SUCCESS);
	}

	REQUIRE(DNS_CONFCTLLIST_VALID(clist));
	
	ctrl = ISC_LIST_HEAD(clist->elements);
	while (ctrl != NULL) {
		tmpctrl = ISC_LIST_NEXT(ctrl, next);
		dns_c_ctrl_delete(lctx, &ctrl);
		ctrl = tmpctrl;
	}

	isc_mem_put(clist->mem, clist, sizeof *clist);

	*list = NULL;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctrlinet_new(isc_log_t *lctx, isc_mem_t *mem, dns_c_ctrl_t **control,
		   isc_sockaddr_t addr, short port,
		   dns_c_ipmatchlist_t *iml, isc_boolean_t copy)
{
	dns_c_ctrl_t  *ctrl;
	isc_result_t	res;
	
	REQUIRE(mem != NULL);
	REQUIRE(control != NULL);

	ctrl = isc_mem_get(mem, sizeof *ctrl);
	if (ctrl == NULL) {
		return (ISC_R_NOMEMORY);
	}

	ctrl->magic = CONFCTL_MAGIC;
	ctrl->mem = mem;
	ctrl->control_type = dns_c_inet_control;
	ctrl->u.inet_v.addr = addr;
	ctrl->u.inet_v.port = port;

	if (copy) {
		res = dns_c_ipmatchlist_copy(lctx, mem,
					     &ctrl->u.inet_v.matchlist, iml);
		if (res != ISC_R_SUCCESS) {
			isc_mem_put(mem, ctrl, sizeof *ctrl);
			return (res);
		}
	} else {
		ctrl->u.inet_v.matchlist = iml;
	}

	*control = ctrl;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctrlunix_new(isc_log_t *lctx,
		   isc_mem_t *mem, dns_c_ctrl_t **control,
		   const char *path, int perm, uid_t uid, gid_t gid)
{
	dns_c_ctrl_t  *ctrl;
	
	REQUIRE(mem != NULL);
	REQUIRE(control != NULL);

	(void) lctx;

	ctrl = isc_mem_get(mem, sizeof *ctrl);
	if (ctrl == NULL) {
		return (ISC_R_NOMEMORY);
	}

	ctrl->magic = CONFCTL_MAGIC;
	ctrl->mem = mem;
	ctrl->control_type = dns_c_unix_control;
	ctrl->u.unix_v.pathname = isc_mem_strdup(mem, path);
	if (ctrl->u.unix_v.pathname == NULL) {
		isc_mem_put(mem, ctrl, sizeof *ctrl);
					/* XXXJAB logwrite */
		return (ISC_R_NOMEMORY);
	}
	
	ctrl->u.unix_v.perm = perm;
	ctrl->u.unix_v.owner = uid;
	ctrl->u.unix_v.group = gid;
	
	*control = ctrl;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ctrl_delete(isc_log_t *lctx,
		  dns_c_ctrl_t **control)
{
	isc_result_t res = ISC_R_SUCCESS;
	isc_result_t rval;
	isc_mem_t *mem;
	dns_c_ctrl_t *ctrl;
	
	REQUIRE(control != NULL);

	ctrl = *control;
	if (ctrl == NULL) {
		return (ISC_R_SUCCESS);
	}

	REQUIRE(DNS_CONFCTL_VALID(ctrl));

	mem = ctrl->mem;

	switch (ctrl->control_type) {
	case dns_c_inet_control:
		res = dns_c_ipmatchlist_delete(lctx,
					       &ctrl->u.inet_v.matchlist);
		break;

	case dns_c_unix_control:
		isc_mem_free(mem, ctrl->u.unix_v.pathname);
		res = ISC_R_SUCCESS;
		break;
	}

	rval = res;

	ctrl->magic = 0;
	
	isc_mem_put(mem, ctrl, sizeof *ctrl);

	*control = NULL;

	return (res);
}


void
dns_c_ctrl_print(isc_log_t *lctx,
		 FILE *fp, int indent, dns_c_ctrl_t *ctl)
{
	short port;
	dns_c_ipmatchlist_t *iml;

	REQUIRE(DNS_CONFCTL_VALID(ctl));
		
	(void) indent;
	
	if (ctl->control_type == dns_c_inet_control) {
		port = ctl->u.inet_v.port;
		iml = ctl->u.inet_v.matchlist;
		
		fprintf(fp, "inet ");
		dns_c_print_ipaddr(lctx, fp,  &ctl->u.inet_v.addr);
		
		if (port == 0) {
			fprintf(fp, " port *\n");
		} else {
			fprintf(fp, " port %d\n", port);
		}
		
		dns_c_printtabs(lctx, fp, indent + 1);
		fprintf(fp, "allow ");
		dns_c_ipmatchlist_print(lctx, fp, indent + 2, iml);
		fprintf(fp, ";\n");
	} else {
		/* The "#" means force a leading zero */
		fprintf(fp, "unix \"%s\" perm %#o owner %d group %d;\n",
			ctl->u.unix_v.pathname,
			ctl->u.unix_v.perm,
			ctl->u.unix_v.owner,
			ctl->u.unix_v.group);
	}
}


