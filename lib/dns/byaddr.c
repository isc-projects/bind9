/*
 * Copyright (C) 2000  Internet Software Consortium.
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

#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/task.h>
#include <isc/util.h>

#include <dns/byaddr.h>
#include <dns/db.h>
#include <dns/events.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/resolver.h>
#include <dns/result.h>
#include <dns/view.h>

/*
 * XXXRTH  We could use a static event...
 */

struct dns_byaddr {
	/* Unlocked. */
	unsigned int		magic;
	isc_mem_t *		mctx;
	isc_mutex_t		lock;
	dns_fixedname_t		name;
	/* Locked by lock. */
	unsigned int		options;
	isc_task_t *		task;
	dns_view_t *		view;
	dns_byaddrevent_t *	event;
	dns_fetch_t *		fetch;
	unsigned int		restarts;
	isc_boolean_t		canceled;
	dns_rdataset_t		rdataset;
};

#define BYADDR_MAGIC			0x42794164U	/* ByAd. */
#define VALID_BYADDR(b)			((b) != NULL && \
					 (b)->magic == BYADDR_MAGIC)

#define MAX_RESTARTS 16

static void byaddr_find(dns_byaddr_t *byaddr, dns_fetchevent_t *event);

static char hex_digits[] = {
	'0', '1', '2', '3', '4', '5', '6', '7', 
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

static inline isc_result_t
address_to_ptr_name(dns_byaddr_t *byaddr, isc_netaddr_t *address) {
	char textname[128];
	unsigned char *bytes;
	int i;
	char *cp;
	isc_buffer_t buffer;
	unsigned int len;

	/*
	 * The caller must be holding the byaddr's lock.
	 */

	/*
	 * We create the text representation and then convert to a
	 * dns_name_t.  This is not maximally efficient, but it keeps all
	 * of the knowledge of wire format in the dns_name_ routines.
	 */

	dns_fixedname_init(&byaddr->name);
	bytes = (unsigned char *)(&address->type);
	if (address->family == AF_INET) {
		(void)sprintf(textname, "%u.%u.%u.%u.in-addr.arpa.",
			      (bytes[3] & 0xff),
			      (bytes[2] & 0xff),
			      (bytes[1] & 0xff),
			      (bytes[0] & 0xff));
	} else if (address->family == AF_INET6) {
		if ((byaddr->options & DNS_BYADDROPT_IPV6NIBBLE) != 0) {
			cp = textname;
			for (i = 15; i >= 0; i--) {
				*cp++ = hex_digits[bytes[i] & 0x0f];
				*cp++ = '.';
				*cp++ = hex_digits[(bytes[i] >> 4) & 0x0f];
				*cp++ = '.';
			}
			strcpy(cp, "ip6.int.");
		} else {
			cp = textname;
			*cp++ = '\\';
			*cp++ = '[';
			*cp++ = 'x';
			for (i = 0; i < 16; i += 2) {
				*cp++ = hex_digits[(bytes[i] >> 4) & 0x0f];
				*cp++ = hex_digits[bytes[i] & 0x0f];
				*cp++ = hex_digits[(bytes[i+1] >> 4) & 0x0f];
				*cp++ = hex_digits[bytes[i+1] & 0x0f];
			}
			strcpy(cp, "].ip6.arpa.");
		}
	} else
		return (ISC_R_NOTIMPLEMENTED);

	len = (unsigned int)strlen(textname);
	isc_buffer_init(&buffer, textname, len);
	isc_buffer_add(&buffer, len);
	return (dns_name_fromtext(dns_fixedname_name(&byaddr->name),
				  &buffer, dns_rootname, ISC_FALSE, NULL));
}

static inline isc_result_t
copy_ptr_targets(dns_byaddr_t *byaddr) {
	isc_result_t result;
	dns_name_t *name;
	dns_name_t target;
	dns_rdata_t rdata;
	isc_region_t r;

	/*
	 * The caller must be holding the byaddr's lock.
	 */
	
	result = dns_rdataset_first(&byaddr->rdataset);
	while (result == ISC_R_SUCCESS) {
		dns_rdataset_current(&byaddr->rdataset, &rdata);
		r.base = rdata.data;
		r.length = rdata.length;
		dns_name_init(&target, NULL);
		dns_name_fromregion(&target, &r);
		name = isc_mem_get(byaddr->mctx, sizeof *name);
		if (name == NULL)
			return (ISC_R_NOMEMORY);
		dns_name_init(name, NULL);
		result = dns_name_dup(&target, byaddr->mctx, name);
		if (result != ISC_R_SUCCESS) {
			isc_mem_put(byaddr->mctx, name, sizeof *name);
			return (ISC_R_NOMEMORY);
		}
		ISC_LIST_APPEND(byaddr->event->names, name, link);
		result = dns_rdataset_next(&byaddr->rdataset);
	}
	if (result == ISC_R_NOMORE)
		result = ISC_R_SUCCESS;
	
	return (result);
}

static void
fetch_done(isc_task_t *task, isc_event_t *event) {
	dns_byaddr_t *byaddr = event->ev_arg;
	dns_fetchevent_t *fevent;

	UNUSED(task);
	REQUIRE(event->ev_type == DNS_EVENT_FETCHDONE);
	REQUIRE(VALID_BYADDR(byaddr));
	REQUIRE(byaddr->task == task);
	fevent = (dns_fetchevent_t *)event;
	REQUIRE(fevent->fetch == byaddr->fetch);

	byaddr_find(byaddr, fevent);
}

static inline isc_result_t
start_fetch(dns_byaddr_t *byaddr) {
	isc_result_t result;

	/*
	 * The caller must be holding the byaddr's lock.
	 */

	REQUIRE(byaddr->fetch == NULL);

	result = dns_resolver_createfetch(byaddr->view->resolver,
					  dns_fixedname_name(&byaddr->name),
					  dns_rdatatype_ptr,
					  NULL, NULL, NULL, 0,
					  byaddr->task, fetch_done, byaddr,
					  &byaddr->rdataset, NULL,
					  &byaddr->fetch);

	return (result);
}

static void
byaddr_find(dns_byaddr_t *byaddr, dns_fetchevent_t *event) {
	isc_result_t result;
	isc_boolean_t want_restart;
	isc_boolean_t send_event = ISC_FALSE;
	isc_event_t *ievent;
	dns_name_t *name, *fname, *prefix;
	dns_name_t tname;
	dns_fixedname_t foundname, fixed;
	dns_rdata_t rdata;
	isc_region_t r;
	unsigned int nlabels, nbits;
	int order;
	dns_namereln_t namereln;

	REQUIRE(VALID_BYADDR(byaddr));

	LOCK(&byaddr->lock);

	result = ISC_R_SUCCESS;
	name = dns_fixedname_name(&byaddr->name);

	do {
		byaddr->restarts++;
		want_restart = ISC_FALSE;

		if (event == NULL && !byaddr->canceled) {
			dns_fixedname_init(&foundname);
			fname = dns_fixedname_name(&foundname);
			INSIST(!dns_rdataset_isassociated(&byaddr->rdataset));
			result = dns_view_find(byaddr->view, name,
					       dns_rdatatype_ptr, 0, 0,
					       ISC_FALSE, fname,
					       &byaddr->rdataset, NULL);
			if (result == ISC_R_NOTFOUND) {
				/*
				 * We don't know anything about the name.
				 * Launch a fetch.
				 */
				result = start_fetch(byaddr);
				if (result != ISC_R_SUCCESS)
					send_event = ISC_TRUE;
				goto done;
			}
		} else {
			result = event->result;
			fname = dns_fixedname_name(&event->foundname);
			dns_resolver_destroyfetch(&byaddr->fetch);
			INSIST(event->rdataset == &byaddr->rdataset);
			INSIST(event->sigrdataset == NULL);
			/*
			 * Detach (if necessary) from things we know we
			 * don't care about.
			 */
			if (event->node != NULL)
				dns_db_detachnode(event->db, &event->node);
			if (event->db != NULL)
				dns_db_detach(&event->db);
		}

		/*
		 * If we've been canceled, forget about the result.
		 */
		if (byaddr->canceled)
			result = ISC_R_CANCELED;

		switch (result) {
		case ISC_R_SUCCESS:
			result = copy_ptr_targets(byaddr);
			send_event = ISC_TRUE;
			break;
		case DNS_R_CNAME:
			/*
			 * Copy the CNAME's target into the byaddr's
			 * query name and start over.
			 */
			result = dns_rdataset_first(&byaddr->rdataset);
			if (result != ISC_R_SUCCESS)
				break;
			dns_rdataset_current(&byaddr->rdataset, &rdata);
			r.base = rdata.data;
			r.length = rdata.length;
			dns_name_init(&tname, NULL);
			dns_name_fromregion(&tname, &r);
			result = dns_name_concatenate(&tname, NULL, name,
						      NULL);
			if (result == ISC_R_SUCCESS)
				want_restart = ISC_TRUE;
			break;
		case DNS_R_DNAME:
			namereln = dns_name_fullcompare(name, fname, &order,
							&nlabels, &nbits);
			INSIST(namereln == dns_namereln_subdomain);
			/*
			 * Get the target name of the DNAME.
			 */
			result = dns_rdataset_first(&byaddr->rdataset);
			if (result != ISC_R_SUCCESS)
				break;
			dns_rdataset_current(&byaddr->rdataset, &rdata);
			r.base = rdata.data;
			r.length = rdata.length;
			dns_name_init(&tname, NULL);
			dns_name_fromregion(&tname, &r);
			/*
			 * Construct the new query name and start over.
			 */
			dns_fixedname_init(&fixed);
			prefix = dns_fixedname_name(&fixed);
			result = dns_name_split(name, nlabels, nbits, prefix,
						NULL);
			if (result != ISC_R_SUCCESS)
				break;
			result = dns_name_concatenate(prefix, &tname, name,
						      NULL);
			if (result == ISC_R_SUCCESS)
				want_restart = ISC_TRUE;
			break;
		default:
			send_event = ISC_TRUE;
		}

	done:
		if (dns_rdataset_isassociated(&byaddr->rdataset))
			dns_rdataset_disassociate(&byaddr->rdataset);

		if (event != NULL) {
			ievent = (isc_event_t *)event;
			isc_event_free(&ievent);
			event = NULL;
		}

		/*
		 * Limit the number of restarts.
		 */
		if (want_restart && byaddr->restarts == MAX_RESTARTS) {
			want_restart = ISC_FALSE;
			result = ISC_R_QUOTA;
			send_event = ISC_TRUE;
		}

	} while (want_restart);

	if (send_event) {
		byaddr->event->result = result;
		byaddr->event->ev_sender = byaddr;
		ievent = (isc_event_t *)byaddr->event;
		byaddr->event = NULL;
		isc_task_sendanddetach(&byaddr->task, &ievent);
		dns_view_detach(&byaddr->view);
	}

	UNLOCK(&byaddr->lock);
}

static void
bevent_destroy(isc_event_t *event) {
	dns_byaddrevent_t *bevent;
	dns_name_t *name, *next_name;
	isc_mem_t *mctx;

	REQUIRE(event->ev_type == DNS_EVENT_BYADDRDONE);
	mctx = event->ev_destroy_arg;
	bevent = (dns_byaddrevent_t *)event;

	for (name = ISC_LIST_HEAD(bevent->names);
	     name != NULL;
	     name = next_name) {
		next_name = ISC_LIST_NEXT(name, link);
		dns_name_free(name, mctx);
		isc_mem_put(mctx, name, sizeof *name);
	}
	isc_mem_put(mctx, event, event->ev_size);
}

isc_result_t
dns_byaddr_create(isc_mem_t *mctx, isc_netaddr_t *address, dns_view_t *view,
		  unsigned int options, isc_task_t *task,
		  isc_taskaction_t action, void *arg, dns_byaddr_t **byaddrp)
{
	isc_result_t result;
	dns_byaddr_t *byaddr;
	isc_event_t *ievent;

	byaddr = isc_mem_get(mctx, sizeof *byaddr);
	if (byaddr == NULL)
		return (ISC_R_NOMEMORY);
	byaddr->mctx = mctx;
	byaddr->options = options;

	byaddr->event = isc_mem_get(mctx, sizeof *byaddr->event);
	if (byaddr->event == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup_byaddr;
	}
	ISC_EVENT_INIT(byaddr->event, sizeof *byaddr->event, 0, NULL,
		       DNS_EVENT_BYADDRDONE, action, arg, byaddr,
		       bevent_destroy, mctx);
	byaddr->event->result = ISC_R_FAILURE;
	ISC_LIST_INIT(byaddr->event->names);

	byaddr->task = NULL;
	isc_task_attach(task, &byaddr->task);

	result = isc_mutex_init(&byaddr->lock);
	if (result != ISC_R_SUCCESS)
		goto cleanup_event;

	result = address_to_ptr_name(byaddr, address);
	if (result != ISC_R_SUCCESS)
		goto cleanup_lock;

	byaddr->view = NULL;
	dns_view_attach(view, &byaddr->view);
	byaddr->fetch = NULL;
	byaddr->restarts = 0;
	byaddr->canceled = ISC_FALSE;
	dns_rdataset_init(&byaddr->rdataset);
	byaddr->magic = BYADDR_MAGIC;
	
	*byaddrp = byaddr;

	byaddr_find(byaddr, NULL);

	return (ISC_R_SUCCESS);

 cleanup_lock:
	isc_mutex_destroy(&byaddr->lock);

 cleanup_event:
	ievent = (isc_event_t *)byaddr->event;
	isc_event_free(&ievent);
	byaddr->event = NULL;

	isc_task_detach(&byaddr->task);

 cleanup_byaddr:
	isc_mem_put(mctx, byaddr, sizeof *byaddr);

	return (result);
}

void
dns_byaddr_cancel(dns_byaddr_t *byaddr) {
	REQUIRE(VALID_BYADDR(byaddr));

	LOCK(&byaddr->lock);

	if (!byaddr->canceled) {
		byaddr->canceled = ISC_TRUE;
		if (byaddr->fetch != NULL) {
			INSIST(byaddr->view != NULL);
			dns_resolver_cancelfetch(byaddr->fetch);
		}
	}

	UNLOCK(&byaddr->lock);
}

void
dns_byaddr_destroy(dns_byaddr_t **byaddrp) {
	dns_byaddr_t *byaddr;

	REQUIRE(byaddrp != NULL);
	byaddr = *byaddrp;
	REQUIRE(VALID_BYADDR(byaddr));
	REQUIRE(byaddr->event == NULL);
	REQUIRE(byaddr->task == NULL);
	REQUIRE(byaddr->view == NULL);

	isc_mutex_destroy(&byaddr->lock);
	byaddr->magic = 0;
	isc_mem_put(byaddr->mctx, byaddr, sizeof *byaddr);

	*byaddrp = NULL;
}
