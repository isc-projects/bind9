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

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/result.h>
#include <isc/task.h>
#include <isc/util.h>
#include <isc/mem.h>
#include <isc/mutex.h>

#include <dns/byaddr.h>
#include <dns/events.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/resolver.h>
#include <dns/view.h>

/*
 * XXXRTH  We could use a static event...
 */

struct dns_byaddr {
	/* Unlocked. */
	unsigned int		magic;
	isc_mem_t *		mctx;
	isc_mutex_t		lock;
	dns_view_t *		view;
	dns_fixedname_t		name;
	/* Locked by lock. */
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

static inline isc_result_t
address_to_ptr_name(dns_byaddr_t *byaddr, isc_netaddr_t *address) {
	dns_fixedname_init(&byaddr->name);
	return (DNS_R_NOTIMPLEMENTED);
}

static void
byaddr_find(dns_byaddr_t *byaddr, dns_fetchevent_t *event) {
	isc_result_t result;
	isc_boolean_t want_restart;
	isc_boolean_t send_event = ISC_FALSE;
	isc_task_t *task;
	isc_event_t *ievent;
	dns_name_t *name;
	dns_rdataset_t *rdataset;

	REQUIRE(VALID_BYADDR(byaddr));

	LOCK(&byaddr->lock);

	result = ISC_R_SUCCESS;

	do {
		byaddr->restarts++;
		want_restart = ISC_FALSE;

		if (event == NULL && !byaddr->canceled) {
			name = dns_fixedname_name(&byaddr->name);
			INSIST(!dns_rdataset_isassociated(&byaddr->rdataset));
			result = dns_view_simplefind(byaddr->view, name,
					       dns_rdatatype_ptr, 0, 0,
					       ISC_FALSE, &byaddr->rdataset,
					       NULL);
		} else {
			INSIST(event->rdataset == &byaddr->rdataset);
			dns_resolver_destroyfetch(byaddr->view->resolver,
						  &byaddr->fetch);
		}

		/*
		 * If we've been canceled, forget about the result.
		 */
		if (byaddr->canceled)
			result = ISC_R_CANCELED;

		switch (result) {
		case ISC_R_SUCCESS:
			send_event = ISC_TRUE;
			break;
		case DNS_R_CNAME:
			want_restart = ISC_TRUE;
			break;
		case DNS_R_DNAME:
			want_restart = ISC_TRUE;
			break;
		default:
			send_event = ISC_TRUE;
		}

		if (event != NULL) {
			ievent = (isc_event_t *)event;
			isc_event_free(&ievent);
		}

		if (dns_rdataset_isassociated(&byaddr->rdataset))
			dns_rdataset_disassociate(&byaddr->rdataset);

		/*
		 * Limit the number of restarts.
		 */
		if (want_restart && byaddr->restarts == MAX_RESTARTS) {
			want_restart = ISC_FALSE;
			result = ISC_R_QUOTA;
			send_event = ISC_TRUE;
		}

	} while (want_restart);

 done:
	if (send_event) {
		byaddr->event->result = result;
		task = byaddr->event->sender;
		byaddr->event->sender = byaddr;
		ievent = (isc_event_t *)byaddr->event;
		byaddr->event = NULL;
		isc_task_sendanddetach(&task, &ievent);
		dns_view_detach(&byaddr->view);
	}

	UNLOCK(&byaddr->lock);
}

isc_result_t
dns_byaddr_create(isc_mem_t *mctx, isc_netaddr_t *address, dns_view_t *view,
		  unsigned int options, isc_task_t *task,
		  isc_taskaction_t action, void *arg, dns_byaddr_t **byaddrp)
{
	isc_result_t result;
	dns_byaddr_t *byaddr;
	isc_task_t *cloned_task;
	isc_event_t *ievent;
	
	byaddr = isc_mem_get(mctx, sizeof *byaddr);
	if (byaddr == NULL)
		return (ISC_R_NOMEMORY);
	byaddr->mctx = mctx;
	byaddr->event = (dns_byaddrevent_t *)
		isc_event_allocate(mctx, NULL, DNS_EVENT_BYADDRDONE,
				   action, arg, sizeof *byaddr->event);
	if (byaddr->event == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup_byaddr;
	}
	cloned_task = NULL;
	isc_task_attach(task, &cloned_task);
	byaddr->event->sender = cloned_task;
	byaddr->event->result = ISC_R_FAILURE;
	ISC_LIST_INIT(byaddr->event->names);

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
	isc_task_detach(&cloned_task);
	ievent = (isc_event_t *)byaddr->event;
	isc_event_free(&ievent);
	byaddr->event = NULL;

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
			dns_resolver_cancelfetch(byaddr->view->resolver,
						 byaddr->fetch);
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
	REQUIRE(byaddr->view == NULL);

	isc_mutex_destroy(&byaddr->lock);
	byaddr->magic = 0;
	isc_mem_put(byaddr->mctx, byaddr, sizeof *byaddr);

	*byaddrp = NULL;
}
