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
#include <dns/resolver.h>
#include <dns/view.h>

/*
 * XXXRTH  We could use a static event...
 */

struct dns_byaddr {
	/* Unlocked. */
	unsigned int		magic;
	isc_mutex_t		lock;
	dns_view_t *		view;
	/* Locked by lock. */
	dns_byaddrevent_t *	event;
};

#define BYADDR_MAGIC			0x42794164U	/* ByAd. */
#define VALID_BYADDR(b)			((b) != NULL && \
					 (b)->magic == BYADDR_MAGIC)

#ifdef notyet

isc_result_t
dns_byaddr_create(isc_netaddr_t *address, dns_view_t *view,
		  unsigned int options, isc_task_t *task,
		  isc_taskaction_t action, void *arg, dns_byaddr_t **byaddrp)
{
	isc_result_t result;
	dns_byaddr_t *byaddr;
	
	byaddr = isc_mem_get(view->mctx, sizeof *byaddr);
	if (byaddr == NULL)
		return (ISC_R_NOMEMORY);

	result = isc_mutex_init(&byaddr->lock);
	if (result != ISC_R_SUCCESS)
		goto cleanup_byaddr;
	byaddr->view = NULL;
	dns_view_attach(view, &byaddr->view);
	
	return (ISC_R_SUCCESS);

 cleanup_lock:
	isc_mutex_destroy(&byaddr->lock);

 cleanup_byaddr:
	isc_mem_put(view->mctx, byaddr, sizeof *byaddr);

	return (result);
}

void
dns_byaddr_cancel(dns_byaddr_t *byaddr) {
}

void
dns_byaddr_destroy(dns_byaddr_t **byaddrp) {
}

#endif
