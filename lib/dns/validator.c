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
#include <isc/magic.h>
#include <isc/result.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/validator.h>
#include <dns/events.h>
#include <dns/name.h>
#include <dns/view.h>

struct dns_validator {
	/* Unlocked. */
	unsigned int			magic;
	isc_mutex_t			lock;
	dns_view_t *			view;
	/* Locked by lock. */
	unsigned int			options;
	unsigned int			attributes;
	dns_validatorevent_t *		event;
};

#define VALIDATOR_MAGIC			0x56616c3fU	/* Val?. */
#define VALID_VALIDATOR(v)	 	ISC_MAGIC_VALID(v, VALIDATOR_MAGIC)

isc_result_t
dns_validator_create(dns_view_t *view, dns_name_t *name,
		     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset,
		     dns_message_t *message, unsigned int options,
		     isc_task_t *task, isc_taskaction_t action, void *arg,
		     dns_validator_t **validatorp)
{
	isc_result_t result;
	dns_validator_t *val;
	isc_task_t *tclone;
	dns_validatorevent_t *event;

	REQUIRE(validatorp != NULL && *validatorp == NULL);

	tclone = NULL;
	result = ISC_R_FAILURE;

	val = isc_mem_get(view->mctx, sizeof *val);
	if (val == NULL)
		return (ISC_R_NOMEMORY);
	val->view = view;
	dns_view_attach(view, &val->view);
	event = (dns_validatorevent_t *)
		isc_event_allocate(view->mctx, task, DNS_EVENT_VALIDATORDONE,
				   action, arg, sizeof (dns_validatorevent_t));
	if (event == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup_val;
	}
	isc_task_attach(task, &tclone);
	event->validator = val;
	event->result = ISC_R_FAILURE;
	event->name = name;
	event->rdataset = rdataset;
	event->sigrdataset = sigrdataset;
	event->message = message;
	result = isc_mutex_init(&val->lock);
	if (result != ISC_R_SUCCESS)
		goto cleanup_event;
	val->event = event;
	val->options = options;
	val->attributes = 0;
	val->magic = VALIDATOR_MAGIC;

	return (ISC_R_SUCCESS);

 cleanup_event:
	isc_task_detach(&tclone);
	isc_event_free((isc_event_t **)&val->event);

 cleanup_val:
	dns_view_detach(&val->view);
	isc_mem_put(view->mctx, val, sizeof *val);
	
	return (result);
}

void
dns_validator_cancel(dns_validator_t *validator) {
	isc_task_t *task;

	REQUIRE(VALID_VALIDATOR(validator));

	LOCK(&validator->lock);
	if (validator->event != NULL) {
		validator->event->result = ISC_R_CANCELED;
		task = validator->event->sender;
		validator->event->sender = validator;
		isc_task_sendanddetach(&task,
				       (isc_event_t **)&validator->event);
		/*
		 * XXXRTH  Do other cancelation stuff here.
		 */
	}
	UNLOCK(&validator->lock);
}

static void
destroy(dns_validator_t *val) {
	dns_view_t *view;

	REQUIRE(VALID_VALIDATOR(val));
	REQUIRE(val->event == NULL);

	view = val->view;
	isc_mutex_destroy(&val->lock);
	val->magic = 0;
	isc_mem_put(view->mctx, val, sizeof *val);

	dns_view_detach(&val->view);
}

void
dns_validator_destroy(dns_validator_t **validatorp) {
	/*
	 * XXXRTH  This is incomplete; we may still be waiting for a fetch
	 *         to complete and need to see that it is done before calling
	 *	   destroy().
	 */
	destroy(*validatorp);
	*validatorp = NULL;
}
