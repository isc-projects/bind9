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

#include <dns/validator.h>

isc_result_t
dns_validator_create(dns_view_t *view, dns_name_t *name,
		     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset,
		     dns_message_t *message, unsigned int options,
		     isc_task_t *task, isc_taskaction_t action, void *arg,
		     dns_validator_t **validatorp)
{
	REQUIRE(validatorp != NULL && *validatorp == NULL);

	(void)view;
	(void)name;
	(void)rdataset;
	(void)sigrdataset;
	(void)message;
	(void)options;
	(void)task;
	(void)action;
	(void)arg;

	return (ISC_R_NOTIMPLEMENTED);
}

void
dns_validator_cancel(dns_validator_t *validator) {
	(void)validator;
}

void
dns_validator_destroy(dns_validator_t **validatorp) {
	(void)validatorp;
}
