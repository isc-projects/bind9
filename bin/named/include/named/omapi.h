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

/* $Id: omapi.h,v 1.7.2.1 2000/07/11 17:23:07 gson Exp $ */

#ifndef NAMED_OMAPI_H
#define NAMED_OMAPI_H 1

#include <dns/aclconf.h>
#include <dns/confctx.h>

#include <omapi/omapi.h>

#define NS_OMAPI_PORT			953

/*
 * This string is the registration name of objects of type control_object_t.
 */
#define NS_OMAPI_CONTROL		"control"

#define NS_OMAPI_COMMAND_RELOAD		"reload"
#define NS_OMAPI_COMMAND_RELOADCONFIG	"reload-config"
#define NS_OMAPI_COMMAND_RELOADZONES	"reload-zones"

isc_result_t
ns_omapi_init(void);

isc_result_t
ns_omapi_configure(isc_mem_t *mctx, dns_c_ctx_t *cctx,
		   dns_aclconfctx_t *aclconfctx);

void
ns_omapi_shutdown(isc_boolean_t exiting);

#endif /* NAMED_OMAPI_H */
