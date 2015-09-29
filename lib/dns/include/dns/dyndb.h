/*
 * Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 2008-2011  Red Hat, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND AUTHORS DISCLAIM ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL AUTHORS BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef DNS_DYNDB_H
#define DNS_DYNDB_H

#include <isc/types.h>

#include <dns/types.h>

ISC_LANG_BEGINDECLS

/*!
 * \brief
 * Context for intializing a dyndb module.
 *
 * This structure passes pointers to globals to which a dyndb
 * module will need access -- the server memory context, hash
 * context, log context, etc.  The structure doesn't persist
 * beyond configuring the dyndb module. The module's register function
 * should attach to all reference-counted variables and its destroy
 * function should detach from them.
 */
struct dns_dyndbctx {
	unsigned int	magic;
	isc_mem_t	*mctx;
	isc_hash_t	*hctx;
	isc_log_t	*lctx;
	dns_view_t	*view;
	dns_zonemgr_t	*zmgr;
	isc_task_t	*task;
	isc_timermgr_t	*timermgr;
	isc_boolean_t	*refvar;
};

#define DNS_DYNDBCTX_MAGIC	ISC_MAGIC('D', 'd', 'b', 'c')
#define DNS_DYNDBCTX_VALID(d)	ISC_MAGIC_VALID(d, DNS_DYNDBCTX_MAGIC)

/*
 * API version
 *
 * When the API changes, increment DNS_DYNDB_VERSION. If the
 * change is backward-compatible (e.g., adding a new function call
 * but not changing or removing an old one), increment DNS_DYNDB_AGE;
 * if not, set DNS_DYNDB_AGE to 0.
 */
#ifndef DNS_DYNDB_VERSION
#define DNS_DYNDB_VERSION 1
#define DNS_DYNDB_AGE 0
#endif

typedef isc_result_t dns_dyndb_register_t(isc_mem_t *mctx,
					  const char *name,
					  const char *parameters,
					  const dns_dyndbctx_t *dctx,
					  void **instp);
/*%
 * Called when registering a new driver instance. 'name' must be unique.
 * 'parameters' contains the driver configuration text. 'dctx' is the
 * initialization context set up in dns_dyndb_createctx().
 *
 * '*instp' must be set to the driver instance handle if the functino
 * is successful.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMEMORY
 *\li	Other errors are possible
 */

typedef void dns_dyndb_destroy_t(void **instp);
/*%
 * Destroy a driver instance. Dereference any reference-counted
 * variables passed in 'dctx' and 'inst' in the register function.
 *
 * \c *instp must be set to \c NULL by the function before it returns.
 */

typedef int dns_dyndb_version_t(unsigned int *flags);
/*%
 * Return the API version number a dyndb module was compiled with.
 *
 * If the returned version number is no greater than than
 * DNS_DYNDB_VERSION, and no less than DNS_DYNDB_VERSION - DNS_DYNDB_AGE,
 * then the module is API-compatible with named.
 *
 * 'flags' is currently unused and may be NULL, but could be used in
 * the future to pass back driver capabilities or other information.
 */

isc_result_t
dns_dyndb_load(const char *libname, const char *name, const char *parameters,
	       isc_mem_t *mctx, const dns_dyndbctx_t *dctx);
/*%
 * Load a dyndb module.
 *
 * This loads a dyndb module using dlopen(), calls its register
 * function (see dns_dyndb_register_t above), and if successful, adds
 * the instance handle to a list of dyndb instances so it can be cleaned
 * up later.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMEMORY
 *\li	Other errors are possible
 */

void
dns_dyndb_cleanup(isc_boolean_t exiting);
/*%
 * Shut down and destroy all running dyndb modules.
 *
 * 'exiting' indicates whether the server is shutting down,
 * as opposed to merely being reconfigured.
 */

isc_result_t
dns_dyndb_createctx(isc_mem_t *mctx, isc_hash_t *hctx, isc_log_t *lctx,
		    dns_view_t *view, dns_zonemgr_t *zmgr,
		    isc_task_t *task, isc_timermgr_t *tmgr,
		    dns_dyndbctx_t **dctxp);
/*%
 * Create a dyndb initialization context structure, with
 * pointers to structures in the server that the dyndb module will
 * need to access (view, zone manager, memory context, hash context,
 * etc). This structure is expected to last only until all dyndb
 * modules have been loaded and initialized; after that it will be
 * destroyed with dns_dyndb_destroyctx().
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMEMORY
 *\li	Other errors are possible
 */

void
dns_dyndb_destroyctx(dns_dyndbctx_t **dctxp);
/*%
 * Destroys a dyndb initialization context structure; all
 * reference-counted members are detached and the structure is freed.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_DYNDB_H */
