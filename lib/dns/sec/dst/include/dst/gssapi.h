#ifndef DST_GSSAPI_H
#define DST_GSSAPI_H 1

#include <isc/lang.h>

#include <isc/types.h>

ISC_LANG_BEGINDECLS

/***
 *** Types
 ***/

/***
 *** Functions
 ***/

isc_result_t
dst_gssapi_acquirecred(dns_name_t *name, isc_boolean_t initiate, void **cred);

isc_result_t
dst_gssapi_initctx(dns_name_t *name, void *cred,
		   isc_region_t *intoken, isc_buffer_t *outtoken,
		   void **context);

isc_result_t
dst_gssapi_acceptctx(dns_name_t *name, void *cred,
		     isc_region_t *intoken, isc_buffer_t *outtoken,
		     void **context);

/*
 * XXX
 */

ISC_LANG_ENDDECLS

#endif /* DST_GSSAPI_H */
