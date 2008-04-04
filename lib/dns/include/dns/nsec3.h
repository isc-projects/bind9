/*
 * Copyright (C) 2008  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: nsec3.h,v 1.3 2008/04/04 23:47:01 tbox Exp $ */

#ifndef DNS_NSEC3_H
#define DNS_NSEC3_H 1

#include <isc/lang.h>
#include <isc/iterated_hash.h>

#include <dns/types.h>
#include <dns/name.h>

/*
 * hash = 1, iterations + optin = 3, salt length = 1, salt = 255 (max)
 * hash length = 1, hash = 255 (max), bitmap = 8192 + 512 (max)
 */
#define DNS_NSEC3_BUFFERSIZE (6 + 255 + 255 + 8192 + 512)

/*
 * Test "unknown" algorithm.  Is mapped to dns_hash_sha1.
 */
#define DNS_NSEC3_UNKNOWNALG 245U

ISC_LANG_BEGINDECLS

isc_result_t
dns_nsec3_buildrdata(dns_db_t *db, dns_dbversion_t *version,
		     dns_dbnode_t *node, unsigned int hashalg,
		     unsigned int optin, unsigned int iterations,
		     const unsigned char *salt, size_t salt_length,
		     const unsigned char *nexthash, size_t hash_length,
		     unsigned char *buffer, dns_rdata_t *rdata);
/*
 * Build the rdata of a NSEC3 record.
 *
 * Requires:
 *	buffer	Points to a temporary buffer of at least
 * 		DNS_NSEC_BUFFERSIZE bytes.
 *	rdata	Points to an initialized dns_rdata_t.
 *
 * Ensures:
 *      *rdata	Contains a valid NSEC rdata.  The 'data' member refers
 *		to 'buffer'.
 */

isc_result_t
dns_nsec3_build(dns_db_t *db, dns_dbversion_t *version, dns_dbnode_t *node,
		int auth_only, const char *salt, size_t salt_length,
		int iterations,	dns_ttl_t ttl);
/*
 * Build an NSEC3 record and add it to a database.
 */

isc_boolean_t
dns_nsec3_typepresent(dns_rdata_t *nsec, dns_rdatatype_t type);
/*
 * Determine if a type is marked as present in an NSEC3 record.
 *
 * Requires:
 *	'nsec' points to a valid rdataset of type NSEC3
 */

isc_result_t
dns_nsec3_hashname(dns_fixedname_t *result,
		   unsigned char rethash[NSEC3_MAX_HASH_LENGTH],
		   size_t *hash_length, dns_name_t *name, dns_name_t *origin,
		   dns_hash_t hashalg, unsigned int iterations,
		   const unsigned char *salt, size_t saltlength);
/*
 * Make a hashed domain name from an unhashed one. If rethash is not NULL
 * the raw hash is stored there.
 */

unsigned int
dns_nsec3_hashlength(dns_hash_t hash);
/*
 * Return the length of the hash produced by the specified algorithm
 * or zero when unknown.
 */

isc_boolean_t
dns_nsec3_supportedhash(dns_hash_t hash);
/*
 * Return whether we support this hash algorithm or not.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_NSEC2_H */
