/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*! \file dns/tsig.h */

#include <stdbool.h>

#include <isc/hashmap.h>
#include <isc/lang.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/stdio.h>
#include <isc/stdtime.h>

#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/types.h>

#include <dst/dst.h>

/* Add -DDNS_TSIG_TRACE=1 to CFLAGS for detailed reference tracing */

/*
 * Algorithms.
 */
extern const dns_name_t *dns_tsig_hmacmd5_name;
#define DNS_TSIG_HMACMD5_NAME dns_tsig_hmacmd5_name
extern const dns_name_t *dns_tsig_gssapi_name;
#define DNS_TSIG_GSSAPI_NAME dns_tsig_gssapi_name
extern const dns_name_t *dns_tsig_hmacsha1_name;
#define DNS_TSIG_HMACSHA1_NAME dns_tsig_hmacsha1_name
extern const dns_name_t *dns_tsig_hmacsha224_name;
#define DNS_TSIG_HMACSHA224_NAME dns_tsig_hmacsha224_name
extern const dns_name_t *dns_tsig_hmacsha256_name;
#define DNS_TSIG_HMACSHA256_NAME dns_tsig_hmacsha256_name
extern const dns_name_t *dns_tsig_hmacsha384_name;
#define DNS_TSIG_HMACSHA384_NAME dns_tsig_hmacsha384_name
extern const dns_name_t *dns_tsig_hmacsha512_name;
#define DNS_TSIG_HMACSHA512_NAME dns_tsig_hmacsha512_name

/*%
 * Default fudge value.
 */
#define DNS_TSIG_FUDGE 300

/*%
 * Default maximum quota for generated keys.
 */
#ifndef DNS_TSIG_MAXGENERATEDKEYS
#define DNS_TSIG_MAXGENERATEDKEYS 4096
#endif /* ifndef DNS_TSIG_MAXGENERATEDKEYS */

struct dns_tsigkeyring {
	unsigned int   magic; /*%< Magic number. */
	isc_hashmap_t *keys;
	unsigned int   writecount;
	isc_rwlock_t   lock;
	isc_mem_t     *mctx;
	/*
	 * LRU list of generated key along with a count of the keys on the
	 * list and a maximum size.
	 */
	unsigned int generated;
	ISC_LIST(dns_tsigkey_t) lru;
	isc_refcount_t references;
};

struct dns_tsigkey {
	/* Unlocked */
	unsigned int	magic; /*%< Magic number. */
	isc_mem_t      *mctx;
	dst_key_t      *key; /*%< Key */
	dns_fixedname_t fn;
	dns_name_t     *name;		  /*%< Key name */
	dst_algorithm_t alg;		  /*< Algorithm */
	dns_name_t	algname;	  /*< Algorithm name, only used if
					    algorithm is DST_ALG_UNKNOWN */
	dns_name_t	  *creator;	  /*%< name that created secret */
	bool		   generated : 1; /*%< key was auto-generated */
	bool		   restored  : 1; /*%< key was restored at startup */
	isc_stdtime_t	   inception;	  /*%< start of validity period */
	isc_stdtime_t	   expire;	  /*%< end of validity period */
	dns_tsigkeyring_t *ring;	  /*%< the enclosing keyring */
	isc_refcount_t	   references;	  /*%< reference counter */
	ISC_LINK(dns_tsigkey_t) link;
};

ISC_LANG_BEGINDECLS

const dns_name_t *
dns_tsigkey_identity(const dns_tsigkey_t *tsigkey);
/*%<
 *	Returns the identity of the provided TSIG key.
 *
 *	Requires:
 *\li		'tsigkey' is a valid TSIG key or NULL
 *
 *	Returns:
 *\li		NULL if 'tsigkey' was NULL
 *\li		identity of the provided TSIG key
 */

isc_result_t
dns_tsigkey_create(const dns_name_t *name, dst_algorithm_t algorithm,
		   unsigned char *secret, int length, isc_mem_t *mctx,
		   dns_tsigkey_t **key);

isc_result_t
dns_tsigkey_createfromkey(const dns_name_t *name, dst_algorithm_t algorithm,
			  dst_key_t *dstkey, bool generated, bool restored,
			  const dns_name_t *creator, isc_stdtime_t inception,
			  isc_stdtime_t expire, isc_mem_t *mctx,
			  dns_tsigkey_t **key);
/*%<
 *	Creates a tsig key structure and stores it in *keyp.
 *	The key's validity period is specified by (inception, expire),
 *	and will not expire if inception == expire.
 *
 *	If generated is true (meaning the key was generated
 *	via TKEY negotation), the creating identity (if any), should
 *	be specified in the creator parameter.
 *
 *	If restored is true, this indicates the key was restored from
 *	a dump file created by dns_tsigkeyring_dumpanddetach(). This is
 *	used only for logging purposes and doesn't affect the key any
 *	other way.
 *
 *	Specifying an unimplemented algorithm will cause failure only if
 *	dstkey != NULL; this allows a transient key with an invalid
 *	algorithm to exist long enough to generate a BADKEY response.
 *
 *	If dns_tsigkey_createfromkey() is successful, a new reference to
 *	'dstkey' will have been made.
 *
 *	dns_tsigkey_create() is a simplified interface that omits
 *	dstkey, generated, restored, inception, and expired (defaulting
 *	to NULL, false, false, 0, and 0).
 *
 *	Requires:
 *\li		'name' is a valid dns_name_t
 *\li		'algorithm' is a valid dns_name_t
 *\li		'secret' is a valid pointer
 *\li		'length' is an integer >= 0
 *\li		'dstkey' is a valid dst key or NULL
 *\li		'creator' points to a valid dns_name_t or is NULL
 *\li		'mctx' is a valid memory context
 *\li		'ring' is a valid TSIG keyring or NULL
 *\li		'key' or '*key' must be NULL
 *
 *	Returns:
 *\li		#ISC_R_SUCCESS
 *\li		#ISC_R_EXISTS - a key with this name already exists
 *\li		#ISC_R_NOTIMPLEMENTED - algorithm is not implemented
 *\li		#ISC_R_NOMEMORY
 */

void
dns_tsigkey_delete(dns_tsigkey_t *key);
/*%<
 *	Prevents this key from being used again.  It will be deleted when
 *	no references exist.
 *
 *	Requires:
 *\li		'key' is a valid TSIG key on a keyring
 */

isc_result_t
dns_tsig_sign(dns_message_t *msg);
/*%<
 *	Generates a TSIG record for this message
 *
 *	Requires:
 *\li		'msg' is a valid message
 *\li		'msg->tsigkey' is a valid TSIG key
 *\li		'msg->tsig' is NULL
 *
 *	Returns:
 *\li		#ISC_R_SUCCESS
 *\li		#ISC_R_NOMEMORY
 *\li		#ISC_R_NOSPACE
 *\li		#DNS_R_EXPECTEDTSIG
 *			- this is a response & msg->querytsig is NULL
 */

isc_result_t
dns_tsig_verify(isc_buffer_t *source, dns_message_t *msg,
		dns_tsigkeyring_t *ring1, dns_tsigkeyring_t *ring2);
/*%<
 *	Verifies the TSIG record in this message
 *
 *	Requires:
 *\li		'source' is a valid buffer containing the unparsed message
 *\li		'msg' is a valid message
 *\li		'msg->tsigkey' is a valid TSIG key if this is a response
 *\li		'msg->tsig' is NULL
 *\li		'msg->querytsig' is not NULL if this is a response
 *\li		'ring1' and 'ring2' are each either a valid keyring or NULL
 *
 *	Returns:
 *\li		#ISC_R_SUCCESS
 *\li		#ISC_R_NOMEMORY
 *\li		#DNS_R_EXPECTEDTSIG - A TSIG was expected but not seen
 *\li		#DNS_R_UNEXPECTEDTSIG - A TSIG was seen but not expected
 *\li		#DNS_R_TSIGERRORSET - the TSIG verified but ->error was set
 *				     and this is a query
 *\li		#DNS_R_CLOCKSKEW - the TSIG failed to verify because of
 *				  the time was out of the allowed range.
 *\li		#DNS_R_TSIGVERIFYFAILURE - the TSIG failed to verify
 *\li		#DNS_R_EXPECTEDRESPONSE - the message was set over TCP and
 *					 should have been a response,
 *					 but was not.
 */

isc_result_t
dns_tsigkey_find(dns_tsigkey_t **tsigkeyp, const dns_name_t *name,
		 const dns_name_t *algorithm, dns_tsigkeyring_t *ring);
/*%<
 *	Returns the TSIG key corresponding to this name and (possibly)
 *	algorithm.  Also increments the key's reference counter.
 *
 *	Requires:
 *\li		'tsigkeyp' is not NULL
 *\li		'*tsigkeyp' is NULL
 *\li		'name' is a valid dns_name_t
 *\li		'algorithm' is a valid dns_name_t or NULL
 *\li		'ring' is a valid keyring
 *
 *	Returns:
 *\li		#ISC_R_SUCCESS
 *\li		#ISC_R_NOTFOUND
 */

const dns_name_t *
dns_tsigkey_algorithm(dns_tsigkey_t *tkey);
/*%<
 * 	Returns the key algorithm associated with a tsigkey object.
 *
 * 	Note that when a tsigkey object is created with algorithm
 * 	DST_ALG_UNKNOWN, the unknown algorithm's name must be cloned
 * 	into tsigkey->algname.
 */

void
dns_tsigkeyring_create(isc_mem_t *mctx, dns_tsigkeyring_t **ringp);
/*%<
 *	Create an empty TSIG key ring.
 *
 *	Requires:
 *\li		'mctx' is not NULL
 *\li		'ringp' is not NULL, and '*ringp' is NULL
 */

isc_result_t
dns_tsigkeyring_add(dns_tsigkeyring_t *ring, dns_tsigkey_t *tkey);
/*%<
 *      Place a TSIG key onto a key ring.
 *
 *      If the key is generated, it is also placed into an LRU queue.
 *      There is a maximum quota of 4096 generated keys per keyring;
 *      if this quota is exceeded, the oldest key in the LRU queue is
 *      deleted.
 *
 *	Requires:
 *\li		'name' and 'ring' are not NULL
 *\li		'tkey' is a valid TSIG key, which has not been
 *		       added to any other keyrings
 *
 *	Returns:
 *\li		#ISC_R_SUCCESS
 *\li		Any other value indicates failure.
 */

isc_result_t
dns_tsigkeyring_dump(dns_tsigkeyring_t *ring, FILE *fp);
/*%<
 *	Dump a TSIG key ring to 'fp'.
 *
 *	Requires:
 *\li		'ring' is a valid keyring.
 */

void
dns_tsigkeyring_restore(dns_tsigkeyring_t *ring, FILE *fp);
/*%<
 *	Restore a TSIG keyring from a dump file 'fp'.
 */

#if DNS_TSIG_TRACE
#define dns_tsigkey_ref(ptr) dns_tsigkey__ref(ptr, __func__, __FILE__, __LINE__)
#define dns_tsigkey_unref(ptr) \
	dns_tsigkey__unref(ptr, __func__, __FILE__, __LINE__)
#define dns_tsigkey_attach(ptr, ptrp) \
	dns_tsigkey__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define dns_tsigkey_detach(ptrp) \
	dns_tsigkey__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(dns_tsigkey);

#define dns_tsigkeyring_ref(ptr) \
	dns_tsigkeyring__ref(ptr, __func__, __FILE__, __LINE__)
#define dns_tsigkeyring_unref(ptr) \
	dns_tsigkeyring__unref(ptr, __func__, __FILE__, __LINE__)
#define dns_tsigkeyring_attach(ptr, ptrp) \
	dns_tsigkeyring__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define dns_tsigkeyring_detach(ptrp) \
	dns_tsigkeyring__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(dns_tsigkeyring);
#else
ISC_REFCOUNT_DECL(dns_tsigkey);
ISC_REFCOUNT_DECL(dns_tsigkeyring);
#endif

ISC_LANG_ENDDECLS
