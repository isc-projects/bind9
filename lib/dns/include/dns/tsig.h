/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#ifndef DNS_TSIG_H
#define DNS_TSIG_H 1

#include <isc/mem.h>
#include <isc/lang.h>

#include <dns/types.h>
#include <dns/name.h>

#include <dst/dst.h>

ISC_LANG_BEGINDECLS

/* Standard algorithm */
#define DNS_TSIG_HMACMD5		"HMAC-MD5.SIG-ALG.REG.INT."
extern dns_name_t *dns_tsig_hmacmd5_name;
#define DNS_TSIG_HMACMD5_NAME		dns_tsig_hmacmd5_name

/* Default fudge value. */
#define DNS_TSIG_FUDGE			300

struct dns_tsig_key {
	unsigned int			magic;		/* Magic number. */
	isc_mem_t			*mctx;
	dst_key_t			*key;		/* Key */
	dns_name_t			name;		/* Key name */
	dns_name_t			algorithm;	/* Algorithm name */
	ISC_LINK(dns_tsig_key_t)	link;
};

#define dns_tsig_emptykey(tsigkey) ((tsigkey)->key == NULL)

isc_result_t
dns_tsig_key_create(dns_name_t *name, dns_name_t *algorithm,
		    unsigned char *secret, int length, isc_mem_t *mctx,
		    dns_tsig_key_t **key);
/*
 *	Creates a tsig key structure pointed to by 'key'.
 *
 *	Requires:
 *		'name' is a valid dns_name_t
 *		'algorithm' is a valid dns_name_t
 *		'secret' is a valid pointer
 *		'length' is an integer greater than 0
 *		'mctx' is a valid memory context
 *		'key' must not be NULL
 *		'*key' must be NULL
 *
 *	Returns:
 *		ISC_R_SUCCESS
 *		DNS_R_NOTIMPLEMENTED - algorithm is not implemented
 *		ISC_R_NOMEMORY
 */

void
dns_tsig_key_free(dns_tsig_key_t **key);
/*
 *	Frees the tsig key structure pointed to by 'key'.
 *
 *	Requires:
 *		'key' is a valid TSIG key
 */

isc_result_t
dns_tsig_sign(dns_message_t *msg);
/*
 *	Generates a TSIG record for this message
 *
 *	Requires:
 *		'msg' is a valid message
 *		'msg->tsigkey' is a valid TSIG key
 *		'msg->tsig' is NULL
 *		'msg->querytsig' is not NULL if this is a response
 *
 *	Returns:
 *		ISC_R_SUCCESS
 *		ISC_R_NOMEMORY
 *		ISC_R_NOSPACE
 */

isc_result_t
dns_tsig_verify(isc_buffer_t *source, dns_message_t *msg);
/*
 *	Verifies the TSIG record in this message
 *
 *	Requires:
 *		'source' is a valid buffer containing the unparsed message
 *		'msg' is a valid message containing a TSIG record
 *		'msg->tsigkey' is a valid TSIG key if this is a response
 *		'msg->tsig' is NULL
 *		'msg->querytsig' is not NULL if this is a response
 *
 *	Returns:
 *		DNS_R_SUCCESS
 *		ISC_R_NOMEMORY
 *		DNS_R_TSIGERRORSET - the TSIG verified but ->error was set
 *				     and this is a query
 *		DNS_R_TSIGVERIFYFAILURE - the TSIG failed to verify
 */

isc_result_t
dns_tsig_findkey(dns_tsig_key_t **tsigkey, dns_name_t *name,
		 dns_name_t *algorithm);
/*
 *	Returns the TSIG key corresponding to this name and algorithm
 *
 *	Requires:
 *		'tsigkey' is not NULL
 *		'*tsigkey' is NULL
 *		'name' is a valid dns_name_t
 *		'algorithm' is a valid dns_name_t
 *
 *	Returns:
 *		ISC_R_SUCCESS
 *		ISC_R_NOTFOUND
 */


isc_result_t
dns_tsig_init(isc_mem_t *mctx);
/*
 *	Initializes the TSIG subsystem
 *
 *	Returns:
 *		ISC_R_SUCCESS
 *		ISC_R_NOMEMORY
 */


void
dns_tsig_destroy(void);
/*
 *	Frees all data associated with the TSIG subsystem
 */

ISC_LANG_ENDDECLS

#endif /* DNS_TSIG_H */
