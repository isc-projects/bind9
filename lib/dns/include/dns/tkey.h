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

#ifndef DNS_TKEY_H
#define DNS_TKEY_H 1

#include <isc/mem.h>
#include <isc/lang.h>

#include <dns/types.h>
#include <dns/name.h>

#include <dst/dst.h>

ISC_LANG_BEGINDECLS

/* Key agreement modes */
#define DNS_TKEYMODE_SERVERASSIGNED		1
#define DNS_TKEYMODE_DIFFIEHELLMAN		2
#define DNS_TKEYMODE_GSSAPI			3
#define DNS_TKEYMODE_RESOLVERASSIGNED		4
#define DNS_TKEYMODE_DELETE			5

isc_result_t
dns_tkey_processquery(dns_message_t *msg);
/*
 *	Processes a query containing a TKEY record, adding or deleting TSIG
 *	keys if necessary, and modifies the message to contain the response.
 *
 *	Requires:
 *		'msg' is a valid message
 *
 *	Returns
 *		ISC_R_SUCCESS	msg was updated (the TKEY operation succeeded,
 *				or msg now includes a TKEY with an error set)
 *		DNS_R_FORMERR	the packet was malformed (missing a TKEY
 *				or KEY).
 *		other		An error occurred while processing the message
 */

isc_result_t
dns_tkey_builddeletequery(dns_message_t *msg, dns_tsigkey_t *key);
/*
 *	Builds a query containing a TKEY record that will delete the
 *	specified shared secret from the server.
 *
 *	Requires:
 *		'msg' is a valid message
 *		'key' is a valid TSIG key
 *
 *	Returns:
 *		ISC_R_SUCCESS	msg was successfully updated to include the
 *				query to be sent
 *		other		an error occurred while building the message
 */

isc_result_t
dns_tkey_builddhquery(dns_message_t *msg, dst_key_t *key, dns_name_t *name,
		      dns_name_t *algorithm);
/*
 *	Builds a query containing a TKEY that will generate a shared
 *	secret using a Diffie-Hellman key exchange.  The shared key
 *	will be of the specified algorithm (only DNS_TSIG_HMACMD5_NAME
 *	is supported), and will be named either 'name',
 *	'name' + server chosen domain, or random data + server chosen domain
 *	if 'name' == dns_rootname
 *
 *	Requires:
 *		'msg' is a valid message
 *		'key' is a valid Diffie Hellman dst key
 *		'name' is a valid name
 *		'algorithm' is a valid name
 *
 *	Returns:
 *		ISC_R_SUCCESS	msg was successfully updated to include the
 *				query to be sent
 *		other		an error occurred while building the message
 */


ISC_LANG_ENDDECLS

#endif /* DNS_TKEY_H */
