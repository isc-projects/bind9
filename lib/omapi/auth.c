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

/* $Id: auth.c,v 1.8.2.2 2000/07/12 00:02:12 gson Exp $ */

/* Principal Author: DCL */

/*
 * XXXDCL Todo:
 * How do keys get specified by named.conf for the control channel?
 * Could use the keys in the address_match_list (acl) specified in the
 * "controls" statement.  All of the keys would need to be at the beginning,
 * so the match does not stop at an IP address.  The server would register
 * all of the keys.  Currently, however, there is no way to limit a key
 * to a particular listening interface on the server, as the configuration
 * file would allow.
 */

/*
 * Subroutines for dealing with authorization.
 */

#include <config.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dst/result.h>

#include <omapi/private.h>

typedef struct auth auth_t;

#define AUTH_MAGIC 	0x41555448U	/* AUTH. */
#define VALID_AUTH(a)	((a) != NULL && (a)->magic == AUTH_MAGIC)

/*
 * XXXDCL For reloading, Make refcounted, and use attach and detach?
 */
struct auth {
	unsigned int		magic;
	char			*name;
	char			*secret;
	size_t			secretlen;
	unsigned int		algorithms;

	ISC_LINK(auth_t)	link;
};

static ISC_LIST(auth_t) omapi_authlist;
static isc_mutex_t mutex;		/* To lock the previous variable. */
static isc_once_t once = ISC_ONCE_INIT; /* To initialize the mutex. */

static void
initialize_mutex(void) {
	RUNTIME_CHECK(isc_mutex_init(&mutex) == ISC_R_SUCCESS);
}

static isc_result_t
auth_find(const char *name, unsigned int algorithm, auth_t **ap) {
	auth_t *a;
	isc_result_t result;

	REQUIRE(name != NULL);
	REQUIRE(ap != NULL && *ap == NULL);

	for (a = ISC_LIST_HEAD(omapi_authlist); a != NULL;
	     a = ISC_LIST_NEXT(a, link))
		if (strcmp(name, a->name) == 0)
			break;

	if (a == NULL)
		result = ISC_R_NOTFOUND;

	else if (algorithm != 0 && (algorithm & a->algorithms) != algorithm)
		result = DST_R_UNSUPPORTEDALG;

	else {
		ENSURE(VALID_AUTH(a));

		*ap = a;

		result = ISC_R_SUCCESS;
	}

	return (result);
}


isc_result_t
auth_makekey(const char *name, unsigned int algorithm, dst_key_t **key) {
	isc_result_t result;
	isc_buffer_t secret;
	auth_t *auth = NULL;
	unsigned int dst_algorithm;
	unsigned int length;
	dns_name_t dnsname;
	char namebuf[1025];
	isc_buffer_t srcb, dstb;

	REQUIRE(name != NULL && algorithm != 0);
	REQUIRE(key != NULL && *key == NULL);

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);
	LOCK(&mutex);
	result = auth_find(name, algorithm, &auth);

	if (result == ISC_R_SUCCESS) {
		switch (algorithm) {
		case OMAPI_AUTH_HMACMD5:
			dst_algorithm = DST_ALG_HMACMD5;
			break;
		default:
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "unknown auth algorithm %d",
					 algorithm);
			return (ISC_R_UNEXPECTED);
		}

		isc_buffer_init(&secret, auth->secret, auth->secretlen);
		isc_buffer_add(&secret, auth->secretlen);

		length = strlen(auth->name);
		isc_buffer_init(&srcb, auth->name, length);
		isc_buffer_add(&srcb, length);
		isc_buffer_init(&dstb, namebuf, sizeof(namebuf));

		dns_name_init(&dnsname, NULL);
		result = dns_name_fromtext(&dnsname, &srcb, dns_rootname,
					   ISC_FALSE, &dstb);
		if (result == ISC_R_SUCCESS)
			result = dst_key_frombuffer(&dnsname, dst_algorithm,
						    0, 0, &secret,
						    omapi_mctx, key);
	}

	UNLOCK(&mutex);

	return (result);
}

static void
auth_delete(auth_t *a) {
	REQUIRE(VALID_AUTH(a));

	ISC_LIST_UNLINK(omapi_authlist, a, link);

	a->magic = 0;

	isc_mem_free(omapi_mctx, a->secret);
	isc_mem_free(omapi_mctx, a->name);
	isc_mem_put(omapi_mctx, a, sizeof(*a));
}

isc_result_t
omapi_auth_register(const char *name, unsigned int algorithms,
		    const unsigned char *secret, size_t secretlen)
{
	auth_t *new = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(name != NULL && secret != NULL);
	REQUIRE(algorithms != 0);

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);
	LOCK(&mutex);

	if (auth_find(name, 0, &new) == ISC_R_SUCCESS)
		result = ISC_R_EXISTS;

	if (result == ISC_R_SUCCESS) {
		new = isc_mem_get(omapi_mctx, sizeof(*new));
		if (new != NULL)
			memset(new, 0, sizeof(*new));
		else
			result  = ISC_R_NOMEMORY;
	}

	if (result == ISC_R_SUCCESS) {
		new->name = isc_mem_strdup(omapi_mctx, name);
		if (new->name == NULL)
			result = ISC_R_NOMEMORY;
	
		new->secret = isc_mem_allocate(omapi_mctx, secretlen);
		if (new->secret == NULL)
			result = ISC_R_NOMEMORY;
		else {
			memcpy(new->secret, secret, secretlen);
			new->secretlen = secretlen;
		}

		new->algorithms = algorithms;

		ISC_LINK_INIT(new, link);

		new->magic = AUTH_MAGIC;

		ISC_LIST_APPEND(omapi_authlist, new, link);
	}

	UNLOCK(&mutex);

	if (result != ISC_R_SUCCESS) {
		if (new->secret != NULL)
			isc_mem_free(omapi_mctx, new->secret);
		if (new->name != NULL)
			isc_mem_free(omapi_mctx, new->name);
		if (new != NULL)
			isc_mem_put(omapi_mctx, new, sizeof(*new));
	}

	return (result);
}

/*
 * Currently the way to effect a reload is to use omapi_auth_deregister(NULL)
 * to remove all of the existing auth structs before building a new
 * omapi_authlist via omapi_auth_register calls.  This clearly leaves a
 * window, however small, where there is no authentication possible.
 */
void
omapi_auth_deregister(const char *name) {
	auth_t *a = NULL;

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);
	LOCK(&mutex);

	if (name == NULL)
		while ((a = ISC_LIST_HEAD(omapi_authlist)) != NULL)
			auth_delete(a);

	else
		if (auth_find(name, 0, &a) == ISC_R_SUCCESS)
			auth_delete(a);

	UNLOCK(&mutex);
}

/*
 * Send a message from the client to the server that says the key with the
 * given name should be used to authenticate messages.
 */
isc_result_t
omapi_auth_use(omapi_object_t *manager, const char *name,
	       unsigned int algorithm) {
	omapi_protocol_t *protocol;
	omapi_connection_t *connection;
	omapi_object_t *message = NULL;
	omapi_object_t *generic = NULL;
	isc_result_t result;
	auth_t *auth = NULL;

	REQUIRE(manager != NULL);
	REQUIRE(manager->type == omapi_type_protocol ||
		(manager->outer != NULL &&
		 manager->outer->type == omapi_type_protocol));

	if (manager->type == omapi_type_protocol)
		protocol = (omapi_protocol_t *)manager;
	else
		protocol = (omapi_protocol_t *)manager->outer;

	REQUIRE(protocol->outer != NULL &&
		protocol->outer->type == omapi_type_connection);

	connection = (omapi_connection_t *)protocol->outer;

	INSIST(connection->is_client);

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);
	LOCK(&mutex);

	result = auth_find(name, algorithm, &auth);

	UNLOCK(&mutex);

	if (result == ISC_R_SUCCESS)
		result = omapi_object_create(&generic, NULL, 0);

	if (result == ISC_R_SUCCESS)
		result = omapi_message_create(&message);

	if (result == ISC_R_SUCCESS)
		result = omapi_object_setinteger(message, "op", OMAPI_OP_OPEN);

	if (result == ISC_R_SUCCESS)
		result = omapi_object_setboolean(message, "update", ISC_TRUE);

	if (result == ISC_R_SUCCESS)
		result = omapi_object_setstring(message, "type", "protocol");

	if (result == ISC_R_SUCCESS)
		result = omapi_object_setobject(message, "object", generic);

	if (result == ISC_R_SUCCESS)
		result = omapi_object_setstring(generic, "auth-name", name);

	if (result == ISC_R_SUCCESS)
		result = omapi_object_setinteger(generic, "auth-algorithm",
						 (int)algorithm);

	if (message != NULL)
		omapi_message_register(message);

	if (result == ISC_R_SUCCESS)
		result =  omapi_message_send(message, manager);

	if (message != NULL) {
		omapi_message_unregister(message);
		omapi_object_dereference(&message);
	}

	if (result == ISC_R_SUCCESS)
		/*
		 * If the name was not found on the server, ISC_R_NOTFOUND
		 * will be returned.  Unlike with a username/password pair,
		 * where it is undesirable to disclose whether it was the
		 * username or password that was at fault, only one item
		 * can be discerned here -- the name, since the secret is
		 * not exchanged.  Therefore there is no point in having
		 * the server obfuscate the ISC_R_NOTFOUND error into some
		 * other error.
		 */
		result = generic->waitresult;

	if (result == ISC_R_SUCCESS)
		/*
		 * This sets up the key in the protocol structure
		 * on this side of the connection.
		 */
		result = object_update((omapi_object_t *)protocol, generic, 0);

	if (generic != NULL)
		omapi_object_dereference(&generic);

	return (result);
}

void
auth_destroy(void) {
	omapi_auth_deregister(NULL);

	RUNTIME_CHECK(isc_mutex_destroy(&mutex) == ISC_R_SUCCESS);
}
