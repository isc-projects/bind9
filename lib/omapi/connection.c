/*
 * Copyright (C) 1996, 1997, 1998, 1999  Internet Software Consortium.
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

/* $Id: connection.c,v 1.2 1999/11/02 04:01:32 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Subroutines for dealing with connections.
 */
#include <errno.h>
#include <fcntl.h>		/* F_SETFL, O_NONBLOCK */
#include <stddef.h>		/* NULL */
#include <stdlib.h>		/* malloc, free */
#include <string.h>		/* memset */
#include <unistd.h>		/* close */

#include <isc/assertions.h>
#include <isc/netdb.h>

#include <omapi/omapip_p.h>

isc_result_t
omapi_connect(omapi_object_t *c, const char *server_name, int port) {
	struct hostent *he;
	int hix;
	isc_result_t result;
	omapi_connection_object_t *obj;
	int flag;

	obj = (omapi_connection_object_t *)malloc(sizeof(*obj));
	if (obj == NULL)
		return (ISC_R_NOMEMORY);
	memset(obj, 0, sizeof(*obj));
	obj->refcnt = 1;
	obj->type = omapi_type_connection;

	omapi_object_reference(&c->outer, (omapi_object_t *)obj,
			       "omapi_protocol_connect");

	omapi_object_reference(&obj->inner, c, "omapi_protocol_connect");

	/*
	 * Set up all the constants in the address.
	 */
	obj->remote_addr.sin_port = htons(port);

	/*
	 * First try for a numeric address, since that's easier to check.
	 */
	if (inet_aton(server_name, &obj->remote_addr.sin_addr) == 0) {
		/*
		 * If we didn't get a numeric address, try for a domain
		 * name.  It's okay for this call to block.
		 */
		he = gethostbyname(server_name);
		if (he == NULL) {
			omapi_object_dereference((omapi_object_t **)&obj,
						 "omapi_connect");
			return (ISC_R_NOTFOUND);
		}
		hix = 1;
		memcpy (&obj->remote_addr.sin_addr,
			he->h_addr_list[0],
			sizeof(obj->remote_addr.sin_addr));
	} else
		he = NULL;

#ifdef ISC_NET_HAVESALEN
	obj->remote_addr.sin_len = sizeof(struct sockaddr_in);
#endif
	obj->remote_addr.sin_family = AF_INET;
	memset(&(obj->remote_addr.sin_zero), 0,
	       sizeof(obj->remote_addr.sin_zero));

	/*
	 * Create a socket on which to communicate.
	 */
	obj->socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (obj->socket < 0) {
		omapi_object_dereference((omapi_object_t **)&obj,
					 "omapi_connect");
		if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS)
			return (ISC_R_NORESOURCES);
		return (ISC_R_UNEXPECTED);
	}

	/*
	 * Set the SO_REUSEADDR flag (this should not fail).
	 */
	flag = 1;
	if (setsockopt(obj->socket, SOL_SOCKET, SO_REUSEADDR,
		       (char *)&flag, sizeof(flag)) < 0) {
		omapi_object_dereference((omapi_object_t **)&obj,
					 "omapi_connect");
		return (ISC_R_UNEXPECTED);
	}

	/*
	 * Try to connect to the one IP address we were given, or any of
	 * the IP addresses listed in the host's A RR.
	 */
	while (connect(obj->socket, ((struct sockaddr *)&obj->remote_addr),
		       sizeof(obj->remote_addr)) < 0) {
		if (he == NULL || he->h_addr_list[hix] == NULL) {
			omapi_object_dereference((omapi_object_t **)&obj,
						 "omapi_connect");
			if (errno == ECONNREFUSED)
				return (ISC_R_CONNREFUSED);
			if (errno == ENETUNREACH)
				return (ISC_R_NETUNREACH);
			return (ISC_R_UNEXPECTED);
		}
		memcpy(&obj->remote_addr.sin_addr, he->h_addr_list[hix++],
		       sizeof(obj->remote_addr.sin_addr));
	}

	obj->state = omapi_connection_connected;

	/*
	 * I don't know why this would fail, so I'm tempted not to test
	 * the return value.
	 */
	hix = sizeof(obj->local_addr);
	if (getsockname(obj->socket, (struct sockaddr *)&obj->local_addr,
			&hix) < 0)
		result = ISC_R_UNEXPECTED;
	else	
		result = ISC_R_SUCCESS;

	if (result == ISC_R_SUCCESS)
		if (fcntl(obj->socket, F_SETFL, O_NONBLOCK) < 0)
			result = ISC_R_UNEXPECTED;

	if (result == ISC_R_SUCCESS)
		result = omapi_register_io_object((omapi_object_t *)obj,
						  omapi_connection_readfd,
						  omapi_connection_writefd,
						  omapi_connection_reader,
						  omapi_connection_writer,
						  omapi_connection_reaper);

	if (result != ISC_R_SUCCESS)
		omapi_object_dereference((omapi_object_t **)&obj,
					 "omapi_connect");

	return (result);
}

/*
 * Disconnect a connection object from the remote end.   If force is true,
 * close the connection immediately.   Otherwise, shut down the receiving end
 * but allow any unsent data to be sent before actually closing the socket.
 */

void
omapi_disconnect(omapi_object_t *h, isc_boolean_t force) {
	omapi_connection_object_t *c;

	REQUIRE(h != NULL);

	c = (omapi_connection_object_t *)h;

	REQUIRE(c->type == omapi_type_connection);

	if (! force) {
		/*
		 * If we're already disconnecting, we don't have to do
		 * anything.
		 */
		if (c->state == omapi_connection_disconnecting)
			return;

		/*
		 * Try to shut down the socket - this sends a FIN to the
		 * remote end, so that it won't send us any more data.   If
		 * the shutdown succeeds, and we still have bytes left to
		 * write, defer closing the socket until that's done.
		 */
		if (shutdown(c->socket, SHUT_RD) == 0) {
			if (c->out_bytes > 0) {
				c->state = omapi_connection_disconnecting;
				return;
			}
		}
	}

	close(c->socket);
	c->state = omapi_connection_closed;

	/*
	 * Disconnect from I/O object, if any.
	 */
	if (h->outer != NULL)
		omapi_object_dereference(&h->outer, "omapi_disconnect");

	/*
	 * If whatever created us registered a signal handler, send it
	 * a disconnect signal.
	 */
	omapi_signal(h, "disconnect", h);
}

isc_result_t
omapi_connection_require(omapi_object_t *h, unsigned int bytes) {
	omapi_connection_object_t *c;

	REQUIRE(h != NULL && h->type == omapi_type_connection);

	c = (omapi_connection_object_t *)h;

	c->bytes_needed = bytes;
	if (c->bytes_needed <= c->in_bytes)
		return (ISC_R_SUCCESS);

	return (ISC_R_NOTYET);
}

/*
 * Return the socket on which the dispatcher should wait for readiness
 * to read, for a connection object.   If we already have more bytes than
 * we need to do the next thing, and we have at least a single full input
 * buffer, then don't indicate that we're ready to read.
 */
int
omapi_connection_readfd(omapi_object_t *h) {
	omapi_connection_object_t *c;

	REQUIRE(h != NULL && h->type == omapi_type_connection);

	c = (omapi_connection_object_t *)h;

	if (c->state != omapi_connection_connected)
		return (-1);
	if (c->in_bytes >= OMAPI_BUFFER_SIZE - 1 &&
	    c->in_bytes > c->bytes_needed)
		return (-1);
	return (c->socket);
}

/*
 * Return the socket on which the dispatcher should wait for readiness
 * to write, for a connection object.   If there are no bytes buffered
 * for writing, then don't indicate that we're ready to write.
 */
int
omapi_connection_writefd(omapi_object_t *h) {
	omapi_connection_object_t *c;

	REQUIRE(h != NULL && h->type == omapi_type_connection);

	c = (omapi_connection_object_t *)h;

	if (c->out_bytes)
		return (c->socket);
	else
		return (-1);
}

/*
 * Reaper function for connection - if the connection is completely closed,
 * reap it.   If it's in the disconnecting state, there were bytes left
 * to write when the user closed it, so if there are now no bytes left to
 * write, we can close it.
 */
isc_result_t
omapi_connection_reaper(omapi_object_t *h) {
	omapi_connection_object_t *c;

	REQUIRE(h != NULL && h->type == omapi_type_connection);

	c = (omapi_connection_object_t *)h;
	if (c->state == omapi_connection_disconnecting && c->out_bytes == 0)
		omapi_disconnect(h, OMAPI_FORCE_DISCONNECT);
	if (c->state == omapi_connection_closed)
		return (ISC_R_NOTCONNECTED);
	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_connection_set_value(omapi_object_t *h, omapi_object_t *id,
			   omapi_data_string_t *name,
			   omapi_typed_data_t *value)
{
	REQUIRE(h != NULL && h->type == omapi_type_connection);
	
	if (h->inner != NULL && h->inner->type->set_value)
		return (*(h->inner->type->set_value))(h->inner, id,
						      name, value);
	return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_connection_get_value(omapi_object_t *h, omapi_object_t *id,
			   omapi_data_string_t *name,
			   omapi_value_t **value)
{
	REQUIRE(h != NULL && h->type == omapi_type_connection);
	
	if (h->inner != NULL && h->inner->type->get_value)
		return (*(h->inner->type->get_value))(h->inner, id,
						      name, value);
	return (ISC_R_NOTFOUND);
}

void
omapi_connection_destroy(omapi_object_t *h, const char *name) {
	omapi_connection_object_t *c;

	REQUIRE(h != NULL && h->type == omapi_type_connection);

	c = (omapi_connection_object_t *)h;

	if (c->state == omapi_connection_connected)
		omapi_disconnect(h, OMAPI_FORCE_DISCONNECT);

	if (c->listener != NULL)
		omapi_object_dereference(&c->listener, name);
}

isc_result_t
omapi_connection_signal_handler(omapi_object_t *h, const char *name,
				va_list ap)
{
	REQUIRE(h != NULL && h->type == omapi_type_connection);
	
	if (h->inner != NULL && h->inner->type->signal_handler)
		return (*(h->inner->type->signal_handler))(h->inner, name, ap);

	return (ISC_R_NOTFOUND);
}

/*
 * Write all the published values associated with the object through the
 * specified connection.
 */

isc_result_t
omapi_connection_stuff_values(omapi_object_t *c, omapi_object_t *id,
			      omapi_object_t *h)
{
	REQUIRE(h != NULL && h->type == omapi_type_connection);

	if (h->inner != NULL && h->inner->type->stuff_values)
		return ((*(h->inner->type->stuff_values))(c, id, h->inner));

	return (ISC_R_SUCCESS);
}
