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

/*
 * Subroutines that support the generic listener object.
 */
#include <errno.h>
#include <fcntl.h>		/* fcntl, F_SETFL, O_NONBLOCK */
#include <stddef.h>		/* NULL */
#include <stdlib.h>		/* malloc, free */
#include <string.h>		/* memset */
#include <unistd.h>		/* close */

#include <isc/assertions.h>

#include <omapi/omapip_p.h>

typedef struct omapi_listener_object {
	OMAPI_OBJECT_PREAMBLE;
	/*
	 * Connection socket.
	 */
	int socket;
	struct sockaddr_in address;
} omapi_listener_object_t;

isc_result_t
omapi_listen(omapi_object_t *h, int port, int max) {
	isc_result_t result;
	omapi_listener_object_t *obj;

	/*
	 * Get the handle.
	 */
	obj = (omapi_listener_object_t *)malloc(sizeof(*obj));
	if (obj == NULL)
		return (ISC_R_NOMEMORY);
	memset(obj, 0, sizeof(*obj));
	obj->refcnt = 1;
	obj->type = omapi_type_listener;

	/*
	 * Connect this object to the inner object.
	 */
	omapi_object_reference(&h->outer, (omapi_object_t *)obj,
			       "omapi_protocol_listen");
	omapi_object_reference(&obj->inner, h, "omapi_protocol_listen");

	/*
	 * Set up the address on which we will listen.
	 */
	obj->address.sin_port = htons(port);
	obj->address.sin_addr.s_addr = htonl(INADDR_ANY);

	/*
	 * Create a socket on which to listen.
	 */
	obj->socket = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (obj->socket < 0) {
		omapi_object_dereference((omapi_object_t **)&obj,
					 "omapi_listen");
		if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS)
			return (ISC_R_NORESOURCES);
		return (ISC_R_UNEXPECTED);
	}
	
	/*
	 * Try to bind to the wildcard address using the port number
	 * we were given.
	 */
	if (bind(obj->socket,
		 (struct sockaddr *)&obj->address, sizeof(obj->address)) < 0) {
		omapi_object_dereference((omapi_object_t **)&obj,
					 "omapi_listen");
		if (errno == EADDRINUSE)
			return (ISC_R_ADDRNOTAVAIL);
		if (errno == EPERM)
			return (ISC_R_NOPERM);
		return (ISC_R_UNEXPECTED);
	}

	/*
	 * Now tell the kernel to listen for connections.
	 */
	if (listen(obj->socket, max) < 0) {
		omapi_object_dereference((omapi_object_t **)&obj,
					 "omapi_listen");
		return (ISC_R_UNEXPECTED);
	}

	if (fcntl(obj->socket, F_SETFL, O_NONBLOCK) < 0) {
		omapi_object_dereference((omapi_object_t **)&obj,
					 "omapi_connect");
		return (ISC_R_UNEXPECTED);
	}

	result = omapi_register_io_object((omapi_object_t *)obj,
					  omapi_listener_readfd, 0,
					  omapi_accept, 0, 0);
	if (result != ISC_R_SUCCESS) {
		omapi_object_dereference((omapi_object_t **)&obj,
					  "omapi_listen");
		return (result);
	}

	return (ISC_R_SUCCESS);
}

/*
 * Return the socket on which the dispatcher should wait for readiness
 * to read, for a listener object.
 */
int
omapi_listener_readfd (omapi_object_t *h) {
	omapi_listener_object_t *l;

	REQUIRE(h != NULL && h->type == omapi_type_listener);

	l = (omapi_listener_object_t *)h;
	
	return (l->socket);
}

/*
 * Reader callback for a listener object.   Accept an incoming connection.
 */
isc_result_t
omapi_accept (omapi_object_t *h) {
	isc_result_t result;
	int len;
	omapi_connection_object_t *obj;
	omapi_listener_object_t *listener;

	REQUIRE(h != NULL && h->type == omapi_type_listener);

	listener = (omapi_listener_object_t *)h;
	
	/*
	 * Get the handle.
	 */
	obj = (omapi_connection_object_t *)malloc(sizeof(*obj));
	if (obj == NULL)
		return (ISC_R_NOMEMORY);
	memset(obj, 0, sizeof(*obj));
	obj->refcnt = 1;
	obj->type = omapi_type_connection;

	/*
	 * Accept the connection.
	 */
	len = sizeof(obj->remote_addr);
	obj->socket = accept(listener->socket,
			     ((struct sockaddr *)&(obj->remote_addr)), &len);
	if (obj->socket < 0) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "omapi_accept");
		if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS)
			return (ISC_R_NORESOURCES);
		return (ISC_R_UNEXPECTED);
	}
	
	obj->state = omapi_connection_connected;

	result = omapi_register_io_object((omapi_object_t *)obj,
					  omapi_connection_readfd,
					  omapi_connection_writefd,
					  omapi_connection_reader,
					  omapi_connection_writer,
					  omapi_connection_reaper);
	if (result != ISC_R_SUCCESS) {
		omapi_object_dereference((omapi_object_t **)&obj,
					 "omapi_accept");
		return (result);
	}

	omapi_object_reference(&obj->listener, (omapi_object_t *)listener,
			       "omapi_accept");

	result = omapi_signal(h, "connect", obj);

	/*
	 * Lose our reference to the connection, so it'll be gc'd when it's
	 * reaped.
	 */
	omapi_object_dereference ((omapi_object_t **)&obj, "omapi_accept");
	return (result);
}

isc_result_t
omapi_listener_set_value(omapi_object_t *h, omapi_object_t *id,
			 omapi_data_string_t *name,
			 omapi_typed_data_t *value)
{
	REQUIRE(h != NULL && h->type == omapi_type_listener);
	
	if (h->inner != NULL && h->inner->type->set_value != NULL)
		return (*(h->inner->type->set_value))(h->inner, id,
						      name, value);
	return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_listener_get_value(omapi_object_t *h, omapi_object_t *id,
			 omapi_data_string_t *name,
			 omapi_value_t **value)
{
	REQUIRE(h != NULL && h->type == omapi_type_listener);
	
	if (h->inner != NULL && h->inner->type->get_value != NULL)
		return (*(h->inner->type->get_value))(h->inner, id,
						      name, value);
	return (ISC_R_NOTFOUND);
}

void
omapi_listener_destroy(omapi_object_t *h, const char *name) {
	omapi_listener_object_t *l;

	REQUIRE(h != NULL && h->type == omapi_type_listener);

	(void)name;		/* Unused. */

	l = (omapi_listener_object_t *)h;
	
	if (l->socket != -1) {
		close(l->socket);
		l->socket = -1;
	}
}

isc_result_t
omapi_listener_signal_handler(omapi_object_t *h, const char *name, va_list ap)
{
	REQUIRE(h != NULL && h->type == omapi_type_listener);
	
	if (h->inner != NULL && h->inner->type->signal_handler != NULL)
		return (*(h->inner->type->signal_handler))(h->inner, name, ap);
	return (ISC_R_NOTFOUND);
}

/*
 * Write all the published values associated with the object through the
 * specified connection.
 */

isc_result_t
omapi_listener_stuff_values(omapi_object_t *c, omapi_object_t *id,
			    omapi_object_t *h)
{
	REQUIRE(h != NULL && h->type == omapi_type_listener);

	if (h->inner != NULL && h->inner->type->stuff_values != NULL)
		return (*(h->inner->type->stuff_values))(c, id, h->inner);
	return (ISC_R_SUCCESS);
}

