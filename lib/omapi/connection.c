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

/* $Id: connection.c,v 1.3 2000/01/04 20:04:37 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Subroutines for dealing with connections.
 */
#include <errno.h>
#include <fcntl.h>		/* F_SETFL, O_NONBLOCK */
#include <stddef.h>		/* NULL */
#include <string.h>		/* memset */
#include <unistd.h>		/* close */

#include <isc/assertions.h>
#include <isc/netdb.h>

#include <omapi/private.h>

/*
 * Swiped from bin/tests/sdig.c.
 */
static isc_result_t
get_address(const char *hostname, in_port_t port, isc_sockaddr_t *sockaddr) {
	struct in_addr in4;
	struct in6_addr in6;
	struct hostent *he;

	/*
	 * Is this an IPv6 numeric address?
	 */
	if (omapi_ipv6 && inet_pton(AF_INET6, hostname, &in6) == 1)
		isc_sockaddr_fromin6(sockaddr, &in6, port);

	/*
	 * What about an IPv4 numeric address?
	 */
	else if (inet_pton(AF_INET, hostname, &in4) == 1)
		isc_sockaddr_fromin(sockaddr, &in4, port);

	else {
		/*
		 * Look up the host name.
		 */
		he = gethostbyname(hostname);
		if (he == NULL)
			return (ISC_R_NOTFOUND);

		INSIST(he->h_addrtype == AF_INET);
		isc_sockaddr_fromin(sockaddr,
				    (struct in_addr *)(he->h_addr_list[0]),
				    port);
	}

	return (ISC_R_SUCCESS);
}

/*
 * This is the function that is called when a CONNECT event is posted on
 * the socket as a result of isc_socket_connect.
 */
static void
omapi_connection_connect(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	isc_socket_connev_t *connect_event;
	omapi_connection_object_t *connection;

	ENSURE(event->sender == connection->socket);

	connect_event = (isc_socket_connev_t *)event;
	if (connect_event->result != ISC_R_SUCCESS) {
		isc_socket_detach(&connection->socket);
		isc_event_free(&event);
		isc_task_shutdown(task);
		return;
	}

	connection = event->arg;

	result = isc_socket_getpeername(connection->socket,
					&connection->remote_addr);
	if (result != ISC_R_SUCCESS) {
		OBJECT_DEREF(&connection, "omapi_connection_connect");
		return;
	}

	result = isc_socket_getsockname(connection->socket,
					&connection->local_addr);
	if (result != ISC_R_SUCCESS) {
		OBJECT_DEREF(&connection, "omapi_connection_connect");
		return;
	}
	
	connection->state = omapi_connection_connected;

	isc_event_free(&event);

	return;
}

/*
 * Make an outgoing connection to an OMAPI server.
 */
isc_result_t
omapi_connection_toserver(omapi_object_t *c, const char *server_name, int port)
{
	isc_result_t result;
	isc_buffer_t *ibuffer, *obuffer;
	isc_task_t *task;
	isc_sockaddr_t sockaddr;
	omapi_connection_object_t *obj;
#if 0	/*XXXDCL*/
	int flag;
#endif

	result = get_address(server_name, port, &sockaddr);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Prepare the task that will wait for the connection to be made.
	 */
	task = NULL;
	result = isc_task_create(omapi_taskmgr, NULL, 0, &task);
	if (result != ISC_R_SUCCESS)
		return (result);

	ibuffer = NULL;
	result = isc_buffer_allocate(omapi_mctx, &ibuffer, OMAPI_BUFFER_SIZE,
				     ISC_BUFFERTYPE_BINARY);
	if (result != ISC_R_SUCCESS)
		return (result);

	obuffer = NULL;
	result = isc_buffer_allocate(omapi_mctx, &obuffer, OMAPI_BUFFER_SIZE,
				     ISC_BUFFERTYPE_BINARY);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * XXXDCL on errors I need to also blast the task and buffers.
	 */

	/*
	 * Create a new connection object.
	 */
	obj = isc_mem_get(omapi_mctx, sizeof(*obj));
	if (obj == NULL)
		return (ISC_R_NOMEMORY);
	memset(obj, 0, sizeof(*obj));
	obj->refcnt = 1;
	obj->task = task;
	obj->type = omapi_type_connection;

	ISC_LIST_INIT(obj->input_buffers);
	ISC_LIST_APPEND(obj->input_buffers, ibuffer, link);
	ISC_LIST_INIT(obj->output_buffers);
	ISC_LIST_APPEND(obj->output_buffers, obuffer, link);

	/*
	 * Tie the new connection object to the protocol object.
	 */
	OBJECT_REF(&c->outer, obj, "omapi_connection_toserver");
	OBJECT_REF(&obj->inner, c, "omapi_connection_toserver");

	/*
	 * Create a socket on which to communicate.
	 */
	result = isc_socket_create(omapi_socketmgr, isc_sockaddr_pf(&sockaddr),
				   isc_sockettype_tcp, &obj->socket);
	if (result != ISC_R_SUCCESS) {
		/* XXXDCL this call and later will not free the connection obj
		 * because it has two refcnts, one for existing plus one
		 * for the tie to h->outer.  This does not seem right to me.
		 */
		OBJECT_DEREF(&obj, "omapi_connection_toserver");
		return (result);
	}

#if 0 /*XXXDCL*/
	/*
	 * Set the SO_REUSEADDR flag (this should not fail).
	 */
	flag = 1;
	if (setsockopt(obj->socket, SOL_SOCKET, SO_REUSEADDR,
		       (char *)&flag, sizeof(flag)) < 0) {
		OBJECT_DEREF(&obj, "omapi_connect");
		return (ISC_R_UNEXPECTED);
	}
#endif

	result = isc_socket_connect(obj->socket, &sockaddr, task,
				    omapi_connection_connect, obj);
	if (result != ISC_R_SUCCESS)
 		OBJECT_DEREF(&obj, "omapi_connection_toserver");
	return (result);
}

/*
 * Disconnect a connection object from the remote end.   If force is true,
 * close the connection immediately.   Otherwise, shut down the receiving end
 * but allow any unsent data to be sent before actually closing the socket.
 */

void
omapi_disconnect(omapi_object_t *generic, isc_boolean_t force) {
	omapi_connection_object_t *connection;

	REQUIRE(generic != NULL);

	connection = (omapi_connection_object_t *)generic;

	REQUIRE(connection->type == omapi_type_connection);

	if (! force) {
		/*
		 * If we're already disconnecting, we don't have to do
		 * anything.
		 */
		if (connection->state == omapi_connection_disconnecting)
			return;

		/*
		 * Try to shut down the socket - this sends a FIN to the
		 * remote end, so that it won't send us any more data.   If
		 * the shutdown succeeds, and we still have bytes left to
		 * write, defer closing the socket until that's done.
		 */
		if (connection->out_bytes > 0) {
#if 0 /*XXXDCL*/
			isc_socket_shutdown(connection->socket,
					    ISC_SOCKSHUT_RECV); 
#else
			isc_socket_cancel(connection->socket, NULL,
					  ISC_SOCKCANCEL_RECV);
#endif
			connection->state = omapi_connection_disconnecting;
			return;
		}
	}

	isc_task_shutdown(connection->task);
	connection->state = omapi_connection_closed;

	/*
	 * Disconnect from I/O object, if any.
	 */
	if (connection->outer != NULL)
		OBJECT_DEREF(&connection->outer, "omapi_disconnect");

	/*
	 * If whatever created us registered a signal handler, send it
	 * a disconnect signal.
	 */
	omapi_signal(generic, "disconnect", generic);
}

isc_result_t
omapi_connection_require(omapi_object_t *generic, unsigned int bytes) {
	omapi_connection_object_t *connection;

	REQUIRE(generic != NULL && generic->type == omapi_type_connection);

	connection = (omapi_connection_object_t *)generic;

	connection->bytes_needed = bytes;
	if (connection->bytes_needed <= connection->in_bytes)
		return (ISC_R_SUCCESS);

	return (ISC_R_NOTYET);
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
		OBJECT_DEREF(&c->listener, name);
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
