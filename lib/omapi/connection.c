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

/* $Id: connection.c,v 1.7 2000/01/13 06:13:21 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Subroutines for dealing with connections.
 */
#include <config.h>

#include <errno.h>
#include <stddef.h>		/* NULL */
#include <string.h>		/* memset */
#include <unistd.h>		/* close */

#include <isc/assertions.h>
#include <isc/error.h>
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

static void
abandon_connection(omapi_connection_object_t *connection,
		   isc_event_t *event, isc_result_t result)
{
	isc_buffer_t *buffer;

	if (event != NULL)
		isc_event_free(&event);

	if (connection->events_pending > 0) {
		/*
		 * The only time CANCELED results should be generated is
		 * because this function already called isc_socket_cancel.
		 * If this isn't a CANCELED result, then the isc_socket_cancel
		 * needs to be done.
		 */
		if (result != ISC_R_CANCELED)
			isc_socket_cancel(connection->socket, NULL,
					  ISC_SOCKCANCEL_ALL);

		/*
		 * Technically not yet, but the end result is the same.
		 */
		connection->state = omapi_connection_unconnected;

		return;
	}

	while ((buffer = ISC_LIST_HEAD(connection->input_buffers)) != NULL) {
		ISC_LIST_UNLINK(connection->input_buffers, buffer, link);
		isc_buffer_free(&buffer);
	}

	while ((buffer = ISC_LIST_HEAD(connection->output_buffers)) != NULL) {
		ISC_LIST_UNLINK(connection->output_buffers, buffer, link);
		isc_buffer_free(&buffer);
	}

	isc_task_destroy(&connection->task);
	isc_socket_detach(&connection->socket);

	OBJECT_DEREF(&connection, "abandon_connection");

	return;
}

/*
 * This is the function that is called when a connect event is posted on
 * the socket as a result of isc_socket_connect.
 */
static void
connect_done(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	isc_socket_t *socket;
	isc_socket_connev_t *connectevent;
	omapi_connection_object_t *connection;

	socket = event->sender;
	connectevent = (isc_socket_connev_t *)event;
	connection = event->arg;

	ENSURE(socket == connection->socket && task == connection->task);

	connection->events_pending--;

	/*
	 * XXXDCL For some reason, a "connection refused" error is not
	 * being indicated here when it would be expected.  I wonder
	 * how that error is indicated.
	 */

	if (connectevent->result != ISC_R_SUCCESS) {
		abandon_connection(connection, event, connectevent->result);
		return;
	}

	result = isc_socket_getpeername(connection->socket,
					&connection->remote_addr);
	if (result != ISC_R_SUCCESS) {
		abandon_connection(connection, event, connectevent->result);
		return;
	}

	result = isc_socket_getsockname(connection->socket,
					&connection->local_addr);
	if (result != ISC_R_SUCCESS) {
		abandon_connection(connection, event, connectevent->result);
		return;
	}
	
	connection->state = omapi_connection_connected;

	isc_event_free(&event);

	return;
}

/*
 * This is the function that is called when a recv event is posted on
 * the socket as a result of isc_socket_recv*.
 */
static void
recv_done(isc_task_t *task, isc_event_t *event) {
	isc_buffer_t *buffer;
	isc_socket_t *socket;
	isc_socketevent_t *socketevent;
	omapi_connection_object_t *connection;
	unsigned int original_bytes_needed;

	socket = event->sender;
	socketevent = (isc_socketevent_t *)event;
	connection = event->arg;

	ENSURE(socket == connection->socket && task == connection->task);

	connection->events_pending--;

	/*
	 * Restore the input buffers to the connection object.
	 */
	for (buffer = ISC_LIST_HEAD(socketevent->bufferlist);
	     buffer != NULL;
	     buffer = ISC_LIST_NEXT(buffer, link))
		ISC_LIST_APPEND(connection->input_buffers, buffer, link);

	if (socketevent->result != ISC_R_SUCCESS) {
		abandon_connection(connection, event, socketevent->result);
		return;
	}

	connection->in_bytes += socketevent->n;

	original_bytes_needed = connection->bytes_needed;

	while (connection->bytes_needed <= connection->in_bytes &&
	       connection->bytes_needed > 0)
		omapi_signal((omapi_object_t *)connection, "ready",
			     connection);

	/*
	 * Queue up another recv request.  If the bufferlist is empty,
	 * then, something under omapi_signal already called
	 * omapi_connection_require and queued the recv (which is
	 * what emptied the bufferlist).
	 */
	if (! ISC_LIST_EMPTY(connection->input_buffers))
		omapi_connection_require((omapi_object_t *)connection, 0);

	isc_event_free(&event);

}

/*
 * This is the function that is called when a send event is posted on
 * the socket as a result of isc_socket_send*.
 */
static void
send_done(isc_task_t *task, isc_event_t *event) {
	isc_buffer_t *buffer;
	isc_socket_t *socket;
	isc_socketevent_t *socketevent;
	omapi_connection_object_t *connection;

	socket = event->sender;
	socketevent = (isc_socketevent_t *)event;
	connection = event->arg;

	ENSURE(socket == connection->socket && task == connection->task);

	/*
	 * XXXDCL I am assuming that partial writes are not done.  I hope this
	 * does not prove to be incorrect. But the assumption can be tested ...
	 */
	ENSURE(socketevent->n == connection->out_bytes &&
	       socketevent->n ==
	       isc_bufferlist_usedcount(&socketevent->bufferlist));

	connection->events_pending--;

	/*
	 * Restore the head of bufferlist into the connection object, resetting
	 * it to have zero used space, and free the remaining buffers.
	 * This is done before the test of the socketevent's result so that
	 * abandon_connection() can free the buffer, if it is called below.
	 */
	buffer = ISC_LIST_HEAD(socketevent->bufferlist);
	ISC_LIST_APPEND(connection->output_buffers, buffer, link);
	isc_buffer_clear(buffer);

	while ((buffer = ISC_LIST_NEXT(buffer, link)) != NULL) {
		ISC_LIST_UNLINK(socketevent->bufferlist, buffer, link);
		isc_buffer_free(&buffer);
	}

	if (socketevent->result != ISC_R_SUCCESS) {
		abandon_connection(connection, event, socketevent->result);
		return;
	}

	connection->out_bytes -= socketevent->n;

	isc_event_free(&event);

	return;
}

void
connection_send(omapi_connection_object_t *connection) {
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);

	if (connection->out_bytes > 0) {
		ENSURE(!ISC_LIST_EMPTY(connection->output_buffers));

		isc_socket_sendv(connection->socket,
				 &connection->output_buffers, connection->task,
				 send_done, connection);

		connection->events_pending++;
	}
}

/*
 * Make an outgoing connection to an OMAPI server.
 */
isc_result_t
omapi_connection_toserver(omapi_object_t *protocol, const char *server_name,
			  int port)
{
	isc_result_t result;
	isc_sockaddr_t sockaddr;
	isc_buffer_t *ibuffer = NULL, *obuffer = NULL;
	isc_task_t *task = NULL;
	omapi_connection_object_t *connection = NULL;

	result = get_address(server_name, port, &sockaddr);
	if (result != ISC_R_SUCCESS)
		return (result);

	/* XXXDCL Make cleanup better */
	/*
	 * Prepare the task that will wait for the connection to be made.
	 */
	result = isc_task_create(omapi_taskmgr, NULL, 0, &task);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = isc_buffer_allocate(omapi_mctx, &ibuffer, OMAPI_BUFFER_SIZE,
				     ISC_BUFFERTYPE_BINARY);
	if (result != ISC_R_SUCCESS) {
		isc_task_destroy(&task);
		return (result);
	}

	result = isc_buffer_allocate(omapi_mctx, &obuffer, OMAPI_BUFFER_SIZE,
				     ISC_BUFFERTYPE_BINARY);
	if (result != ISC_R_SUCCESS) {
		isc_buffer_free(&ibuffer);
		isc_task_destroy(&task);
		return (result);
	}

	/*
	 * Create a new connection object.
	 */
	result = omapi_object_new((omapi_object_t **)&connection,
				  omapi_type_connection, sizeof(*connection));
	if (result != ISC_R_SUCCESS) {
		isc_buffer_free(&obuffer);
		isc_buffer_free(&ibuffer);
		isc_task_destroy(&task);
		return (result);
	}
		
	connection->is_client = ISC_TRUE;

	connection->task = task;

	ISC_LIST_INIT(connection->input_buffers);
	ISC_LIST_APPEND(connection->input_buffers, ibuffer, link);
	ISC_LIST_INIT(connection->output_buffers);
	ISC_LIST_APPEND(connection->output_buffers, obuffer, link);

	result = isc_mutex_init(&connection->mutex);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = isc_condition_init(&connection->waiter);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * An introductory message is expected from the server.
	 * It is not necessary to lock the mutex here because there
	 * will be no recv() tasks that could possibly compete for the
	 * messages_expected variable, since isc_socket_create has
	 * not even been called yet.
	 */
	connection->messages_expected = 1;

	/*
	 * Tie the new connection object to the protocol object.
	 */
	OBJECT_REF(&protocol->outer, connection, "omapi_connection_toserver");
	OBJECT_REF(&connection->inner, protocol, "omapi_connection_toserver");

	/*
	 * Create a socket on which to communicate.
	 */
	result = isc_socket_create(omapi_socketmgr, isc_sockaddr_pf(&sockaddr),
				   isc_sockettype_tcp, &connection->socket);
	if (result != ISC_R_SUCCESS) {
		/* XXXDCL this call and later will not free the connection obj
		 * because it has two refcnts, one for existing plus one
		 * for the tie to h->outer.  This does not seem right to me.
		 */
		OBJECT_DEREF(&connection, "omapi_connection_toserver");
		isc_buffer_free(&obuffer);
		isc_buffer_free(&ibuffer);
		isc_task_destroy(&task);
		return (result);
	}

#if 0
	/*
	 * Set the SO_REUSEADDR flag (this should not fail).
	 * XXXDCL is this needed?  isc_socket_* does not support it.
	 */
	flag = 1;
	if (setsockopt(connection->socket, SOL_SOCKET, SO_REUSEADDR,
		       (char *)&flag, sizeof(flag)) < 0) {
		OBJECT_DEREF(&connection, "omapi_connect");
		return (ISC_R_UNEXPECTED);
	}
#endif

	result = isc_socket_connect(connection->socket, &sockaddr, task,
				    connect_done, connection);
	if (result != ISC_R_SUCCESS) {
		abandon_connection(connection, NULL, result);
		return (result);
	}

	connection->events_pending++;

	return (result);
}

/*
 * Put some bytes into the output buffer for a connection.
 */
isc_result_t
omapi_connection_copyin(omapi_object_t *generic, unsigned char *src,
			unsigned int len)
{
	omapi_connection_object_t *connection;
	isc_buffer_t *buffer;
	isc_bufferlist_t bufferlist;
	isc_result_t result;
	unsigned int space_available;

	REQUIRE(generic != NULL && generic->type == omapi_type_connection);

	connection = (omapi_connection_object_t *)generic;

	/*
	 * Check for enough space in the output buffers.
	 */
	bufferlist = connection->output_buffers;
	space_available = isc_bufferlist_availablecount(&bufferlist);

	while (space_available < len) {
		/*
		 * Add new buffers until there is sufficient space.
		 */
		buffer = NULL;
		result = isc_buffer_allocate(omapi_mctx, &buffer,
					     OMAPI_BUFFER_SIZE,
					     ISC_BUFFERTYPE_BINARY);
		if (result != ISC_R_SUCCESS)
			return (result);

		space_available += OMAPI_BUFFER_SIZE;
		ISC_LIST_APPEND(bufferlist, buffer, link);
	}

	/*
	 * XXXDCL out_bytes hardly seems needed as it is easy to get a
	 * total of how much data is in the output buffers.
	 */
	connection->out_bytes += len;

	/*
	 * Copy the data into the buffers, splitting across buffers
	 * as necessary.
	 */
	for (buffer = ISC_LIST_HEAD(bufferlist); len > 0;
	     buffer = ISC_LIST_NEXT(buffer, link)) {

		space_available = ISC_BUFFER_AVAILABLECOUNT(buffer);
		if (space_available > len)
			space_available = len;

		isc_buffer_putmem(buffer, src, space_available);

		src += space_available;
		len -= space_available;
	}

	return (ISC_R_SUCCESS);
}

/*
 * Copy some bytes from the input buffer, and advance the input buffer
 * pointer beyond the bytes copied out.
 */
isc_result_t
omapi_connection_copyout(unsigned char *dst, omapi_object_t *generic,
			 unsigned int size)
{
	omapi_connection_object_t *connection;
	isc_buffer_t *buffer;
	unsigned int copy_bytes;

	REQUIRE(generic != NULL && generic->type == omapi_type_connection);

	connection = (omapi_connection_object_t *)generic;

	if (size > connection->in_bytes)
		return (ISC_R_NOMORE);
	
	connection->bytes_needed -= size;

	buffer = ISC_LIST_HEAD(connection->input_buffers);

	/*
	 * The data could potentially be split across multiple buffers,
	 * so rather than a simple memcpy, a loop is needed.
	 */
	while (size > 0) {
		copy_bytes = buffer->used - buffer->current;
		if (copy_bytes > size)
			copy_bytes = size;

		/*
		 * When dst == NULL, this function is being used to skip
		 * over uninteresting input.
		 */
		if (dst != NULL)
			(void)memcpy(dst, buffer->base + buffer->current,
				     copy_bytes);

		isc_buffer_forward(buffer, copy_bytes);

		size -= copy_bytes;
		connection->in_bytes -= copy_bytes;

		buffer = ISC_LIST_NEXT(buffer, link);
	}

	return (ISC_R_SUCCESS);
}

/*
 * Disconnect a connection object from the remote end.   If force is true,
 * close the connection immediately.   Otherwise, shut down the receiving end
 * but allow any unsent data to be sent before actually closing the socket.
 */

void
omapi_connection_disconnect(omapi_object_t *generic, isc_boolean_t force) {
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
		OBJECT_DEREF(&connection->outer, "omapi_connection_disconnect");

	/*
	 * If whatever created us registered a signal handler, send it
	 * a disconnect signal.
	 */
	omapi_signal(generic, "disconnect", generic);
}

/*
 * The caller wants a specific amount of bytes to be read.  Queue up a
 * recv for the socket.
 */
isc_result_t
omapi_connection_require(omapi_object_t *generic, unsigned int bytes) {
	omapi_connection_object_t *connection;

	REQUIRE(generic != NULL && generic->type == omapi_type_connection);

	connection = (omapi_connection_object_t *)generic;

	connection->bytes_needed += bytes;

	if (connection->bytes_needed <= connection->in_bytes)
		return (ISC_R_SUCCESS);

	if (connection->bytes_needed >
	    isc_bufferlist_availablecount(&connection->input_buffers)) {
		/*
		 * Not enough space to put the required volume of information.
		 * See if the space can be attained by getting rid of the
		 * used buffer space.
		 *
		 * This could be made more efficient by not freeing
		 * the completely used buffers, but honestly the free/allocate
		 * code will probably *never* be used in practice; to even test
		 * the free/allocate stuff OMAPI_BUFFER_SIZE has to be set to
		 * an absurdly low value (like 4).
		 */
		isc_bufferlist_t bufferlist = connection->input_buffers;
		isc_buffer_t *buffer;
		isc_result_t result;

		buffer = ISC_LIST_HEAD(bufferlist);

		/*
		 * Lop off any completely used buffers, except the last one.
		 */
		while (ISC_BUFFER_AVAILABLECOUNT(buffer) == 0 &&
		       buffer != ISC_LIST_TAIL(bufferlist)) {

			ISC_LIST_UNLINK(bufferlist, buffer, link);
			isc_buffer_free(&buffer);

			buffer = ISC_LIST_HEAD(bufferlist);
		}

		/*
		 * Reclaim any used space.  (Any buffers after this one,
		 * if they exist at all, will be empty.)
		 */
		isc_buffer_compact(buffer);

		/*
		 * Create as many new buffers as necessary to fit the
		 * entire size requirement.
		 */
		while (connection->bytes_needed >
		       isc_bufferlist_availablecount(&bufferlist)) {

			buffer = NULL;
			result = isc_buffer_allocate(omapi_mctx, &buffer,
						     OMAPI_BUFFER_SIZE,
						     ISC_BUFFERTYPE_BINARY);
			if (result != ISC_R_SUCCESS)
				return (result);

			ISC_LIST_APPEND(bufferlist, buffer, link);
		}
	}

	/*
	 * Queue the receive task.
	 * XXXDCL The "minimum" argument has not been fully thought out.
	 */
	isc_socket_recvv(connection->socket, &connection->input_buffers,
			 connection->bytes_needed - connection->in_bytes,
			 connection->task, recv_done, connection);

	connection->events_pending++;

	return (OMAPI_R_NOTYET);
}

/*
 * This function is meant to pause the client until it has received
 * a message from the server, either the introductory message or a response
 * to a message it has sent.  Because the socket library is multithreaded,
 * those events can happen before omapi_connection_wait is ever called.
 * So a counter needs to be set for every expected message, and this 
 * function can only return when that counter is 0.
 */
isc_result_t
omapi_connection_wait(omapi_object_t *object,
		      omapi_object_t *connection_handle,
		      isc_time_t *timeout)
{
	/*
	 * 'object' is not really used.
	 */
	omapi_connection_object_t *connection;
	isc_result_t result, wait_result;

	REQUIRE(object != NULL && connection_handle != NULL);
	REQUIRE(connection_handle->type == omapi_type_connection);

	connection = (omapi_connection_object_t *)connection_handle;
	/*
	 * This routine is not valid for server connections.
	 */
	REQUIRE(connection->is_client);

	result = isc_mutex_lock(&connection->mutex);
	if (result != ISC_R_SUCCESS)
		return (result);

	wait_result = ISC_R_SUCCESS;

	while (connection->messages_expected > 0 &&
	       wait_result == ISC_R_SUCCESS) {
		if (timeout == NULL)
			wait_result = isc_condition_wait(&connection->waiter,
							 &connection->mutex);
		else
			wait_result =
				isc_condition_waituntil(&connection->waiter,
							&connection->mutex,
							timeout);
	}

	if (wait_result == ISC_R_SUCCESS || wait_result == ISC_R_TIMEDOUT) {
		result = isc_mutex_unlock(&connection->mutex);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	return (wait_result);
}

isc_result_t
omapi_connection_setvalue(omapi_object_t *connection, omapi_object_t *id,
			  omapi_data_string_t *name, omapi_typed_data_t *value)
{
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);
	
	PASS_SETVALUE(connection);
}

isc_result_t
omapi_connection_getvalue(omapi_object_t *connection, omapi_object_t *id,
			  omapi_data_string_t *name, omapi_value_t **value)
{
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);

	PASS_GETVALUE(connection);
}

void
omapi_connection_destroy(omapi_object_t *handle, const char *name) {
	omapi_connection_object_t *connection;

	REQUIRE(handle != NULL && handle->type == omapi_type_connection);

	(void)name;

	connection = (omapi_connection_object_t *)handle;

	if (connection->state == omapi_connection_connected)
		omapi_connection_disconnect(handle, OMAPI_FORCE_DISCONNECT);
}

isc_result_t
omapi_connection_signalhandler(omapi_object_t *connection, const char *name,
			       va_list ap)
{
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);
	
	PASS_SIGNAL(connection);
}

/*
 * Write all the published values associated with the object through the
 * specified connection.
 */
isc_result_t
omapi_connection_stuffvalues(omapi_object_t *connection, omapi_object_t *id,
			     omapi_object_t *handle)
{
	REQUIRE(connection != NULL && connection->type == omapi_type_connection);

	PASS_STUFFVALUES(handle);
}

/*
 * XXXDCL These could potentially use the isc_buffer_* integer functions
 */
isc_result_t
omapi_connection_getuint32(omapi_object_t *c, isc_uint32_t *value) {
	isc_uint32_t inbuf;
	isc_result_t result;

	result = omapi_connection_copyout((unsigned char *)&inbuf, c,
					  sizeof(inbuf));
	if (result != ISC_R_SUCCESS)
		return (result);

	*value = ntohl(inbuf);
	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_connection_putuint32(omapi_object_t *c, isc_uint32_t value) {
	isc_uint32_t inbuf;

	inbuf = htonl(value);
	
	return (omapi_connection_copyin(c, (unsigned char *)&inbuf,
					sizeof(inbuf)));
}

isc_result_t
omapi_connection_getuint16(omapi_object_t *c, isc_uint16_t *value) {
	isc_uint16_t inbuf;
	isc_result_t result;

	result = omapi_connection_copyout((unsigned char *)&inbuf, c,
					  sizeof(inbuf));
	if (result != ISC_R_SUCCESS)
		return (result);

	*value = ntohs(inbuf);
	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_connection_putuint16(omapi_object_t *c, isc_uint32_t value) {
	isc_uint16_t inbuf;

	REQUIRE(value < 65536);

	inbuf = htons((isc_uint16_t)value);
	
	return (omapi_connection_copyin(c, (unsigned char *)&inbuf,
					sizeof(inbuf)));
}

isc_result_t
omapi_connection_puttypeddata(omapi_object_t *c, omapi_typed_data_t *data)
{
	isc_result_t result;
	omapi_handle_t handle;

	REQUIRE(data != NULL &&
		(data->type == omapi_datatype_int    ||
		 data->type == omapi_datatype_string ||
		 data->type == omapi_datatype_data   ||
		 data->type == omapi_datatype_object));

	switch (data->type) {
	      case omapi_datatype_int:
		result = omapi_connection_putuint32(c, sizeof(isc_uint32_t));
		if (result != ISC_R_SUCCESS)
			return (result);
		return (omapi_connection_putuint32(c, ((isc_uint32_t)
							(data->u.integer))));

	      case omapi_datatype_string:
	      case omapi_datatype_data:
		result = omapi_connection_putuint32(c, data->u.buffer.len);
		if (result != ISC_R_SUCCESS)
			return (result);
		if (data->u.buffer.len > 0)
			return (omapi_connection_copyin(c,
							data->u.buffer.value,
							data->u.buffer.len));
		return (ISC_R_SUCCESS);

	      case omapi_datatype_object:
		if (data->u.object != NULL) {
			result = omapi_object_handle(&handle, data->u.object);
			if (result != ISC_R_SUCCESS)
				return (result);
		} else
			handle = 0;
		result = omapi_connection_putuint32(c, sizeof(handle));
		if (result != ISC_R_SUCCESS)
			return (result);
		return (omapi_connection_putuint32(c, handle));
	}

	UNEXPECTED_ERROR(__FILE__, __LINE__,
			 "unknown type in omapi_connection_puttypeddata: "
			 "%d\n", data->type);
	return (ISC_R_UNEXPECTED);
}

isc_result_t
omapi_connection_putname(omapi_object_t *c, const char *name) {
	isc_result_t result;
	unsigned int len = strlen(name);

	if (len > 65535)
		/* XXXDCL better error? */
		return (ISC_R_FAILURE);

	result = omapi_connection_putuint16(c, len);
	if (result != ISC_R_SUCCESS)
		return (result);

	return (omapi_connection_copyin(c, (char *)name, len));
}

isc_result_t
omapi_connection_putstring(omapi_object_t *c, const char *string) {
	isc_result_t result;
	unsigned int len;

	if (string != NULL)
		len = strlen(string);
	else
		len = 0;

	result = omapi_connection_putuint32(c, len);

	if (result == ISC_R_SUCCESS && len > 0)
		result = omapi_connection_copyin(c, (char *)string, len);
	return (result);
}

isc_result_t
omapi_connection_puthandle(omapi_object_t *c, omapi_object_t *h) {
	isc_result_t result;
	omapi_handle_t handle;

	if (h != NULL) {
		result = omapi_object_handle(&handle, h);
		if (result != ISC_R_SUCCESS)
			return (result);
	} else
		handle = 0;	/* The null handle. */

	result = omapi_connection_putuint32(c, sizeof(handle));

	if (result == ISC_R_SUCCESS)
		result = omapi_connection_putuint32(c, handle);

	return (result);
}
