/*
 * Copyright (C) 1996, 1997, 1998, 1999, 2000  Internet Software Consortium.
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

/* $Id: connection.c,v 1.27 2000/05/17 22:48:07 bwelling Exp $ */

/* Principal Author: DCL */

/*
 * Subroutines for dealing with connections.
 */

#include <config.h>

#include <isc/buffer.h>
#include <isc/bufferlist.h>
#include <isc/netdb.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/task.h>
#include <isc/util.h>

#include <omapi/private.h>
#include <omapi/result.h>

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
	if (isc_net_probeipv6 == ISC_R_SUCCESS &&
	    inet_pton(AF_INET6, hostname, &in6) == 1)
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
 * Called when there are no more events are pending on the socket.
 * It can be detached and data for the connection object freed.
 */
static void
free_connection(omapi_connection_t *connection) {
	isc_buffer_t *buffer;

	connection->state = omapi_connection_disconnecting;

	while ((buffer = ISC_LIST_HEAD(connection->input_buffers)) != NULL) {
		ISC_LIST_UNLINK(connection->input_buffers, buffer, link);
		isc_buffer_free(&buffer);
	}

	while ((buffer = ISC_LIST_HEAD(connection->output_buffers)) != NULL) {
		ISC_LIST_UNLINK(connection->output_buffers, buffer, link);
		isc_buffer_free(&buffer);
	}

	if (connection->task != NULL)
		isc_task_destroy(&connection->task);

	if (connection->socket != NULL)
		isc_socket_detach(&connection->socket);

	if (connection->is_client) {
		RUNTIME_CHECK(isc_mutex_destroy(&connection->wait_lock) ==
			      ISC_R_SUCCESS);
		RUNTIME_CHECK(isc_condition_destroy(&connection->waiter) ==
			      ISC_R_SUCCESS);

		/*
		 * Break the link between the protocol object and its parent
		 * (usually a generic object); this is done so the client's
		 * reference to its managing object does not prevent the
		 * connection object and protocol object from being destroyed.
		 */
		INSIST(connection->inner->type == omapi_type_protocol &&
		       connection->inner->inner != NULL);
		OBJECT_DEREF(&connection->inner->inner->outer);
		OBJECT_DEREF(&connection->inner->inner);

	} else {
		/*
		 * Ensure that the protocol object has no parent, and
		 * signal the listener that the connection is ended.
		 */
		INSIST(connection->inner->inner == NULL);

		object_signal(connection->listener, "disconnect", connection);
		OBJECT_DEREF(&connection->listener);
	}

	/*
	 * Finally, free the object itself.
	 */
	OBJECT_DEREF(&connection);
}

static void
end_connection(omapi_connection_t *connection) {
	connection->state = omapi_connection_disconnecting;

	if (connection->events_pending == 0) {
		connection->state = omapi_connection_closed;

		/*
		 * The client connection will be waiting if the error was
		 * triggered in one of the socket event handlers.  It will
		 * not be waiting an error happened in omapi_meesgae_send
		 * or send_intro.
		 *
		 * The server connection will never be waiting.
		 */
		if (connection->waiting) {
			/*
			 * Signal connection_wait and have it do the cleanup.
			 * free_connection can't be called directly here
			 * because it can't be sure that the mutex has been
			 * finished being touched by connection_wait even if
			 * free_connection has signaled it.  (Nasty little race
			 * condition with the lock.)
			 */
			SIGNAL(&connection->waiter);
		} else
			free_connection(connection);

		return;
	}

	/*
	 * This function is only expected to be called by the client side
	 * when events_pending is 0.  On the server side, this function
	 * could possibly be called with an event pending if
	 * omapi_listener_shutdown was called and had to resort to
	 * forced disconnects to blow away outstanding connections.
	 */
	INSIST(! connection->is_client);

	/*
	 * It is also expected that the library only has one event
	 * outstanding at any given time.
	 */
	INSIST(connection->events_pending == 1);

	/*
	 * Cancel the outstanding event.  It will generate an ISC_R_CANCELED
	 * result for either recv_done or send_done, which will decrement
	 * events_pending to 0 and call end_connection again.
	 */
	isc_socket_cancel(connection->socket, NULL, ISC_SOCKCANCEL_ALL);
}

/*
 * Pause the client until it has received a message from the server, either the
 * introductory message or a response to a message it has sent.  This is
 * necessary because the underlying socket library is multithreaded, and
 * it is possible that reading incoming data would trigger an error 
 * that causes the connection to be destroyed --- while the client program
 * is still trying to use it.
 *
 * This problem does not exist in the server, because everything in the
 * server happens in the socket event functions, and as soon as one
 * detects an error the connection is destroyed and no further attempt
 * is made to use it.  The server has its own mechanism for making sure
 * destroyed connections are gone via omapi_listener_shutdown.
 */
static isc_result_t
connection_wait(omapi_connection_t *connection_handle) {
	omapi_connection_t *connection;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(connection_handle != NULL &&
		connection_handle->type == omapi_type_connection);

	connection = (omapi_connection_t *)connection_handle;
	/*
	 * This routine is not valid for server connections.
	 */
	INSIST(connection->is_client);

	INSIST(connection->state == omapi_connection_connecting ||
	       connection->state == omapi_connection_connected);
	
	connection->waiting = ISC_TRUE;

	while (connection->events_pending > 0)
		WAIT(&connection->waiter, &connection->wait_lock);

	connection->waiting = ISC_FALSE;
	UNLOCK(&connection->wait_lock);

	if (connection->state == omapi_connection_closed) {
		/*
		 * An error occurred and end_connection needs to have
		 * free_connection called now that we're done looking
		 * at connection->events_pending.
		 */
		result = connection->result;

		free_connection(connection);
	}

	return (result);
}

/*
 * This is the function that is called when a connect event is posted on
 * the socket as a result of isc_socket_connect.  It is only called
 * on the client side.
 */
static void
connect_done(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	isc_socket_t *socket;
	omapi_connection_t *connection;

	UNUSED(task);

	socket = event->ev_sender;
	connection = event->ev_arg;
	result = ((isc_socket_connev_t *)event)->result;

	isc_event_free(&event);

	INSIST(socket == connection->socket && task == connection->task);

	/*
	 * Acquire the wait_lock before proceeding, to guarantee that
	 * connection_wait was entered in connection_toserver.
	 */
	LOCK(&connection->wait_lock);
	UNLOCK(&connection->wait_lock);

	INSIST(connection->events_pending == 1);
	connection->events_pending--;

	if (result == ISC_R_SUCCESS)
		result = isc_socket_getpeername(connection->socket,
						&connection->remote_addr);

	if (result == ISC_R_SUCCESS)
		result = isc_socket_getsockname(connection->socket,
						&connection->local_addr);

	if (result == ISC_R_SUCCESS) {
		connection->state = omapi_connection_connected;

		/*
		 * Unblock omapi_protocol_connect so it can send the intro.
		 */
		SIGNAL(&connection->waiter);
	} else {
		/*
		 * Set the state to disconnecting and unblock connection_wait
		 * to free the connection.
		 */
		connection->result = result;

		end_connection(connection);
	}
}

/*
 * This is the function that is called when a recv event is posted on
 * the socket as a result of isc_socket_recv*.  It is called by both the
 * client and the server.
 */
static void
recv_done(isc_task_t *task, isc_event_t *event) {
	isc_buffer_t *buffer;
	isc_bufferlist_t bufferlist;
	isc_result_t result;
	isc_socket_t *socket;
	isc_socketevent_t *socketevent;
	omapi_connection_t *connection;
	unsigned int bytes_read;

	UNUSED(task);
	
	socket = event->ev_sender;
	connection = event->ev_arg;
	socketevent = (isc_socketevent_t *)event;
	bufferlist = socketevent->bufferlist;
	bytes_read = socketevent->n;
	result = socketevent->result;

	isc_event_free(&event);

	INSIST(socket == connection->socket && task == connection->task);

	/*
	 * Acquire the wait_lock before proceeding, to guarantee that
	 * connection_wait was entered in connection_send.
	 */
	if (connection->is_client) {
		LOCK(&connection->wait_lock);
		UNLOCK(&connection->wait_lock);
	}

	INSIST(connection->events_pending == 1);
	connection->events_pending--;

	/*
	 * Restore the input buffers to the connection object.
	 */
	for (buffer = ISC_LIST_HEAD(bufferlist);
	     buffer != NULL;
	     buffer = ISC_LIST_NEXT(buffer, link))
		ISC_LIST_APPEND(connection->input_buffers, buffer, link);

	if (result == ISC_R_SUCCESS) {
		connection->in_bytes += bytes_read;

		/*
		 * Signal protocol_signalhandler that the bytes it requested
		 * are present.  Though this is set up as a loop, it should
		 * only execute once because protocol_signalhandler will
		 * loop calling dispatch_messages as long as there is
		 * input available.
		 */
		while (connection->bytes_needed <= connection->in_bytes &&
		       connection->bytes_needed > 0) {
			result = object_signal((omapi_object_t *)connection,
					       "ready", connection);

			if (result != ISC_R_SUCCESS)
				break;
		}
	}

	if (result == ISC_R_SUCCESS) {
		if (connection->is_client)
			/*
			 * Attempt to unblock connection_send.  It might
			 * be the case that not all the bytes the client
			 * needs have yet been read, and so it would
			 * have had connection_require queue another recv,
			 * so events_pending will be 1 and connection_wait
			 * will not yet continue.
			 */
			SIGNAL(&connection->waiter);
	} else {
		/*
		 * Set the state to disconnecting and unblock connection_wait
		 * to free the connection.
		 */
		connection->result = result;
		end_connection(connection);
	}
}

/*
 * This is the function that is called when a send event is posted on
 * the socket as a result of isc_socket_send*.  It is called by both the
 * client and the server.
 */
static void
send_done(isc_task_t *task, isc_event_t *event) {
	isc_buffer_t *buffer;
	isc_bufferlist_t bufferlist;
	isc_socket_t *socket;
	isc_socketevent_t *socketevent;
	omapi_connection_t *connection;
	unsigned int sent_bytes;

	UNUSED(task);
	
	socket = event->ev_sender;
	connection = event->ev_arg;
	socketevent = (isc_socketevent_t *)event;
	sent_bytes = socketevent->n;
	bufferlist = socketevent->bufferlist;

	isc_event_free(&event);

	INSIST(socket == connection->socket && task == connection->task);

	/*
	 * Check the validity of the assumption that partial
	 * writes are not done.
	 */
	INSIST(sent_bytes == connection->out_bytes &&
	       sent_bytes == isc_bufferlist_usedcount(&bufferlist));

	/*
	 * Acquire the wait_lock before proceeding, to guarantee that
	 * connection_wait was entered in connection_send.
	 */
	if (connection->is_client) {
		LOCK(&connection->wait_lock);
		UNLOCK(&connection->wait_lock);
	}

	INSIST(connection->events_pending == 1);
	connection->events_pending--;

	/*
	 * Restore the head of bufferlist into the connection object, resetting
	 * it to have zero used space, and free the remaining buffers.
	 * This is done before the test of the socketevent's result so that
	 * end_connection can free the buffer, if it is called below.
	 */
	buffer = ISC_LIST_HEAD(bufferlist);
	ISC_LIST_APPEND(connection->output_buffers, buffer, link);
	isc_buffer_clear(buffer);

	while ((buffer = ISC_LIST_NEXT(buffer, link)) != NULL) {
		ISC_LIST_UNLINK(bufferlist, buffer, link);
		isc_buffer_free(&buffer);
	}

	if (connection->result == ISC_R_SUCCESS) {
		connection->out_bytes -= sent_bytes;

		/*
		 * Both the server and client are allowed to have only
		 * one event outstanding on a client at a time.  Each has
		 * already set up the number of bytes it expects to read
		 * next, but not queued the isc_socket_recv yet.  Calling
		 * connection_require for 0 bytes will enable the recv.
		 */
		connection_require(connection, 0);

	} else
		/*
		 * Set the state to disconnecting and unblock connection_wait
		 * to free the connection.
		 */
		end_connection(connection);
}

isc_result_t
connection_send(omapi_connection_t *connection) {
	isc_result_t result;

	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);

	REQUIRE(connection->state == omapi_connection_connected);
	REQUIRE(connection->out_bytes > 0);

	INSIST(!ISC_LIST_EMPTY(connection->output_buffers));
	/*
	 * This does not need to be locked, because the only thing that
	 * decrements events_pending is the socket event handlers, and the
	 * design is to have only one event outstanding at a time.
	 */
	INSIST(connection->events_pending == 0);
	connection->events_pending++;

	/*
	 * Block the send event from posting before the wait is established.
	 */
	if (connection->is_client)
		LOCK(&connection->wait_lock);
		
	isc_socket_sendv(connection->socket, &connection->output_buffers,
			 connection->task, send_done, connection);

	if (connection->is_client)
		/*
		 * Wait for the server's response to be processed.  If
		 * the result is not ISC_R_SUCCESS, connection_wait
		 * has freed the connection.
		 */
		result = connection_wait(connection);
	else
		result = ISC_R_SUCCESS;

	return (result);
}

/*
 * Make an outgoing connection to an OMAPI server.
 */
isc_result_t
connect_toserver(omapi_object_t *protocol, const char *server_name, int port) {
	isc_result_t result;
	isc_sockaddr_t sockaddr;
	isc_buffer_t *ibuffer = NULL, *obuffer = NULL;
	isc_task_t *task = NULL;
	omapi_connection_t *connection = NULL;

	result = get_address(server_name, port, &sockaddr);
	if (result != ISC_R_SUCCESS)
		return (result);

	/* XXXDCL Make cleanup better */
	/*
	 * Prepare the task that will wait for the connection to be made.
	 */
	result = isc_task_create(omapi_taskmgr, 0, &task);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = isc_buffer_allocate(omapi_mctx, &ibuffer, OMAPI_BUFFER_SIZE);
	if (result != ISC_R_SUCCESS)
		goto free_task;

	result = isc_buffer_allocate(omapi_mctx, &obuffer, OMAPI_BUFFER_SIZE);
	if (result != ISC_R_SUCCESS)
		goto free_ibuffer;

	/*
	 * Create a new connection object.
	 */
	result = omapi_object_create((omapi_object_t **)&connection,
				     omapi_type_connection,
				     sizeof(*connection));
	if (result != ISC_R_SUCCESS)
		goto free_obuffer;
		
	connection->is_client = ISC_TRUE;
	connection->waiting = ISC_FALSE;
	connection->state = omapi_connection_connecting;
	connection->task = task;

	ISC_LIST_INIT(connection->input_buffers);
	ISC_LIST_APPEND(connection->input_buffers, ibuffer, link);
	ISC_LIST_INIT(connection->output_buffers);
	ISC_LIST_APPEND(connection->output_buffers, obuffer, link);

	RUNTIME_CHECK(isc_mutex_init(&connection->wait_lock) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_condition_init(&connection->waiter) ==
		      ISC_R_SUCCESS);

	/*
	 * Tie the new connection object to the protocol object.
	 */
	OBJECT_REF(&protocol->outer, connection);
	OBJECT_REF(&connection->inner, protocol);

	/*
	 * Create a socket on which to communicate.
	 */
	result = isc_socket_create(omapi_socketmgr, isc_sockaddr_pf(&sockaddr),
				   isc_sockettype_tcp, &connection->socket);
	if (result == ISC_R_SUCCESS) {
		/*
		 * Lock before requesting the connection; this way
		 * connection_wait can safely block on connection->waiter
		 * before some connect error comes in and blows away the
		 * connection structure.
		 */
		LOCK(&connection->wait_lock);

		connection->events_pending = 1;
		result = isc_socket_connect(connection->socket, &sockaddr,
					    task, connect_done, connection);
	}

	if (result == ISC_R_SUCCESS)
		/*
		 * Wait for the connection event.  If result != ISC_R_SUCCESS,
		 * the connection was already abandoned via connect_done, so
		 * it does not need to be freed.
		 */
		result = connection_wait(connection);

	else
		/*
		 * There was an error calling isc_socket_create or
		 * isc_socket_connect.  Tear down the connection.
		 */
		end_connection(connection);

	return (result);

free_obuffer:
	isc_buffer_free(&obuffer);
free_ibuffer:
	isc_buffer_free(&ibuffer);
free_task:
	isc_task_destroy(&task);

	return (result);
}

/*
 * Put some bytes into the output buffer for a connection.
 */
isc_result_t
omapi_connection_putmem(omapi_object_t *c, unsigned char *src,
			unsigned int len)
{
	omapi_connection_t *connection;
	omapi_protocol_t *protocol;
	isc_buffer_t *buffer;
	isc_bufferlist_t bufferlist;
	isc_region_t region;
	isc_result_t result;
	unsigned int space_available;

	REQUIRE(c != NULL && c->type == omapi_type_connection);

	connection = (omapi_connection_t *)c;

	protocol = (omapi_protocol_t *)connection->inner;

	REQUIRE(protocol != NULL && protocol->type == omapi_type_protocol);

	/*
	 * XXX make the auth stuff a part of the connection object instead?
	 */
	if (protocol->dst_update) {
		region.base = src;
		region.length = len;
		result = dst_key_sign(DST_SIGMODE_UPDATE, protocol->key,
				      &protocol->dstctx, &region, NULL);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

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
					     OMAPI_BUFFER_SIZE);
		if (result != ISC_R_SUCCESS)
			return (result);

		space_available += OMAPI_BUFFER_SIZE;
		ISC_LIST_APPEND(bufferlist, buffer, link);
	}

	connection->out_bytes += len;

	/*
	 * Copy the data into the buffers, splitting across buffers
	 * as necessary.
	 */
	for (buffer = ISC_LIST_HEAD(bufferlist); len > 0;
	     buffer = ISC_LIST_NEXT(buffer, link)) {

		space_available = isc_buffer_availablelength(buffer);
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
void
connection_copyout(unsigned char *dst, omapi_connection_t *connection,
		   unsigned int size)
{
	isc_buffer_t *buffer;
	isc_region_t region;
	unsigned int copy_bytes;
	omapi_protocol_t *protocol;

	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);

	protocol = (omapi_protocol_t *)connection->inner;

	REQUIRE(protocol != NULL && protocol->type == omapi_type_protocol);

	INSIST(size <= connection->in_bytes);
	
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

		region.base = (unsigned char *)buffer->base + buffer->current;
		region.length = copy_bytes;

		/*
		 * When dst == NULL, this function is being used to skip
		 * over uninteresting input.
		 */
		if (dst != NULL)
			(void)memcpy(dst, region.base, copy_bytes);

		if (protocol->dst_update &&
		    protocol->verify_result == ISC_R_SUCCESS)
			protocol->verify_result =
				dst_key_verify(DST_SIGMODE_UPDATE,
					       protocol->key,
					       &protocol->dstctx,
					       &region, NULL);

		isc_buffer_forward(buffer, copy_bytes);

		size -= copy_bytes;
		connection->in_bytes -= copy_bytes;

		buffer = ISC_LIST_NEXT(buffer, link);
	}
}

/*
 * Disconnect a connection object from the remote end.   If force is true,
 * close the connection immediately.   Otherwise, shut down the receiving end
 * but allow any unsent data to be sent before actually closing the socket.
 *
 * This routine is called in the following situations:
 *
 *   The client wants to exit normally after all its transactions are
 *   processed.  Closing the connection causes an ISC_R_EOF event result
 *   to be given to the server's recv_done, which then causes the
 *   server's recv_done to close its side of the connection.
 *
 *   The client got some sort of error it could not handle gracefully, so
 *   it wants to just tear down the connection.  This can be caused either
 *   internally in the omapi library, or by the calling program.
 *
 *   The server is dropping the connection.  This is always asynchronous;
 *   the server will never block waiting for a connection to be completed
 *   because it never initiates a "normal" close of the connection.
 *   (Receipt of ISC_R_EOF is always treated as though it were an error,
 *   no matter what the client had been intending; it's the nature of
 *   the protocol.)
 */
void
omapi_connection_disconnect(omapi_object_t *generic, isc_boolean_t force) {
	omapi_connection_t *connection;

	REQUIRE(generic != NULL);

	connection = (omapi_connection_t *)generic;

	REQUIRE(connection->type == omapi_type_connection);

	/*
	 * Only the client can request an unforced disconnection.  The server's
	 * "normal" (non-error) disconnection will always happen when the
	 * client goes away, and the only time it calls this function
	 * is to forcibly blow away a connection while trying to shut down.
	 * XXXDCL ... hmm, can timeouts of the client on the server be handled?
	 */
	REQUIRE(force || connection->is_client);

	/*
	 * XXXDCL this has to be fixed up when isc_socket_shutdown is
	 * available, because then the shutdown can be done asynchronously.
	 * It is currently done synchronously.
	 */

	if (! force) {
		/*
		 * Client wants a clean disconnect.
		 *
		 * Since this *must* have been called from the client driving
		 * thread, and the client never gets control back until all
		 * outstanding events have been posted, and the connection must
		 * still be valid for it to have been passed here, the
		 * following *must* be true.
		 */
		INSIST(connection->state == omapi_connection_connected);
		INSIST(connection->events_pending == 0);

		/*
		 * Fall through.
		 */
	}

	end_connection(connection);
}

/*
 * The caller wants a specific amount of bytes to be read.  Queue up a
 * recv for the socket.
 */
isc_result_t
connection_require(omapi_connection_t *connection, unsigned int bytes) {
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);

	INSIST(connection->state == omapi_connection_connected);

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
		while (isc_buffer_availablelength(buffer) == 0 &&
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
						     OMAPI_BUFFER_SIZE);
			if (result != ISC_R_SUCCESS)
				return (result);

			ISC_LIST_APPEND(bufferlist, buffer, link);
		}
	}


	/*
	 * Queue the receive task.
	 */
	INSIST(connection->events_pending == 0);
	connection->events_pending++;

	/*
	 * The client should already be waiting.
	 */
	if (connection->is_client)
		INSIST(connection->waiting);

	/*
	 * XXXDCL The "minimum" arg has not been fully thought out.
	 */
	isc_socket_recvv(connection->socket, &connection->input_buffers,
			 connection->bytes_needed - connection->in_bytes,
			 connection->task, recv_done, connection);

	return (OMAPI_R_NOTYET);
}

void
connection_getuint32(omapi_connection_t *connection,
		     isc_uint32_t *value)
{
	isc_uint32_t inbuf;

	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);

	connection_copyout((unsigned char *)&inbuf, connection, sizeof(inbuf));

	*value = ntohl(inbuf);
}

void
connection_getuint16(omapi_connection_t *connection,
		     isc_uint16_t *value) {
	isc_uint16_t inbuf;

	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);

	connection_copyout((unsigned char *)&inbuf, connection, sizeof(inbuf));

	*value = ntohs(inbuf);
}

isc_result_t
omapi_connection_putuint32(omapi_object_t *c, isc_uint32_t value) {
	isc_uint32_t inbuf;

	inbuf = htonl(value);
	
	return (omapi_connection_putmem(c, (unsigned char *)&inbuf,
					sizeof(inbuf)));
}

isc_result_t
omapi_connection_putuint16(omapi_object_t *c, isc_uint32_t value) {
	isc_uint16_t inbuf;

	REQUIRE(value < 65536);

	inbuf = htons((isc_uint16_t)value);
	
	return (omapi_connection_putmem(c, (unsigned char *)&inbuf,
					sizeof(inbuf)));
}

isc_result_t
omapi_connection_putdata(omapi_object_t *c, omapi_data_t *data) {
	isc_result_t result;
	omapi_handle_t handle;

	REQUIRE(data != NULL &&
		(data->type == omapi_datatype_int    ||
		 data->type == omapi_datatype_data   ||
		 data->type == omapi_datatype_string ||
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
			return (omapi_connection_putmem(c,
							data->u.buffer.value,
							data->u.buffer.len));
		return (ISC_R_SUCCESS);

	      case omapi_datatype_object:
		if (data->u.object != NULL) {
			result = object_gethandle(&handle, data->u.object);
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
			 "unknown type in omapi_connection_putdata: "
			 "%d", data->type);
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

	return (omapi_connection_putmem(c, (unsigned char *)name, len));
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
		result = omapi_connection_putmem(c, (unsigned char *)string,
						 len);
	return (result);
}

isc_result_t
omapi_connection_puthandle(omapi_object_t *c, omapi_object_t *h) {
	isc_result_t result;
	omapi_handle_t handle;

	if (h != NULL) {
		result = object_gethandle(&handle, h);
		if (result != ISC_R_SUCCESS)
			return (result);
	} else
		handle = 0;	/* The null handle. */

	result = omapi_connection_putuint32(c, sizeof(handle));

	if (result == ISC_R_SUCCESS)
		result = omapi_connection_putuint32(c, handle);

	return (result);
}

static isc_result_t
connection_setvalue(omapi_object_t *connection, omapi_string_t *name,
		    omapi_data_t *value)
{
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);
	
	return (omapi_object_passsetvalue(connection, name, value));
}

static isc_result_t
connection_getvalue(omapi_object_t *connection, omapi_string_t *name,
		    omapi_value_t **value)
{
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);

	return (omapi_object_passgetvalue(connection, name, value));
}

static void
connection_destroy(omapi_object_t *handle) {
	omapi_connection_t *connection;

	REQUIRE(handle != NULL && handle->type == omapi_type_connection);

	connection = (omapi_connection_t *)handle;

	/*
	 * end_connection is the proper entry point for removing a
	 * connection, so it should have been called to do all the cleanup.
	 */

	/*
	 * XXXDCL somehow, not all memory is being destroyed with abnormal
	 * drops.  run the omapi_test program listener.  then run the
	 * omapi_test as a client, and break at the end of omapi_auth_use.
	 * when the debugger stops, exit the debugger.  only two blocks
	 * of memory are freed, but i suspect there are more than those
	 * associated with the connection.
	 */

	if (connection->state == omapi_connection_connected) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "Unexpected path to connection_destroy - "
				 "the connection object was dereferenced "
				 "without a previous disconnect");
		omapi_connection_disconnect(handle, OMAPI_FORCE_DISCONNECT);
	}
}

static isc_result_t
connection_signalhandler(omapi_object_t *connection, const char *name,
			 va_list ap)
{
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);
	
	return (omapi_object_passsignal(connection, name, ap));
}

/*
 * Write all the published values associated with the object through the
 * specified connection.
 */
static isc_result_t
connection_stuffvalues(omapi_object_t *connection, omapi_object_t *handle)
{
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);

	return (omapi_object_passstuffvalues(connection, handle));
}

isc_result_t
connection_init(void) {
	return (omapi_object_register(&omapi_type_connection, "connection",
				      connection_setvalue,
				      connection_getvalue,
				      connection_destroy,
				      connection_signalhandler,
				      connection_stuffvalues,
				      NULL, NULL, NULL));
}
