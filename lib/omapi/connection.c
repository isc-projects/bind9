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

/* $Id: connection.c,v 1.10 2000/01/17 20:06:31 tale Exp $ */

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

/*
 * Called when there are no more events are pending on the socket.
 * It can be detached and data for the connection object freed.
 */
static void
free_connection(omapi_connection_object_t *connection) {
	isc_buffer_t *buffer;

	/*
	 * The mutex is locked when this routine is called.  Unlock
	 * it so that the isc_condition_signal below will allow
	 * omapi_connection_wait to be able to acquire the lock.
	 */
	RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex) == ISC_R_SUCCESS);

	/*
	 * This one is locked too, unlock it so it can be destroyed.
	 */
	RUNTIME_CHECK(isc_mutex_unlock(&connection->recv_lock) ==
		      ISC_R_SUCCESS);

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

	RUNTIME_CHECK(isc_mutex_destroy(&connection->mutex) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_mutex_destroy(&connection->recv_lock) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_condition_destroy(&connection->waiter) ==
		      ISC_R_SUCCESS);

	/*
	 * If whatever created us registered a signal handler, send it
	 * a disconnect signal.
	 */
	omapi_signal((omapi_object_t *)connection, "disconnect", connection);

#if 0
	/*
	 * Free the inner generic object via the protocol object.
	 * XXXDCL wildass stab in the dark
	 */
	OBJECT_DEREF(&connection->inner->inner);
#endif

	

	/*
	 * Finally, free the object itself.
	 */
	OBJECT_DEREF(&connection);
}

static void
end_connection(omapi_connection_object_t *connection, isc_event_t *event,
	       isc_result_t result)
{
	if (event != NULL)
		isc_event_free(&event);

	/*
	 * XXXDCL would be nice to send the result as an 
	 * omapi_signal(object, "status", result) but i don't
	 * think this can be done with the connection as the object.
	 */

	/*
	 * Don't proceed until recv_done() has finished whatever
	 * it was doing that decremented events_pending to 0.
	 */
	RUNTIME_CHECK(isc_mutex_lock(&connection->recv_lock) == ISC_R_SUCCESS);

	/*
	 * Lock the connection's mutex to examine connection->events_pending.
	 */
	RUNTIME_CHECK(isc_mutex_lock(&connection->mutex) == ISC_R_SUCCESS);

	fprintf(stderr, "END_CONNECTION, %d events_pending\n",
		connection->events_pending);

	if (connection->events_pending == 0) {
		if (connection->waiting) {
			/*
			 * This must have been an error, since
			 * omapi_connection_wait can't be called after
			 * omapi_connection_disconnect is called for
			 * a normal close.
			 *
			 * Signal omapi_connection_wait and have it do the
			 * cleanup.  free_connection can't be called
			 * directly here because it can't be sure
			 * that the mutex has been finished being touched
			 * by omapi_connection_wait even if it
			 * free_connection signals it.  (Nasty little
			 * race condition with the lock.)
			 *
			 * Make sure that when it is awakened, it exits its
			 * wait loop by setting messages_expected to 0.
			 */
			connection->state = omapi_connection_closed;
			connection->messages_expected = 0;

			RUNTIME_CHECK(isc_condition_signal(&connection->waiter)
				      == ISC_R_SUCCESS);
		} else
			free_connection(connection);

		return;
	}

	RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_mutex_unlock(&connection->recv_lock) ==
		      ISC_R_SUCCESS);

	/*
	 * There are events pending.  Cancel them, and each will generate
	 * a call with ISC_R_CANCELED to this routine until finally
	 * events_pending is 0 and the connection is freed.  The
	 * only time ISC_R_CANCELED should be generated is after this
	 * function already called isc_socket_cancel, because it is
	 * the only place in the omapi library that isc_socket_cancel is used.
	 */

	if (result != ISC_R_CANCELED)
		isc_socket_cancel(connection->socket, NULL,
				  ISC_SOCKCANCEL_ALL);
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

	fprintf(stderr, "CONNECT_DONE\n");

	INSIST(socket == connection->socket && task == connection->task);

	RUNTIME_CHECK(isc_mutex_lock(&connection->mutex) == ISC_R_SUCCESS);
	/*
	 * XXXDCL I may have made an unwarranted assumption about
	 * events_pending becoming 0 on the client when disconnecting
	 * only in recv_done.  I'm concerned that there might be some
	 * sort of logic window, however small, where that isn't true.
	 */
	INSIST(connection->events_pending > 0);
	if (--connection->events_pending == 0 && connection->is_client &&
	    connection->state == omapi_connection_disconnecting)
		FATAL_ERROR(__FILE__, __LINE__,
			    "events_pending == 0 in connect_done while "
			    "disconnecting, this should not happen!");
	RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex) == ISC_R_SUCCESS);

	/*
	 * XXXDCL For some reason, a "connection refused" error is not
	 * being indicated here when it would be expected.  I wonder
	 * how that error is indicated.
	 */

	if (connectevent->result != ISC_R_SUCCESS)
		goto abandon;

	result = isc_socket_getpeername(connection->socket,
					&connection->remote_addr);
	if (result != ISC_R_SUCCESS)
		goto abandon;

	result = isc_socket_getsockname(connection->socket,
					&connection->local_addr);
	if (result != ISC_R_SUCCESS)
		goto abandon;
	
	connection->state = omapi_connection_connected;

	isc_event_free(&event);

	return;

abandon:
	end_connection(connection, event, connectevent->result);
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

	fprintf(stderr, "RECV_DONE, %d bytes\n", socketevent->n);

	INSIST(socket == connection->socket && task == connection->task);

	/*
	 * XXXDCL This recv_lock is a dirty, ugly, nasty hack and I
	 * am ashamed for it.  I have struggled for days with how to
	 * prevent the driving progam's call of omapi_connection_disconnect
	 * from conflicting with the execution of the task thread
	 * (this one, where recv_done is being called).
	 *
	 * Basically, most of the real work happens in the task thread,
	 * all kicked off by signalling "ready" a few lines below.  If
	 * this recv_done() is processing the last expected bytes of a message,
	 * then it will wake up the driving program, and the driving program
	 * can go ahead and issue a disconnect.  Since there are neither
	 * events_pending nor messages_expected, end_connecton goes ahead
	 * and frees the connection.  But that can happen before this
	 * very function can go finish up what it is doing with the
	 * connection structure, which is clearly a bad thing.
	 *
	 * The regular mutex in the connection (the one named "mutex") is
	 * being used throughout the code in a much more localized fashion,
	 * and while it might be possible to more broadly scope it so that
	 * it essentially does the job that recv_lock is doing, I honestly
	 * have not yet fully thought that out and I have already burned
	 * so much time trying other approaches before I struck on this
	 * recv_lock idea.  My gut reaction is I don't like how long
	 * a lock on 'mutex' would be held, and I am not entirely sure
	 * that there aren't deadlock situations.  I have to think about it
	 * ... LATER.
	 */
	RUNTIME_CHECK(isc_mutex_lock(&connection->recv_lock) == ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_mutex_lock(&connection->mutex) == ISC_R_SUCCESS);
	INSIST(connection->events_pending > 0);
	connection->events_pending--;
	RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex) == ISC_R_SUCCESS);

	/*
	 * Restore the input buffers to the connection object.
	 */
	for (buffer = ISC_LIST_HEAD(socketevent->bufferlist);
	     buffer != NULL;
	     buffer = ISC_LIST_NEXT(buffer, link))
		ISC_LIST_APPEND(connection->input_buffers, buffer, link);

	if (socketevent->result != ISC_R_SUCCESS)
		goto abandon;

	connection->in_bytes += socketevent->n;

	original_bytes_needed = connection->bytes_needed;

	/*
	 * Signal omapi_protocol_signal_handler that the bytes it requested
	 * are present.
	 *
	 * XXXDCL it will then isc_condition_signal the driving thread,
	 * which is free to go ahead and call omapi_connection_disconnect.
	 * since there are possibly no more events pending and no more messages
	 * expected at that point, the driving thread may end up freeing the
	 * connection before this routine is done manipulating it.
	 * what a big, ugly, pain in the rump.
	 */
	while (connection->bytes_needed <= connection->in_bytes &&
	       connection->bytes_needed > 0)

		if (omapi_signal((omapi_object_t *)connection, "ready",
				 connection) != ISC_R_SUCCESS)
			goto abandon;


	/*
	 * Queue up another recv request.  If the bufferlist is empty,
	 * then, something under omapi_signal already called
	 * omapi_connection_require and queued the recv (which is
	 * what emptied the bufferlist).
	 */
	if (! ISC_LIST_EMPTY(connection->input_buffers))
		omapi_connection_require((omapi_object_t *)connection, 0);

	/*
	 * See if that was the last event the client was expecting, so
	 * that the connection can be freed.  This test needs to be
	 * done, because it is possible omapi_connection_disconnect has
	 * already been called, before the signal handler managed to
	 * decrement messages_expected.  That means that _disconnect
	 * set the state to disconnecting but didn't call the
	 * end_connection routine.  If this was the last event,
	 * no more events are going to come in and call recv_done again,
	 * so this is the only time that it can be identified that
	 * the conditions for finally freeing the connection are all true.
	 *
	 * XXXDCL I don't *think* this has to be done in the send_done or
	 * connect_done handlers, because a normal termination (one defined as
	 * "omapi_connection_disconnect called by the client with 'force' as
	 * false") will only happen after the last of the expected data is
	 * received.
	 */
	if (connection->is_client) {
		RUNTIME_CHECK(isc_mutex_lock(&connection->mutex) ==
			      ISC_R_SUCCESS);
		if (connection->events_pending == 0 &&
		    connection->state == omapi_connection_disconnecting) {
			INSIST(connection->messages_expected == 1);

			/*
			 * omapi_connection_disconnect was called, but
			 * end_connection has not been.  Call it now.
			 */
			RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex)
				      == ISC_R_SUCCESS);
			RUNTIME_CHECK(isc_mutex_unlock(&connection->recv_lock)
				      == ISC_R_SUCCESS);

			end_connection(connection, event, ISC_R_SUCCESS);
			return;
		}
		RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex) ==
			      ISC_R_SUCCESS);
	}
	RUNTIME_CHECK(isc_mutex_unlock(&connection->recv_lock) ==
		      ISC_R_SUCCESS);

	isc_event_free(&event);
	return;

abandon:
	RUNTIME_CHECK(isc_mutex_unlock(&connection->recv_lock) ==
		      ISC_R_SUCCESS);
	end_connection(connection, event, socketevent->result);
	return;
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

	fprintf(stderr, "SEND_DONE, %d bytes\n", socketevent->n);

	INSIST(socket == connection->socket && task == connection->task);

	/*
	 * XXXDCL I am assuming that partial writes are not done.  I hope this
	 * does not prove to be incorrect. But the assumption can be tested ...
	 */
	INSIST(socketevent->n == connection->out_bytes &&
	       socketevent->n ==
	       isc_bufferlist_usedcount(&socketevent->bufferlist));

	RUNTIME_CHECK(isc_mutex_lock(&connection->mutex) == ISC_R_SUCCESS);
	/*
	 * XXXDCL I may have made an unwarranted assumption about
	 * events_pending becoming 0 on the client when disconnecting
	 * only in recv_done.  I'm concerned that there might be some
	 * sort of logic window, however small, where that isn't true.
	 */
	INSIST(connection->events_pending > 0);
	if (--connection->events_pending == 0 && connection->is_client &&
	    connection->state == omapi_connection_disconnecting)
		FATAL_ERROR(__FILE__, __LINE__,
			    "events_pending == 0 in send_done while "
			    "disconnecting, this should not happen!");
	RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex) == ISC_R_SUCCESS);

	/*
	 * Restore the head of bufferlist into the connection object, resetting
	 * it to have zero used space, and free the remaining buffers.
	 * This is done before the test of the socketevent's result so that
	 * end_connection() can free the buffer, if it is called below.
	 */
	buffer = ISC_LIST_HEAD(socketevent->bufferlist);
	ISC_LIST_APPEND(connection->output_buffers, buffer, link);
	isc_buffer_clear(buffer);

	while ((buffer = ISC_LIST_NEXT(buffer, link)) != NULL) {
		ISC_LIST_UNLINK(socketevent->bufferlist, buffer, link);
		isc_buffer_free(&buffer);
	}

	if (socketevent->result != ISC_R_SUCCESS)
		goto abandon;

	connection->out_bytes -= socketevent->n;

	isc_event_free(&event);
	return;

abandon:
	end_connection(connection, event, socketevent->result);
	return;
}

void
connection_send(omapi_connection_object_t *connection) {
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);

	REQUIRE(connection->state == omapi_connection_connected);

	if (connection->out_bytes > 0) {
		INSIST(!ISC_LIST_EMPTY(connection->output_buffers));

		RUNTIME_CHECK(isc_mutex_lock(&connection->mutex) ==
			      ISC_R_SUCCESS);
		connection->events_pending++;
		RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex) ==
			      ISC_R_SUCCESS);

		isc_socket_sendv(connection->socket,
				 &connection->output_buffers, connection->task,
				 send_done, connection);
	}
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
	if (result != ISC_R_SUCCESS)
		goto free_task;

	result = isc_buffer_allocate(omapi_mctx, &obuffer, OMAPI_BUFFER_SIZE,
				     ISC_BUFFERTYPE_BINARY);
	if (result != ISC_R_SUCCESS)
		goto free_ibuffer;

	/*
	 * Create a new connection object.
	 */
	result = omapi_object_create((omapi_object_t **)&connection,
				  omapi_type_connection, sizeof(*connection));
	if (result != ISC_R_SUCCESS)
		goto free_obuffer;
		
	connection->is_client = ISC_TRUE;
	connection->waiting = ISC_FALSE;

	connection->task = task;

	ISC_LIST_INIT(connection->input_buffers);
	ISC_LIST_APPEND(connection->input_buffers, ibuffer, link);
	ISC_LIST_INIT(connection->output_buffers);
	ISC_LIST_APPEND(connection->output_buffers, obuffer, link);

	RUNTIME_CHECK(isc_mutex_init(&connection->mutex) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_mutex_init(&connection->recv_lock) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_condition_init(&connection->waiter) ==
		      ISC_R_SUCCESS);

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
	OBJECT_REF(&protocol->outer, connection);
	OBJECT_REF(&connection->inner, protocol);

	/*
	 * Create a socket on which to communicate.
	 */
	result = isc_socket_create(omapi_socketmgr, isc_sockaddr_pf(&sockaddr),
				   isc_sockettype_tcp, &connection->socket);
	if (result != ISC_R_SUCCESS)
		goto free_object;

#if 0
	/*
	 * Set the SO_REUSEADDR flag (this should not fail).
	 * XXXDCL is this needed?  isc_socket_* does not support it.
	 */
	flag = 1;
	if (setsockopt(connection->socket, SOL_SOCKET, SO_REUSEADDR,
		       (char *)&flag, sizeof(flag)) < 0) {
		OBJECT_DEREF(&connection);
		return (ISC_R_UNEXPECTED);
	}
#endif

	RUNTIME_CHECK(isc_mutex_lock(&connection->mutex) == ISC_R_SUCCESS);
	connection->events_pending++;
	RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex) == ISC_R_SUCCESS);

	result = isc_socket_connect(connection->socket, &sockaddr, task,
				    connect_done, connection);
	if (result != ISC_R_SUCCESS) {
		end_connection(connection, NULL, result);
		return (result);
	}

	return (ISC_R_SUCCESS);

free_object:
	OBJECT_DEREF(&connection);
	OBJECT_DEREF(&protocol->outer);
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
 *
 * The client might or might not want to block on the disconnection.
 * Currently the way to accomplish this is to call omapi_connection_wait
 * before calling this function.  A more complex method could be developed,
 * but after spending (too much) time thinking about it, it hardly seems to
 * be worth the effort when it is easy to just insist that the
 * omapi_connection_wait be done.
 *
 * Also, if the error is being thrown from the library, the client
 * might *already* be waiting on (or intending to wait on) whatever messages
 * it has already sent, so it needs to be awakened.  That will be handled
 * by free_connection after all of the cancelled events are processed.
 */
void
omapi_connection_disconnect(omapi_object_t *generic, isc_boolean_t force) {
	omapi_connection_object_t *connection;

	REQUIRE(generic != NULL);

	connection = (omapi_connection_object_t *)generic;

	REQUIRE(connection->type == omapi_type_connection);

	/*
	 * Only the client can request an unforced disconnection.  The server's
	 * disconnection will always happen when the client goes away.
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
		 * Increment the count of messages expected.  Even though
		 * no message is really expected, this will keep
		 * omapi_connection_wait from exiting until free_connection()
		 * signals it.
		 */
		RUNTIME_CHECK(isc_mutex_lock(&connection->mutex) ==
			      ISC_R_SUCCESS);
		INSIST(connection->state == omapi_connection_connected);

		connection->messages_expected++;

		/*
		 * If there are other messages expected for the socket,
		 * then set the state to disconnecting.  Based on that
		 * flag, when recv_done gets the last output from the server,
		 * it will then end the connection.   The reason the state 
		 * is set to disconnecting only here and not while falling
		 * through to end_connection below is that it is the
		 * flag which says whether end_connection has been called or
		 * not.
		 */
		if (connection->messages_expected > 1) {
			connection->state = omapi_connection_disconnecting;
			RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex) ==
				      ISC_R_SUCCESS);
			return;
		}

		/*
		 * ... else fall through.
		 */
		INSIST(connection->events_pending == 0);
		RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex) ==
			      ISC_R_SUCCESS);
	}
			      
	/*
	 * XXXDCL
	 * This might be improved if the 'force' argument to this function
	 * were instead an isc_reault_t argument.  Then omapi_signal could send
	 * a "status" back up to a signal handler that could set a waitresult.
	 */
	end_connection(connection, NULL,
		       force ? ISC_R_UNEXPECTED : ISC_R_SUCCESS);
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

	INSIST(connection->state == omapi_connection_connected ||
	       connection->state == omapi_connection_disconnecting);

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

	RUNTIME_CHECK(isc_mutex_lock(&connection->mutex) == ISC_R_SUCCESS);

	/*
	 * Queue the receive task.
	 * XXXDCL The "minimum" arg has not been fully thought out.
	 */
	connection->events_pending++;
	isc_socket_recvv(connection->socket, &connection->input_buffers,
			 connection->bytes_needed - connection->in_bytes,
			 connection->task, recv_done, connection);

	RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex) ==
		      ISC_R_SUCCESS);

	return (OMAPI_R_NOTYET);
}

/*
 * This function is meant to pause the client until it has received
 * a message from the server, either the introductory message or a response
 * to a message it has sent.  Because the socket library is multithreaded,
 * those events can happen before omapi_connection_wait is ever called.
 * So a counter needs to be set for every expected message, and this 
 * function can only return when that counter is 0.
 *
 * XXXDCL ICK.  There is a problem.  What if an error that causes disconnection
 * is happens before it is detected by the driving program, before this
 * function has ever been called, but after all of the connection data
 * has been freed.
 *
 * Actually, that seems to be a problem throughout this WHOLE LIBRARY.  It
 * really needs to be handled somehow.
 */
isc_result_t
omapi_connection_wait(omapi_object_t *object,
		      omapi_object_t *connection_handle,
		      isc_time_t *timeout)
{
	/*
	 * XXXDCL 'object' is not really used.
	 */
	omapi_connection_object_t *connection;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(object != NULL && connection_handle != NULL);
	REQUIRE(connection_handle->type == omapi_type_connection);

	connection = (omapi_connection_object_t *)connection_handle;
	/*
	 * This routine is not valid for server connections.
	 */
	INSIST(connection->is_client);

	RUNTIME_CHECK(isc_mutex_lock(&connection->mutex) == ISC_R_SUCCESS);
	INSIST(connection->state == omapi_connection_connected);
	
	connection->waiting = ISC_TRUE;

	while (connection->messages_expected > 0 && result == ISC_R_SUCCESS)

		if (timeout == NULL)
			result = isc_condition_wait(&connection->waiter,
						    &connection->mutex);
		else
			result = isc_condition_waituntil(&connection->waiter,
							 &connection->mutex,
							 timeout);

	RUNTIME_CHECK(result == ISC_R_SUCCESS || result == ISC_R_TIMEDOUT);

	connection->waiting = ISC_FALSE;

	if (connection->state == omapi_connection_closed)
		/*
		 * An error occurred and end_connection needs to have
		 * free_connection called now that we're done looking
		 * at connection->messages_expected.
		 *
		 * XXXDCL something better to do with the result value?
		 */
		free_connection(connection);
	else
		RUNTIME_CHECK(isc_mutex_unlock(&connection->mutex) ==
			      ISC_R_SUCCESS);

	return (result);
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

static isc_result_t
connection_setvalue(omapi_object_t *connection, omapi_object_t *id,
		    omapi_data_string_t *name, omapi_typed_data_t *value)
{
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);
	
	PASS_SETVALUE(connection);
}

static isc_result_t
connection_getvalue(omapi_object_t *connection, omapi_object_t *id,
		    omapi_data_string_t *name, omapi_value_t **value)
{
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);

	PASS_GETVALUE(connection);
}

static void
connection_destroy(omapi_object_t *handle) {
	omapi_connection_object_t *connection;

	REQUIRE(handle != NULL && handle->type == omapi_type_connection);

	connection = (omapi_connection_object_t *)handle;

	if (connection->state == omapi_connection_connected)
		omapi_connection_disconnect(handle, OMAPI_FORCE_DISCONNECT);
}

static isc_result_t
connection_signalhandler(omapi_object_t *connection, const char *name,
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
static isc_result_t
connection_stuffvalues(omapi_object_t *connection, omapi_object_t *id,
		       omapi_object_t *handle)
{
	REQUIRE(connection != NULL &&
		connection->type == omapi_type_connection);

	PASS_STUFFVALUES(handle);
}

isc_result_t
omapi_connection_init(void) {
	return (omapi_object_register(&omapi_type_connection,
					   "connection",
					   connection_setvalue,
					   connection_getvalue,
					   connection_destroy,
					   connection_signalhandler,
					   connection_stuffvalues,
					   NULL, NULL, NULL));
}
