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
#include <stddef.h>		/* NULL */
#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/bufferlist.h>
#include <isc/error.h>
#include <isc/mem.h>

#include <omapi/private.h>

typedef struct omapi_listener_object {
	OMAPI_OBJECT_PREAMBLE;
	isc_task_t *task;
	isc_socket_t *socket;	/* Connection socket. */
	isc_sockaddr_t address;
} omapi_listener_t;

/*
 * Reader callback for a listener object.   Accept an incoming connection.
 */
static void
listener_accept(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	isc_buffer_t *ibuffer = NULL;
	isc_buffer_t *obuffer = NULL;
	isc_task_t *connection_task = NULL;
	isc_socket_t *socket;
	omapi_connection_t *connection = NULL;
	omapi_object_t *protocol = NULL;

	/*
	 * XXXDCL What are the meaningful things the listen/accept function
	 * can do if it fails to process an incoming connection because one
	 * of the functions it calls fails?
	 * The cleanup options are hurting my head.
	 */

	/*
	 * Immediately set up another listen task for the socket.
	 */
	isc_socket_accept(event->sender, task, listener_accept, event->arg);

	result = ((isc_socket_newconnev_t *)event)->result;
	socket = ((isc_socket_newconnev_t *)event)->newsocket;

	/*
	 * No more need for the event, once all the desired data has been
	 * used from it.
	 */
	isc_event_free(&event);

	/*
	 * Check for the validity of new connection event.
	 */
	if (result != ISC_R_SUCCESS)
		/*
		 * The result is probably ISC_R_UNEXPECTED; what can really be
		 * done about this other than just flunking out of here?
		 */
		return;

	/*
	 * The new connection is good to go.  Allocate the buffers for it and
	 * prepare its own task.
	 */
	if (isc_task_create(omapi_taskmgr, NULL, 0, &connection_task) !=
	    ISC_R_SUCCESS)
		goto free_task;

	ibuffer = NULL;
	result = isc_buffer_allocate(omapi_mctx, &ibuffer, OMAPI_BUFFER_SIZE,
				     ISC_BUFFERTYPE_BINARY);
	if (result != ISC_R_SUCCESS)
		goto free_ibuffer;

	obuffer = NULL;
	result = isc_buffer_allocate(omapi_mctx, &obuffer, OMAPI_BUFFER_SIZE,
				     ISC_BUFFERTYPE_BINARY);
	if (result != ISC_R_SUCCESS)
		goto free_obuffer;

	/*
	 * Create a new connection object.
	 */
	result = omapi_object_create((omapi_object_t **)&connection,
				  omapi_type_connection, sizeof(*connection));
	if (result != ISC_R_SUCCESS)
		goto free_obuffer;

	connection->task = connection_task;
	connection->state = omapi_connection_connected;
	connection->socket = socket;
	connection->is_client = ISC_FALSE;

	ISC_LIST_INIT(connection->input_buffers);
	ISC_LIST_APPEND(connection->input_buffers, ibuffer, link);
	ISC_LIST_INIT(connection->output_buffers);
	ISC_LIST_APPEND(connection->output_buffers, obuffer, link);

	RUNTIME_CHECK(isc_mutex_init(&connection->mutex) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_mutex_init(&connection->recv_lock) == ISC_R_SUCCESS);

	/*
	 * Create a new protocol object to oversee the handling of this
	 * connection.
	 */
	protocol = NULL;
	result = omapi_object_create(&protocol, omapi_type_protocol,
				     sizeof(omapi_protocol_t));
	if (result != ISC_R_SUCCESS)
		goto free_connection_object;

	/*
	 * Tie the protocol object bidirectionally to the connection
	 * object, with the connection as the outer object.
	 */
	OBJECT_REF(&protocol->outer, connection);
	OBJECT_REF(&connection->inner, protocol);

	/*
	 * Send the introductory message.
	 */
	result = send_intro(protocol, OMAPI_PROTOCOL_VERSION);

	if (result != ISC_R_SUCCESS)
		goto free_protocol_object;

	/*
	 * Lose one reference to the connection, so it'll be gc'd when it's
	 * reaped.  
	 * XXXDCL that's Ted's comment, but I don't see how it can be true.
	 * I don't see how it will "lose one reference" since
	 * omapi_object_dereference does not decrement refcnt.
	 */
	OBJECT_DEREF(&connection);
	return;

free_protocol_object:
	/*
	 * Remove the protocol object's reference to the connection
	 * object, so that the connection object will be destroyed.
	 * XXXDCL aigh, this is so confusing.  I don't think the
	 * right thing is being done.
	 */
	OBJECT_DEREF(&connection->inner);
	OBJECT_DEREF(&protocol);

	/* FALLTHROUGH */
free_connection_object:
	/*
	 * Destroy the connection.  This will free everything created
	 * in this function but the event, which was already freed.
	 */
	OBJECT_DEREF(&connection);
	return;

	/*
	 * Free resources that were being created for the connection object.
	 */
free_obuffer:
	isc_buffer_free(&obuffer);
free_ibuffer:
	isc_buffer_free(&ibuffer);
free_task:
	isc_task_destroy(&connection_task);
}

isc_result_t
omapi_listener_listen(omapi_object_t *caller, int port, int max) {
	isc_result_t result;
	isc_task_t *task;
	omapi_listener_t *listener;
	struct in_addr inaddr;

	task = NULL;
	result = isc_task_create(omapi_taskmgr, NULL, 0, &task);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Create the listener object.
	 */
	listener = NULL;
	result = omapi_object_create((omapi_object_t **)&listener,
				     omapi_type_listener, sizeof(*listener));

	if (result != ISC_R_SUCCESS) {
		isc_task_destroy(&task);
		return (result);
	}

	listener->task = task;

	/*
	 * Tie the listener object to the calling object.
	 */
	OBJECT_REF(&caller->outer, listener);
	OBJECT_REF(&listener->inner, caller);

	/*
	 * Create a socket on which to listen.
	 */
	listener->socket = NULL;
	result = isc_socket_create(omapi_socketmgr, PF_INET,
				   isc_sockettype_tcp, &listener->socket);

	if (result == ISC_R_SUCCESS) {
		/*
		 * Set up the addressses on which to listen and bind to it.
		 */
		inaddr.s_addr = INADDR_ANY;
		isc_sockaddr_fromin(&listener->address, &inaddr, port);

		result = isc_socket_bind(listener->socket, &listener->address);
	}

	if (result == ISC_R_SUCCESS)
		/*
		 * Now tell the kernel to listen for connections.
		 */
		result = isc_socket_listen(listener->socket, max);

	if (result == ISC_R_SUCCESS)
		/*
		 * Queue up the first accept event.  The listener object
		 * will be passed to listener_accept() when it is called,
		 * though currently nothing is done with it.
		 */
		result = isc_socket_accept(listener->socket, task,
					   listener_accept, listener);

	if (result != ISC_R_SUCCESS)
		/*
		 * The listener has a refcnt of 2, so this does not really
		 * free it. XXXDCL
		 */
		OBJECT_DEREF(&listener);

	return (result);
}

static isc_result_t
listener_setvalue(omapi_object_t *listener, omapi_string_t *name,
		  omapi_data_t *value)
{
	/*
	 * Nothing meaningful can be set in a listener object; just
	 * continue the call through the object chain.
	 */
	REQUIRE(listener != NULL && listener->type == omapi_type_listener);

	return (omapi_object_passsetvalue(listener, name, value));
}

static isc_result_t
listener_getvalue(omapi_object_t *listener, omapi_string_t *name,
		  omapi_value_t **value)
{
	/*
	 * Nothing meaningful can be fetched from a listener object; just
	 * continue the call through the object chain.
	 */
	REQUIRE(listener != NULL && listener->type == omapi_type_listener);
	
	return (omapi_object_passgetvalue(listener, name, value));
}

static void
listener_destroy(omapi_object_t *object) {
	omapi_listener_t *listener;

	REQUIRE(object != NULL && object->type == omapi_type_listener);

	listener = (omapi_listener_t *)object;

	isc_task_destroy(&listener->task);

	if (listener->socket != NULL) {
#if 0 /*XXXDCL*/
		isc_socket_cancel(listener->socket, NULL, ISC_SOCKCANCEL_ALL);
		isc_socket_shutdown(listener->socket, ISC_SOCKSHUT_ALL);
#else
		isc_task_shutdown(listener->task);
#endif
		listener->socket = NULL;
	}
}

static isc_result_t
listener_signalhandler(omapi_object_t *listener, const char *name, va_list ap)
{
	REQUIRE(listener != NULL && listener->type == omapi_type_listener);
	
	/*
	 * This function is reached when listener_accept does an
	 * object_signal of "connect" on the listener object.  Nothing
	 * need be done here, but the object that originally requested
	 * the listen needs to signalled that a connection was made.
	 */
	return (omapi_object_passsignal(listener, name, ap));
}

/*
 * Write all the published values associated with the object through the
 * specified connection.
 */
static isc_result_t
listener_stuffvalues(omapi_object_t *connection, omapi_object_t *listener)
{
	REQUIRE(listener != NULL && listener->type == omapi_type_listener);

	return (omapi_object_passstuffvalues(connection, listener));
}

isc_result_t
listener_init(void) {
	return (omapi_object_register(&omapi_type_listener, "listener",
				      listener_setvalue,
				      listener_getvalue,
				      listener_destroy,
				      listener_signalhandler,
				      listener_stuffvalues,
				      NULL, NULL, NULL));
}
