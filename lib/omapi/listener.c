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

/*
 * Subroutines that support the generic listener object.
 */

#include <config.h>

#include <stdlib.h>		/* NULL and abort() */

#include <isc/buffer.h>
#include <isc/bufferlist.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/util.h>

#include <omapi/private.h>

typedef struct omapi_listener_object {
	OMAPI_OBJECT_PREAMBLE;
	isc_mutex_t mutex;
	isc_task_t *task;
	isc_socket_t *socket;	/* Listening socket. */
	dns_acl_t *acl;
	/*
	 * Locked by mutex.
	 */
	isc_boolean_t listening;
	ISC_LIST(omapi_connection_t) connections;
} omapi_listener_t;

static void
free_listener(omapi_listener_t *listener) {
	/*
	 * Break the link between the listener object and its parent
	 * (usually a generic object); this is done so the server's
	 * reference to its managing object does not prevent the
	 * listener object from being destroyed.
	 */
	OBJECT_DEREF(&listener->inner->outer);
	OBJECT_DEREF(&listener->inner);

	/*
	 * The listener object can now be freed.
	 */
	OBJECT_DEREF(&listener);
}

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
	isc_sockaddr_t sockaddr;
	isc_netaddr_t netaddr;
	omapi_connection_t *connection = NULL;
	omapi_object_t *protocol = NULL;
	omapi_listener_t *listener;
	int match;

	/*
	 * XXXDCL audit error handling
	 */

	result = ((isc_socket_newconnev_t *)event)->result;
	socket = ((isc_socket_newconnev_t *)event)->newsocket;
	listener = (omapi_listener_t *)event->ev_arg;

	/*
	 * No more need for the event, once all the desired data has been
	 * used from it.
	 */
	isc_event_free(&event);

	if (result == ISC_R_CANCELED) {
		/*
		 * omapi_listener_shutdown was called.
		 */
		LOCK(&listener->mutex);

		listener->listening = ISC_FALSE;

		if (ISC_LIST_HEAD(listener->connections) == NULL) {
			UNLOCK(&listener->mutex);
			free_listener(listener);

		} else {
			/*
			 * All connections this listener was responsible for
			 * must be removed.
			 *
			 * XXXDCL
			 * Since it is possible that this shutdown was
			 * triggered by one of the clients, it would be nice
			 * to give it a little time to exit, as well as allow
			 * any other connections to finish up cleanly.
			 * Unfortunately, since this could be called in the
			 * task/event thread of a program (as it is in named),
			 * no other events can be delivered while this routine
			 * blocks, so a loop to use isc_condition_waituntil
			 * until all of the connections are gone is pointless.
			 */
			for (connection = ISC_LIST_HEAD(listener->connections);
			     connection != NULL;
			     connection = ISC_LIST_NEXT(connection, link))
				omapi_connection_disconnect((omapi_object_t *)
						       connection,
						       OMAPI_FORCE_DISCONNECT);
			UNLOCK(&listener->mutex);
		}

		return;
	}

	/*
	 * Set up another accept task for the socket.
	 */
	isc_socket_accept(listener->socket, task, listener_accept, listener);

	/*
	 * Check for the validity of new connection event.
	 * If the result is not ISC_R_SUCCESS, what can really
	 * be done about it other than just flunking out of here?
	 */
	if (result != ISC_R_SUCCESS)
		return;
	
	/*
	 * Is the connection from a valid host?
	 */
	result = isc_socket_getpeername(socket, &sockaddr);

	if (result == ISC_R_SUCCESS) {
		isc_netaddr_fromsockaddr(&netaddr, &sockaddr);

		result = dns_acl_match(&netaddr, NULL, listener->acl,
				       NULL, &match, NULL);
	}

	if (result != ISC_R_SUCCESS || match <= 0) {
		/*
		 * Permission denied.  Close the connection.
		 * XXXDCL isc_log_write an error.
		 */
		isc_socket_detach(&socket);

		return;
	}

	/*
	 * The new connection is good to go.  Allocate the buffers for it and
	 * prepare its own task.
	 */
	if (isc_task_create(omapi_taskmgr, 0, &connection_task) !=
	    ISC_R_SUCCESS)
		goto free_task;

	ibuffer = NULL;
	result = isc_buffer_allocate(omapi_mctx, &ibuffer, OMAPI_BUFFER_SIZE);
	if (result != ISC_R_SUCCESS)
		goto free_ibuffer;

	obuffer = NULL;
	result = isc_buffer_allocate(omapi_mctx, &obuffer, OMAPI_BUFFER_SIZE);
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
	 * Lose the external reference to the protocol object so both the
	 * connection object and protocol object will be freed when the
	 * connection ends.
	 */
	OBJECT_DEREF(&protocol);

	/*
	 * Add the connection to the list of connections known by the
	 * listener.  This is an added reference to the connection
	 * object, but since there's no easy way to use omapi_object_reference
	 * with the ISC_LIST macros, that reference is just not counted.
	 */
	LOCK(&listener->mutex);
	ISC_LIST_APPEND(listener->connections, connection, link);
	UNLOCK(&listener->mutex);

	/*
	 * Remember the listener that accepted the connection, so it
	 * can be told when the connection goes away.
	 */
	OBJECT_REF(&connection->listener, listener);

	/*
	 * Send the introductory message.  The return value does not
	 * matter; if send_intro failed, it already destroyed the connection.
	 */
	(void)send_intro(connection->inner, OMAPI_PROTOCOL_VERSION);

	return;

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
omapi_listener_listen(omapi_object_t *caller, isc_sockaddr_t *addr,
		      dns_acl_t *acl, int max,
		      isc_taskaction_t destroy_action, void *destroy_arg)
{
	isc_result_t result;
	isc_task_t *task;
	omapi_listener_t *listener;

	REQUIRE(caller != NULL);
	REQUIRE(addr != NULL && isc_sockaddr_getport(addr) != 0);

	task = NULL;
	result = isc_task_create(omapi_taskmgr, 0, &task);
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

	RUNTIME_CHECK(isc_mutex_init(&listener->mutex) == ISC_R_SUCCESS);
	ISC_LIST_INIT(listener->connections);

	/*
	 * Create a socket on which to listen.
	 */
	listener->socket = NULL;
	result = isc_socket_create(omapi_socketmgr, PF_INET,
				   isc_sockettype_tcp, &listener->socket);

	if (result == ISC_R_SUCCESS)
		result = isc_socket_bind(listener->socket, addr);

	if (result == ISC_R_SUCCESS)
		/*
		 * Now tell the kernel to listen for connections.
		 */
		result = isc_socket_listen(listener->socket, max);

	if (result == ISC_R_SUCCESS) {
		/*
		 * Queue up the first accept event.  The listener object
		 * will be passed to listener_accept() when it is called.
		 */
		dns_acl_attach(acl, &listener->acl);
		listener->listening = ISC_TRUE;
		result = isc_socket_accept(listener->socket, task,
					   listener_accept, listener);
	}

	if (result == ISC_R_SUCCESS) {
		/*
		 * Tie the listener object to the calling object.
		 */
		OBJECT_REF(&caller->outer, listener);
		OBJECT_REF(&listener->inner, caller);

		/*
		 * The callback is not set until here because it should
		 * only be called if the listener was successfully set up.
		 */
		listener->destroy_action = destroy_action;
		listener->destroy_arg = destroy_arg;


	} else {
		/*
		 * Failed to set up the listener.  
		 */
		listener->listening = ISC_FALSE;
		OBJECT_DEREF(&listener);
	}

	return (result);
}

void
omapi_listener_shutdown(omapi_object_t *listener) {
	omapi_listener_t *l;

	REQUIRE((listener != NULL && listener->type == omapi_type_listener) ||
		(listener->outer != NULL &&
		 listener->outer->type == omapi_type_listener));

	if (listener->type == omapi_type_listener)
		l = (omapi_listener_t *)listener;
	else
		l = (omapi_listener_t *)listener->outer;

	/*
	 * It is improper to call this function without having had a successful
	 * run of omapi_listener_listen.
	 */
	REQUIRE(l->socket != NULL && l->task != NULL);

	/*
	 * Stop accepting connections.
	 */
	isc_socket_cancel(l->socket, NULL, ISC_SOCKCANCEL_ACCEPT);
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
listener_destroy(omapi_object_t *listener) {
	omapi_listener_t *l;

	REQUIRE(listener != NULL && listener->type == omapi_type_listener);

	l = (omapi_listener_t *)listener;

	LOCK(&l->mutex);
	INSIST(ISC_LIST_EMPTY(l->connections));
	UNLOCK(&l->mutex);

	RUNTIME_CHECK(isc_mutex_destroy(&l->mutex) == ISC_R_SUCCESS);

	if (l->task != NULL)
		isc_task_destroy(&l->task);

	if (l->socket != NULL)
		isc_socket_detach(&l->socket);

	if (l->acl != NULL)
		dns_acl_detach(&l->acl);
}

static isc_result_t
listener_signalhandler(omapi_object_t *listener, const char *name, va_list ap)
{
	omapi_connection_t *c;
	omapi_listener_t *l;
	isc_result_t result;

	REQUIRE(listener != NULL && listener->type == omapi_type_listener);

	l = (omapi_listener_t *)listener;

	/*
	 * free_connection() signals the listener when one of the connections
	 * it accepted has gone away.
	 */
	if (strcmp(name, "disconnect") == 0) {
		c = va_arg(ap, omapi_connection_t *);

		LOCK(&l->mutex);
		ISC_LIST_UNLINK(l->connections, c, link);

		if (! l->listening && ISC_LIST_HEAD(l->connections) == NULL) {
			/*
			 * The listener has been shutdown and the last
			 * connection was received.
			 */
			UNLOCK(&l->mutex);
			free_listener(l);

		} else
			UNLOCK(&l->mutex);

		result = ISC_R_SUCCESS;
	} else
		result = omapi_object_passsignal(listener, name, ap);

	return (result);
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
