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
 * Subroutines for dealing with message objects.
 */
#include <stddef.h>		/* NULL */
#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/error.h>

#include <omapi/private.h>

omapi_message_t *registered_messages;

isc_result_t
omapi_message_create(omapi_object_t **o) {
	omapi_message_t *message = NULL;
	omapi_object_t *g;
	isc_result_t result;

	result = omapi_object_create((omapi_object_t **)&message,
				     omapi_type_message, sizeof(*message));
	if (result != ISC_R_SUCCESS)
		return (result);

	g = NULL;
	result = omapi_object_create(&g, NULL, 0);
	if (result != ISC_R_SUCCESS) {
		OBJECT_DEREF(&message);
		return (result);
	}

	OBJECT_REF(&message->inner, g);
	OBJECT_REF(&g->outer, message);
	OBJECT_REF(o, message);

	OBJECT_DEREF(&message);
	OBJECT_DEREF(&g);

	return (result);
}

/*
 * XXXDCL Make register/unregister implicitly part of omapi_message_send?
 */
void
omapi_message_register(omapi_object_t *h) {
	omapi_message_t *m;

	REQUIRE(h != NULL && h->type == omapi_type_message);

	m = (omapi_message_t *)h;
	
	/*
	 * Already registered?
	 */
	REQUIRE(m->prev == NULL && m->next == NULL &&
		registered_messages != m);

	if (registered_messages != NULL) {
		OBJECT_REF(&m->next, registered_messages);
		OBJECT_REF(&registered_messages->prev, m);
		OBJECT_DEREF(&registered_messages);
	}

	OBJECT_REF(&registered_messages, m);
}

void
omapi_message_unregister(omapi_object_t *h) {
	omapi_message_t *m;
	omapi_message_t *n;

	REQUIRE(h != NULL && h->type == omapi_type_message);

	m = (omapi_message_t *)h;
	
	/*
	 * Not registered?
	 */
	REQUIRE(m->prev != NULL || registered_messages == m);

	n = NULL;
	if (m->next != NULL) {
		OBJECT_REF(&n, m->next);
		OBJECT_DEREF(&m->next);
	}

	if (m->prev != NULL) {
		omapi_message_t *tmp = NULL;
		OBJECT_REF(&tmp, m->prev);
		OBJECT_DEREF(&m->prev);

		if (tmp->next != NULL)
			OBJECT_DEREF(&tmp->next);

		if (n != NULL)
			OBJECT_REF(&tmp->next, n);

		OBJECT_DEREF(&tmp);

	} else {
		OBJECT_DEREF(&registered_messages);
		if (n != NULL)
			OBJECT_REF(&registered_messages, n);
	}

	if (n != NULL)
		OBJECT_DEREF(&n);
}

isc_result_t
omapi_message_send(omapi_object_t *message, omapi_object_t *protocol) {
	/*
	 * For this function, at least, generic objects have fully spelled
	 * names and special type objects have short names.
	 * XXXDCL It would be good to be more consistent about this throughout
	 * the code.
	 */
	omapi_protocol_t *p;
	omapi_connection_t *c;
	omapi_message_t *m;
	omapi_object_t *connection;
	isc_result_t result;

	REQUIRE(message != NULL && message->type == omapi_type_message);
	/*
	 * Allow the function to be called with an object that is managing
	 * the client side.
	 */
	REQUIRE((protocol != NULL && protocol->type == omapi_type_protocol) ||
		(protocol->outer != NULL &&
		 protocol->outer->type == omapi_type_protocol));

	if (protocol->type != omapi_type_protocol)
		protocol = protocol->outer;

	p = (omapi_protocol_t *)protocol;

	connection = (omapi_object_t *)(protocol->outer);
	c = (omapi_connection_t *)connection;

	INSIST(connection != NULL &&
	       connection->type == omapi_type_connection);

	m = (omapi_message_t *)message;

	/* XXXTL Write the authenticator length */
	result = omapi_connection_putuint32(connection, 0);
	if (result == ISC_R_SUCCESS)
		/* XXXTL Write the ID of the authentication key we're using. */
		result = omapi_connection_putuint32(connection, 0);

	if (result == ISC_R_SUCCESS)
		/*
		 * Write the opcode.
		 */
		result = omapi_connection_putuint32(connection, m->op);

	if (result == ISC_R_SUCCESS)
		/*
		 * Write the handle.  If we've been given an explicit handle,
		 * use that.  Otherwise, use the handle of the object we're
		 * sending.  The caller is responsible for arranging for one of
		 * these handles to be set (or not).
		 */
		result = omapi_connection_putuint32(connection,
						    (m->h ? m->h
						     : (m->object ?
							m->object->handle
							: 0)));

	if (result == ISC_R_SUCCESS) {
		/*
		 * Set and write the transaction ID.
		 */
		m->id = p->next_xid++;
		result = omapi_connection_putuint32(connection, m->id);
	}

	if (result == ISC_R_SUCCESS)
		/*
		 * Write the transaction ID of the message to which this is a
		 * response.
		 */
		result = omapi_connection_putuint32(connection, m->rid);

	if (result == ISC_R_SUCCESS)
		/*
		 * Stuff out the name/value pairs specific to this message.
		 */
		result = object_stuffvalues(connection, message);

	if (result == ISC_R_SUCCESS)
		/*
		 * Write the zero-length name that terminates the list of
		 * name/value pairs specific to the message.
		 */
		result = omapi_connection_putuint16(connection, 0);

	if (result == ISC_R_SUCCESS && m->object != NULL)
		/*
		 * Stuff out all the published name/value pairs in the object
		 * that's being sent in the message, if there is one.
		 */
		result = object_stuffvalues(connection, m->object);

	if (result == ISC_R_SUCCESS)
		/*
		 * Write the zero-length name length value that terminates
		 * the list of name/value pairs for the associated object.
		 */
		result = omapi_connection_putuint16(connection, 0);

	if (result == ISC_R_SUCCESS)
		/* XXXTL Write the authenticator... */
		(void)0;

	/*
	 * Prime the bytes_needed for the server's reply message.
	 * There is no need to lock.  In the server everything happens in
	 * the socket thread so only one event function is running at a time,
	 * and in the client, there should be no events outstanding which
	 * would cause the socket thread to access this variable .
	 */
	if (result == ISC_R_SUCCESS) {
		INSIST(c->bytes_needed == 0);
		c->bytes_needed = p->header_size;

		result = connection_send(c);
		
		/*
		 * The client waited for the result; the server did not.
		 * The server's result will always be ISC_R_SUCCESS.
		 *
		 * If the client's result is not ISC_R_SUCCESS, the connection
		 * was already closed by the socket event handler that got
		 * the error.  Unfortunately, it is not known whether
		 * it was send_done or recv_done that ended the connection;
		 * if the connection object were not destroyed, one way it
		 * could be inferred is by seeing whether connection->out_bytes
		 * is 0.
		 *
		 * XXXDCL "connection disconnected"
		 */
		if (result != ISC_R_SUCCESS)
			object_signal(message, "status", result, NULL);

	} else if (c->is_client) {
		/*
		 * One of the calls to omapi_connection_put* or to
		 * object_stuffvalues failed.  As of the time of writing
		 * this comment, that would pretty much only happen if
		 * the required output buffer space could be dynamically
		 * allocated.
		 *
		 * The server is in recv_done; let the error propagate back up
		 * the stack to there, and it will close the connection safely.
		 * If the server tried to free the connection here, recv_done
		 * wouldn't be able to distinguish the error from errors
		 * coming out of parts of the library that did not destroy
		 * the connection.
		 *
		 * The client needs the connection destroyed right here,
		 * because control is about to return to the driving thread
		 * and it is guaranteed that if omapi_message_send returns
		 * an error for any reason, then the connection will be gone.
		 * Otherwise the client would have the same problem described
		 * for recv_done on the server -- it wouldn't be able to tell
		 * whether the error freed the connection.
		 */
		omapi_connection_disconnect(connection,
					    OMAPI_FORCE_DISCONNECT);


		/*
		 * The client also needs to be notified the message
		 * never got sent.
		 *
		 * XXXDCL "message not sent; connection disconnected"
		 */
		object_signal(message, "status", result, NULL);
	}

	return (result);
}

isc_result_t
message_process(omapi_object_t *mo, omapi_object_t *po) {
	omapi_message_t *message, *m;
	omapi_object_t *object = NULL;
	omapi_objecttype_t *type = NULL;
	omapi_value_t *tv = NULL;
	unsigned long create, update, exclusive;
	isc_result_t result, waitstatus;

	REQUIRE(mo != NULL && mo->type == omapi_type_message);

	message = (omapi_message_t *)mo;

	if (message->rid != 0) {
		for (m = registered_messages; m != NULL; m = m->next)
			if (m->id == message->rid)
				break;
		/*
		 * If we don't have a real message corresponding to
		 * the message ID to which this message claims it is a
		 * response, something's fishy.
		 */
		if (m == NULL)
			return (ISC_R_NOTFOUND);
	} else
		m = NULL;

	switch (message->op) {
	      case OMAPI_OP_OPEN:
		if (m != NULL) {
			return (send_status(po, OMAPI_R_INVALIDARG,
					    message->id,
					    "OPEN can't be a response"));
		}

		/*
		 * Get the type of the requested object, if one was
		 * specified.
		 *
		 * In this and subsequent calls to omapi_object_getvalue,
		 * an error could be returned, typically ISC_R_NOMEMORY.
		 * send_status *might* fail if the problem is being out
		 * of memory ... but it is worth a shot.
		 */
		result = omapi_object_getvalue(mo, "type", &tv);
		if (result == ISC_R_SUCCESS) {
			if (tv->value->type == omapi_datatype_data ||
			    tv->value->type == omapi_datatype_string)
				type = object_findtype(tv);
			omapi_value_dereference(&tv);
		} else if (result == ISC_R_NOTFOUND)
			type = NULL;
		else
			return (send_status(po, result, message->id,
					    isc_result_totext(result)));

		/*
		 * Get the create flag.
		 */
		result = omapi_object_getvalue(mo, "create", &tv);
		if (result == ISC_R_SUCCESS) {
			create = omapi_value_getint(tv);
			omapi_value_dereference(&tv);
		} else if (result == ISC_R_NOTFOUND)
			create = 0;
		else
			return (send_status(po, result, message->id,
					    isc_result_totext(result)));

		/*
		 * Get the update flag.
		 */
		result = omapi_object_getvalue(mo, "update", &tv);
		if (result == ISC_R_SUCCESS) {
			update = omapi_value_getint(tv);
			omapi_value_dereference(&tv);
		} else if (result == ISC_R_NOTFOUND)
			update = 0;
		else
			return (send_status(po, result, message->id,
					    isc_result_totext(result)));

		/*
		 * Get the exclusive flag.
		 */
		result = omapi_object_getvalue(mo, "exclusive", &tv);
		if (result == ISC_R_SUCCESS) {
			exclusive = omapi_value_getint(tv);
			omapi_value_dereference(&tv);
		} else if (result == ISC_R_NOTFOUND)
			exclusive = 0;
		else
			return (send_status(po, result, message->id,
					    isc_result_totext(result)));

		/*
		 * If we weren't given a type, look the object up with
		 * the handle.
		 */
		if (type == NULL) {
			if (create != 0)
				return (send_status(po, OMAPI_R_INVALIDARG,
						   message->id,
						   "type required on create"));

			goto refresh;
		}

		/*
		 * If the type doesn't provide a lookup method, we can't
		 * look up the object.  Ditto if no lookup key is provided.
		 */
		if (message->object == NULL)
			return (send_status(po, ISC_R_NOTFOUND,
					    message->id,
					    "no lookup key specified"));

		result = object_methodlookup(type, &object, message->object);
		if (result == ISC_R_NOTIMPLEMENTED)
			return (send_status(po, result, message->id,
					    "unsearchable object type"));

		if (result != ISC_R_SUCCESS &&
		    result != ISC_R_NOTFOUND &&
		    result != OMAPI_R_NOKEYS)
			return (send_status(po, result, message->id,
					    "object lookup failed"));

		/*
		 * If we didn't find the object and we aren't supposed to
		 * create it, return an error.
		 */
		if (result == ISC_R_NOTFOUND && create == 0) {
			return (send_status(po, ISC_R_NOTFOUND, message->id,
					   "no object matches specification"));
		}			

		/*
		 * If we found an object, we're supposed to be creating an
		 * object, and we're not supposed to have found an object,
		 * return an error.
		 */
		if (result == ISC_R_SUCCESS && create != 0 && exclusive != 0) {
			OBJECT_DEREF(&object);
			return (send_status(po, ISC_R_EXISTS, message->id,
					   "specified object already exists"));
		}

		/*
		 * If we're creating the object, do it now.
		 */
		if (object == NULL) {
			result = object_methodcreate(type, &object);
			if (result != ISC_R_SUCCESS)
				return (send_status(po, result, message->id,
						   "can't create new object"));
		}

		/*
		 * If we're updating it, do so now.
		 */
		if (create != 0 || update != 0) {
			result = object_update(object, message->object,
					       message->h);
			if (result != ISC_R_SUCCESS) {
				OBJECT_DEREF(&object);
				return (send_status(po, result, message->id,
						    "can't update object"));
			}
		}
		
		/*
		 * Now send the new contents of the object back in response.
		 */
		goto send;

	      case OMAPI_OP_REFRESH:
	      refresh:
		result = handle_lookup(&object, message->h);
		if (result != ISC_R_SUCCESS)
			return (send_status(po, result, message->id,
					    "no matching handle"));

	      send:		
		result = send_update(po, message->id, object);
		OBJECT_DEREF(&object);
		return (result);

	      case OMAPI_OP_UPDATE:
		if (m->object != NULL)
			OBJECT_REF(&object, m->object);

		else {
			result = handle_lookup(&object, message->h);
			if (result != ISC_R_SUCCESS)
				return (send_status(po, result, message->id,
						    "no matching handle"));
		}

		if (message->object != NULL)
			result = object_update(object, message->object,
					       message->h);
		else
			result = ISC_R_SUCCESS;

		OBJECT_DEREF(&object);

		if (result != ISC_R_SUCCESS) {
			if (message->rid == 0)
				return (send_status(po, result, message->id,
						    "can't update object"));
			if (m != NULL)
				object_signal((omapi_object_t *)m,
					      "status", result, NULL);
			return (ISC_R_SUCCESS);
		}

		if (message->rid == 0)
			result = send_status(po, ISC_R_SUCCESS, message->id,
					     NULL);

		if (m != NULL)
			object_signal((omapi_object_t *)m, "status",
				      ISC_R_SUCCESS, NULL);

		return (result);

	      case OMAPI_OP_NOTIFY:
		return (send_status(po, ISC_R_NOTIMPLEMENTED, message->id,
				    "notify not implemented yet"));

	      case OMAPI_OP_STATUS:
		/*
		 * The return status of a request.
		 */
		if (m == NULL)
			return (ISC_R_UNEXPECTED);

		/*
		 * Get the wait status.
		 */
		result = omapi_object_getvalue(mo, "result", &tv);
		if (result == ISC_R_SUCCESS) {
			waitstatus = omapi_value_getint(tv);
			omapi_value_dereference(&tv);
		} else
			waitstatus = ISC_R_UNEXPECTED;

		result = omapi_object_getvalue(mo, "message", &tv);

		object_signal((omapi_object_t *)m, "status", waitstatus, tv);

		if (result == ISC_R_SUCCESS)
			omapi_value_dereference(&tv);

		/*
		 * Even if the two omapi_object_getvalue calls in this
		 * section returned errors, the operation is considered
		 * successful. XXXDCL (should it be?)
		 */
		return (ISC_R_SUCCESS);

	      case OMAPI_OP_DELETE:
		result = handle_lookup(&object, message->h);
		if (result != ISC_R_SUCCESS)
			return (send_status(po, result, message->id,
					    "no matching handle"));

		result = object_methodremove(object->type, object);
		if (result == ISC_R_NOTIMPLEMENTED)
			return (send_status(po, ISC_R_NOTIMPLEMENTED,
					    message->id,
					    "no remove method for object"));

		OBJECT_DEREF(&object);

		return (send_status(po, result, message->id, NULL));
	}
	return (ISC_R_NOTIMPLEMENTED);
}

static isc_result_t
message_setvalue(omapi_object_t *h, omapi_string_t *name, omapi_data_t *value)
{
	omapi_message_t *m;

	REQUIRE(h != NULL && h->type == omapi_type_message);

	m = (omapi_message_t *)h;

	/*
	 * Can't set authlen.
	 */

	/*
	 * Can set authenticator, but the value must be typed data.
	 */
	if (omapi_string_strcmp(name, "authenticator") == 0) {
		if (m->authenticator != NULL)
			omapi_data_dereference(&m->authenticator);
		omapi_data_reference(&m->authenticator, value);
		return (ISC_R_SUCCESS);

	} else if (omapi_string_strcmp(name, "object") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_object);

		if (m->object != NULL)
			OBJECT_DEREF(&m->object);
		OBJECT_REF(&m->object, value->u.object);
		return (ISC_R_SUCCESS);

	} else if (omapi_string_strcmp(name, "notify-object") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_object);

		if (m->notify_object != NULL)
			OBJECT_DEREF(&m->notify_object);
		OBJECT_REF(&m->notify_object, value->u.object);
		return (ISC_R_SUCCESS);

	/*
	 * Can set authid, but it has to be an integer.
	 */
	} else if (omapi_string_strcmp(name, "authid") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_int);

		m->authid = value->u.integer;
		return (ISC_R_SUCCESS);

	/*
	 * Can set op, but it has to be an integer.
	 */
	} else if (omapi_string_strcmp(name, "op") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_int);

		m->op = value->u.integer;
		return (ISC_R_SUCCESS);

	/*
	 * Handle also has to be an integer.
	 */
	} else if (omapi_string_strcmp(name, "handle") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_int);

		m->h = value->u.integer;
		return (ISC_R_SUCCESS);

	/*
	 * Transaction ID has to be an integer.
	 */
	} else if (omapi_string_strcmp(name, "id") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_int);

		m->id = value->u.integer;
		return (ISC_R_SUCCESS);

	/*
	 * Remote transaction ID has to be an integer.
	 */
	} else if (omapi_string_strcmp(name, "rid") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_int);

		m->rid = value->u.integer;
		return (ISC_R_SUCCESS);
	}

	/*
	 * Try to find some inner object that can take the value.
	 */
	return (omapi_object_passsetvalue(h, name, value));
}

static isc_result_t
message_getvalue(omapi_object_t *h, omapi_string_t *name,
		 omapi_value_t **value)
{
	omapi_message_t *m;

	REQUIRE(h != NULL && h->type == omapi_type_message);

	m = (omapi_message_t *)h;

	/*
	 * Look for values that are in the message data structure.
	 */
	if (omapi_string_strcmp(name, "authenticator") == 0) {
		if (m->authenticator != NULL)
			return (omapi_value_storedata(value, name,
						      m->authenticator));
		else
			return (ISC_R_NOTFOUND);

	} else if (omapi_string_strcmp(name, "authlen") == 0)
		return (omapi_value_storeint(value, name, (int)m->authlen));

	else if (omapi_string_strcmp(name, "authid") == 0)
		return (omapi_value_storeint(value, name, (int)m->authid));

	else if (omapi_string_strcmp(name, "op") == 0)
		return (omapi_value_storeint(value, name, (int)m->op));

	else if (omapi_string_strcmp(name, "handle") == 0)
		return (omapi_value_storeint(value, name, (int)m->h));

	else if (omapi_string_strcmp(name, "id") == 0)
		return (omapi_value_storeint(value, name, (int)m->id));

	else if (omapi_string_strcmp(name, "rid") == 0)
		return (omapi_value_storeint(value, name, (int)m->rid));

	/*
	 * See if there's an inner object that has the value.
	 */
	return (omapi_object_passgetvalue(h, name, value));
}

static void
message_destroy(omapi_object_t *handle) {
	omapi_message_t *message;

	REQUIRE(handle != NULL && handle->type == omapi_type_message);

	message = (omapi_message_t *)handle;

	if (message->authenticator != NULL)
		omapi_data_dereference(&message->authenticator);

	INSIST(message->prev == NULL && message->next == NULL &&
	       registered_messages != message);

	if (message->object != NULL)
		OBJECT_DEREF(&message->object);

	if (message->notify_object != NULL)
		OBJECT_DEREF(&message->notify_object);

}

static isc_result_t
message_signalhandler(omapi_object_t *handle, const char *name, va_list ap) {
	omapi_message_t *message;

	REQUIRE(handle != NULL && handle->type == omapi_type_message);

	message = (omapi_message_t *)handle;
	
	if (strcmp(name, "status") == 0 &&
	    (message->object != NULL || message->notify_object != NULL)) {
		if (message->notify_object != NULL)
			return (object_vsignal(message->notify_object, name,
					       ap));
		else
			return (object_vsignal(message->object, name, ap));
	}

	return (omapi_object_passsignal(handle, name, ap));
}

/*
 * Write all the published values associated with the object through the
 * specified connection.
 */
static isc_result_t
message_stuffvalues(omapi_object_t *connection, omapi_object_t *message)
{
	REQUIRE(message != NULL && message->type == omapi_type_message);

	return (omapi_object_passstuffvalues(connection, message));
}

isc_result_t
message_init(void) {
	return (omapi_object_register(&omapi_type_message, "message",
				      message_setvalue,
				      message_getvalue,
				      message_destroy,
				      message_signalhandler,
				      message_stuffvalues,
				      NULL, NULL, NULL));
}
