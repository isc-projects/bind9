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
 * Subroutines for dealing with message objects.
 */
#include <stddef.h>		/* NULL */
#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/error.h>

#include <omapi/private.h>

omapi_message_t *omapi_registered_messages;

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

void
omapi_message_register(omapi_object_t *h) {
	omapi_message_t *m;

	REQUIRE(h != NULL && h->type == omapi_type_message);

	m = (omapi_message_t *)h;
	
	/*
	 * Already registered?
	 */
	REQUIRE(m->prev == NULL && m->next == NULL &&
		omapi_registered_messages != m);

	if (omapi_registered_messages != NULL) {
		OBJECT_REF(&m->next, omapi_registered_messages);
		OBJECT_REF(&omapi_registered_messages->prev, m);
		OBJECT_DEREF(&omapi_registered_messages);
	}

	OBJECT_REF(&omapi_registered_messages, m);
}

static void
omapi_message_unregister(omapi_object_t *h) {
	omapi_message_t *m;
	omapi_message_t *n;

	REQUIRE(h != NULL && h->type == omapi_type_message);

	m = (omapi_message_t *)h;
	
	/*
	 * Not registered?
	 */
	REQUIRE(! (m->prev == NULL && omapi_registered_messages != m));

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
		OBJECT_DEREF(&omapi_registered_messages);
		if (n != NULL)
			OBJECT_REF(&omapi_registered_messages, n);
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
	REQUIRE(protocol != NULL && protocol->type == omapi_type_protocol);

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
	 * When the client sends a message, it expects a reply.  Increment
	 * the count of messages_expected and make sure an isc_socket_recv
	 * gets queued.
	 *
	 * If the connection is in the disconnecting state, connection_send
	 * will note it, by aborting :-), in just a moment.  In any event, it
	 * is decreed to be a fatal error for the client program to call this
	 * function after having asked to disconnect, so going ahead with the
	 * omapi_connection_require call here in the driving thread (rather
	 * than in the task thread, where omapi_protocol_signal_handler
	 * normally does things) is ok.  It is also known that if this is the
	 * only message being sent right now, then there should be no other
	 * recv_done() results coming in until after the
	 * omapi_connection_require(), so some error is not going to be blowing
	 * away the connection.
	 *
	 * XXXDCL I don't think the bulk of this is necessary any more.
	 * The main thing that needs to be done is for the client to wait
	 * on the server's reply.  But what of the server, when it sends
	 * a message?  I might still have an outstanding issue there.
	 */
	if (result == ISC_R_SUCCESS && c->is_client) {
		RUNTIME_CHECK(isc_mutex_lock(&c->mutex) == ISC_R_SUCCESS);
		c->messages_expected++;

		/*
		 * This should always be true with the current state of
		 * forcing synchronicity with the server.  If it is not, then
		 * there is a significant risk that the client program will
		 * try to use the connection even when the server has destroyed
		 * it because of some sort of error.
		 */
		INSIST(c->messages_expected == 1);

		/*
		 * omapi_connection_require() needs an unlocked mutex.
		 */
		RUNTIME_CHECK(isc_mutex_unlock(&c->mutex) == ISC_R_SUCCESS);
		result = connection_require(c, p->header_size);

		/*
		 * How could there possibly be that amount of bytes
		 * waiting if no other messages were outstanding?
		 * Answer: it shouldn't be possible.  Make sure.
		 * OMAPI_R_NOTYET is the expected response; anything
		 * else is an error.
		 */
		INSIST(result != ISC_R_SUCCESS);
		if (result == OMAPI_R_NOTYET) {
			connection_send(c);
			result = connection_wait(connection, NULL);
		}

	} else if (result == ISC_R_SUCCESS)
		connection_send(c);

	if (result != ISC_R_SUCCESS)
		omapi_connection_disconnect(connection,
					    OMAPI_FORCE_DISCONNECT);

	return (result);
}

isc_result_t
message_process(omapi_object_t *mo, omapi_object_t *po) {
	omapi_message_t *message, *m;
	omapi_object_t *object = NULL;
	omapi_objecttype_t *type = NULL;
	omapi_value_t *tv = NULL;
	unsigned long create, update, exclusive;
	unsigned long wsi;
	isc_result_t result, waitstatus;

	REQUIRE(mo != NULL && mo->type == omapi_type_message);

	message = (omapi_message_t *)mo;

	if (message->rid != 0) {
		for (m = omapi_registered_messages; m != NULL; m = m->next)
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
		 */
		result = omapi_object_getvalue(mo, "type", &tv);
		if (result == ISC_R_SUCCESS &&
		    (tv->value->type == omapi_datatype_data ||
		     tv->value->type == omapi_datatype_string)) {
			type = object_findtype(tv);
		} else
			type = NULL;
		if (tv != NULL)
			omapi_value_dereference(&tv);

		/*
		 * Get the create flag.
		 */
		result = omapi_object_getvalue(mo, "create", &tv);
		if (result == ISC_R_SUCCESS) {
			create = omapi_value_asint(tv->value);
			omapi_value_dereference(&tv);
		} else
			create = 0;

		/*
		 * Get the update flag.
		 */
		result = omapi_object_getvalue(mo, "update", &tv);
		if (result == ISC_R_SUCCESS) {
			update = omapi_value_asint(tv->value);
			omapi_value_dereference(&tv);
		} else
			update = 0;

		/*
		 * Get the exclusive flag.
		 */
		result = omapi_object_getvalue(mo, "exclusive", &tv);
		if (result == ISC_R_SUCCESS) {
			exclusive = omapi_value_asint(tv->value);
			omapi_value_dereference(&tv);
		} else
			exclusive = 0;

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
			return (send_status(po, ISC_R_NOTIMPLEMENTED,
					    message->id,
					    "unsearchable object type"));

		if (result != ISC_R_SUCCESS &&
		    result != ISC_R_NOTFOUND &&
		    result != OMAPI_R_NOKEYS) {
			return (send_status(po, result, message->id,
					    "object lookup failed"));
		}

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
					       message->handle);
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
		result = handle_lookup(&object, message->handle);
		if (result != ISC_R_SUCCESS) {
			return (send_status(po, result, message->id,
					    "no matching handle"));
		}
	      send:		
		result = send_update(po, message->id, object);
		OBJECT_DEREF(&object);
		return (result);

	      case OMAPI_OP_UPDATE:
		if (m->object != NULL) {
			OBJECT_REF(&object, m->object);
		} else {
			result = handle_lookup(&object, message->handle);
			if (result != ISC_R_SUCCESS) {
				return (send_status(po, result, message->id,
						    "no matching handle"));
			}
		}

		result = object_update(object, message->object,
				       message->handle);
		if (result != ISC_R_SUCCESS) {
			OBJECT_DEREF(&object);
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
			wsi = omapi_value_asint(tv->value);
			waitstatus = wsi;
			omapi_value_dereference(&tv);
		} else
			waitstatus = ISC_R_UNEXPECTED;

		result = omapi_object_getvalue(mo, "message", &tv);
		object_signal((omapi_object_t *)m, "status",
			      waitstatus, tv);
		if (result == ISC_R_SUCCESS)
			omapi_value_dereference(&tv);
		return (ISC_R_SUCCESS);

	      case OMAPI_OP_DELETE:
		result = handle_lookup(&object, message->handle);
		if (result != ISC_R_SUCCESS) {
			return (send_status(po, result, message->id,
					    "no matching handle"));
		}

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
	if (omapi_string_strcmp(name, "authenticator") == 0)
		if (m->authenticator != NULL)
			return (omapi_value_storedata(value, name,
						      m->authenticator));
		else
			return (ISC_R_NOTFOUND);

	else if (omapi_string_strcmp(name, "authlen") == 0)
		return (omapi_value_storeint(value, name, (int)m->authlen));

	else if (omapi_string_strcmp(name, "authid") == 0)
		return (omapi_value_storeint(value, name, (int)m->authid));

	else if (omapi_string_strcmp(name, "op") == 0)
		return (omapi_value_storeint(value, name, (int)m->op));

	else if (omapi_string_strcmp(name, "handle") == 0)
		return (omapi_value_storeint(value, name, (int)m->handle));

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

	if (message->prev == NULL && omapi_registered_messages != message)
		omapi_message_unregister(handle);
	if (message->prev != NULL)
		OBJECT_DEREF(&message->prev);
	if (message->next != NULL)
		OBJECT_DEREF(&message->next);
	if (message->object != NULL)
		OBJECT_DEREF(&message->object);
}

static isc_result_t
message_signalhandler(omapi_object_t *handle, const char *name, va_list ap) {
	omapi_message_t *message;

	REQUIRE(handle != NULL && handle->type == omapi_type_message);

	message = (omapi_message_t *)handle;
	
	if (strcmp(name, "status") == 0 &&
	    (message->object != NULL || message->notify_object != NULL))
		if (message->object != NULL)
			return (object_vsignal(message->object, name, ap));
		else
			return (object_vsignal(message->notify_object, name,
					       ap));

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
