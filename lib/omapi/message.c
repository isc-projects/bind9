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

#include <omapi/private.h>

omapi_message_object_t *omapi_registered_messages;

isc_result_t
omapi_message_new(omapi_object_t **o, const char *name) {
	omapi_message_object_t *message = NULL;
	omapi_object_t *g;
	isc_result_t result;

	result = omapi_object_new((omapi_object_t **)&message,
				  omapi_type_message, sizeof(*message));
	if (result != ISC_R_SUCCESS)
		return (result);

	g = NULL;
	result = omapi_generic_new(&g, name);
	if (result != ISC_R_SUCCESS) {
		OBJECT_DEREF(&message, "omapi_message_new");
		return (result);
	}

	OBJECT_REF(&message->inner, g, name);
	OBJECT_REF(&g->outer, message, name);
	OBJECT_REF(o, message, name);

	OBJECT_DEREF(&message, name);
	OBJECT_DEREF(&g, name);

	return (result);
}

isc_result_t
omapi_message_setvalue(omapi_object_t *h, omapi_object_t *id,
			omapi_data_string_t *name,
			omapi_typed_data_t *value)
{
	omapi_message_object_t *m;

	REQUIRE(h != NULL && h->type == omapi_type_message);

	m = (omapi_message_object_t *)h;

	/*
	 * Can't set authlen.
	 */

	/*
	 * Can set authenticator, but the value must be typed data.
	 */
	if (omapi_ds_strcmp(name, "authenticator") == 0) {
		if (m->authenticator != NULL)
			omapi_data_dereference(&m->authenticator,
					       "omapi_message_set_value");
		omapi_data_reference(&m->authenticator, value,
				     "omapi_message_set_value");
		return (ISC_R_SUCCESS);

	} else if (omapi_ds_strcmp(name, "object") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_object);

		if (m->object != NULL)
			OBJECT_DEREF(&m->object, "omapi_message_set_value");
		OBJECT_REF(&m->object, value->u.object,
			  "omapi_message_set_value");
		return (ISC_R_SUCCESS);

	} else if (omapi_ds_strcmp(name, "notify-object") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_object);

		if (m->notify_object != NULL)
			OBJECT_DEREF(&m->notify_object,
				    "omapi_message_set_value");
		OBJECT_REF(&m->notify_object, value->u.object,
			  "omapi_message_set_value");
		return (ISC_R_SUCCESS);

	/*
	 * Can set authid, but it has to be an integer.
	 */
	} else if (omapi_ds_strcmp(name, "authid") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_int);

		m->authid = value->u.integer;
		return (ISC_R_SUCCESS);

	/*
	 * Can set op, but it has to be an integer.
	 */
	} else if (omapi_ds_strcmp(name, "op") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_int);

		m->op = value->u.integer;
		return (ISC_R_SUCCESS);

	/*
	 * Handle also has to be an integer.
	 */
	} else if (omapi_ds_strcmp(name, "handle") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_int);

		m->h = value->u.integer;
		return (ISC_R_SUCCESS);

	/*
	 * Transaction ID has to be an integer.
	 */
	} else if (omapi_ds_strcmp(name, "id") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_int);

		m->id = value->u.integer;
		return (ISC_R_SUCCESS);

	/*
	 * Remote transaction ID has to be an integer.
	 */
	} else if (omapi_ds_strcmp(name, "rid") == 0) {
		INSIST(value != NULL && value->type == omapi_datatype_int);

		m->rid = value->u.integer;
		return (ISC_R_SUCCESS);
	}

	/*
	 * Try to find some inner object that can take the value.
	 */
	PASS_SETVALUE(h);
}

isc_result_t
omapi_message_getvalue(omapi_object_t *h, omapi_object_t *id,
			omapi_data_string_t *name,
			omapi_value_t **value)
{
	omapi_message_object_t *m;

	REQUIRE(h != NULL && h->type == omapi_type_message);

	m = (omapi_message_object_t *)h;

	/*
	 * Look for values that are in the message data structure.
	 */
	if (omapi_ds_strcmp(name, "authlen") == 0)
		return (omapi_make_int_value(value, name, (int)m->authlen,
					     "omapi_message_get_value"));
	else if (omapi_ds_strcmp(name, "authenticator") == 0) {
		if (m->authenticator != NULL)
			return (omapi_make_value(value, name, m->authenticator,
						 "omapi_message_get_value"));
		else
			return (ISC_R_NOTFOUND);
	} else if (omapi_ds_strcmp(name, "authid") == 0) {
		return (omapi_make_int_value(value, name, (int)m->authid,
					     "omapi_message_get_value"));
	} else if (omapi_ds_strcmp(name, "op") == 0) {
		return (omapi_make_int_value(value, name, (int)m->op,
					     "omapi_message_get_value"));
	} else if (omapi_ds_strcmp(name, "handle") == 0) {
		return (omapi_make_int_value(value, name, (int)m->handle,
					     "omapi_message_get_value"));
	} else if (omapi_ds_strcmp(name, "id") == 0) {
		return (omapi_make_int_value(value, name, (int)m->id, 
					     "omapi_message_get_value"));
	} else if (omapi_ds_strcmp(name, "rid") == 0) {
		return (omapi_make_int_value(value, name, (int)m->rid,
					     "omapi_message_get_value"));
	}

	/*
	 * See if there's an inner object that has the value.
	 */
	PASS_GETVALUE(h);
}

void
omapi_message_destroy(omapi_object_t *handle, const char *name) {
	omapi_message_object_t *message;

	REQUIRE(handle != NULL && handle->type == omapi_type_message);

	message = (omapi_message_object_t *)handle;

	if (message->authenticator != NULL)
		omapi_data_dereference(&message->authenticator, name);

	if (message->prev == NULL && omapi_registered_messages != message)
		omapi_message_unregister(handle);
	if (message->prev != NULL)
		OBJECT_DEREF(&message->prev, name);
	if (message->next != NULL)
		OBJECT_DEREF(&message->next, name);
	if (message->id_object != NULL)
		OBJECT_DEREF(&message->id_object, name);
	if (message->object != NULL)
		OBJECT_DEREF(&message->object, name);
}

isc_result_t
omapi_message_signalhandler(omapi_object_t *handle, const char *name,
			    va_list ap) {
	omapi_message_object_t *message;

	REQUIRE(handle != NULL && handle->type == omapi_type_message);

	message = (omapi_message_object_t *)handle;
	
	if (strcmp(name, "status") == 0 &&
	    (message->object != NULL || message->notify_object != NULL)) {
		if (message->object != NULL)
			return ((message->object->type->signal_handler))
				(message->object, name, ap);
		else
			return ((message->notify_object->type->signal_handler))
				(message->notify_object, name, ap);
	}

	PASS_SIGNAL(handle);
}

/*
 * Write all the published values associated with the object through the
 * specified connection.
 */

isc_result_t
omapi_message_stuffvalues(omapi_object_t *connection, omapi_object_t *id,
			  omapi_object_t *message)
{
	REQUIRE(message != NULL && message->type == omapi_type_message);

	PASS_STUFFVALUES(message);
}

isc_result_t
omapi_message_register(omapi_object_t *h) {
	omapi_message_object_t *m;

	REQUIRE(h != NULL && h->type == omapi_type_message);

	m = (omapi_message_object_t *)h;
	
	/*
	 * Already registered?
	 */
	REQUIRE(m->prev == NULL && m->next == NULL &&
		omapi_registered_messages != m);

	if (omapi_registered_messages != NULL) {
		OBJECT_REF(&m->next, omapi_registered_messages,
			  "omapi_message_register");
		OBJECT_REF(&omapi_registered_messages->prev, m,
			  "omapi_message_register");
		OBJECT_DEREF(&omapi_registered_messages,
			    "omapi_message_register");
	}

	OBJECT_REF(&omapi_registered_messages, m,
		  "omapi_message_register");
	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_message_unregister(omapi_object_t *h) {
	omapi_message_object_t *m;
	omapi_message_object_t *n;

	REQUIRE(h != NULL && h->type == omapi_type_message);

	m = (omapi_message_object_t *)h;
	
	/*
	 * Not registered?
	 */
	REQUIRE(! (m->prev == NULL && omapi_registered_messages != m));

	n = NULL;
	if (m->next != NULL) {
		OBJECT_REF(&n, m->next, "omapi_message_unregister");
		OBJECT_DEREF(&m->next, "omapi_message_unregister");
	}

	if (m->prev != NULL) {
		omapi_message_object_t *tmp = NULL;
		OBJECT_REF(&tmp, m->prev, "omapi_message_register");
		OBJECT_DEREF(&m->prev, "omapi_message_unregister");

		if (tmp->next != NULL)
			OBJECT_DEREF(&tmp->next, "omapi_message_unregister");

		if (n != NULL)
			OBJECT_REF(&tmp->next, n, "omapi_message_unregister");

		OBJECT_DEREF(&tmp, "omapi_message_unregister");

	} else {
		OBJECT_DEREF(&omapi_registered_messages,
			    "omapi_message_unregister");
		if (n != NULL)
			OBJECT_REF(&omapi_registered_messages, n,
				  "omapi_message_unregister");
	}

	if (n != NULL)
		OBJECT_DEREF(&n, "omapi_message_unregister");

	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_message_process(omapi_object_t *mo, omapi_object_t *po) {
	omapi_message_object_t *message, *m;
	omapi_object_t *object = NULL;
	omapi_value_t *tv = NULL;
	unsigned long create, update, exclusive;
	unsigned long wsi;
	isc_result_t result, waitstatus;
	omapi_object_type_t *type;

	REQUIRE(mo != NULL && mo->type == omapi_type_message);

	message = (omapi_message_object_t *)mo;

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
			return (omapi_protocol_send_status(po, NULL,
							   OMAPI_R_INVALIDARG,
							   message->id,
							   "OPEN can't be "
							   "a response"));
		}

		/*
		 * Get the type of the requested object, if one was
		 * specified.
		 */
		result = omapi_get_value_str(mo, NULL, "type", &tv);
		if (result == ISC_R_SUCCESS &&
		    (tv->value->type == omapi_datatype_data ||
		     tv->value->type == omapi_datatype_string)) {
			for (type = omapi_object_types;
			     type != NULL; type = type->next)
				if (omapi_td_strcmp(tv->value, type->name)
				    == 0)
					break;
		} else
			type = NULL;
		if (tv != NULL)
			omapi_data_valuedereference(&tv,
						    "omapi_message_process");

		/*
		 * Get the create flag.
		 */
		result = omapi_get_value_str(mo, NULL, "create", &tv);
		if (result == ISC_R_SUCCESS) {
			result = omapi_get_int_value(&create, tv->value);
			omapi_data_valuedereference(&tv,
						    "omapi_message_process");
			if (result != ISC_R_SUCCESS) {
				return (omapi_protocol_send_status(po, NULL,
						 result, message->id,
						 "invalid create flag value"));
			}
		} else
			create = 0;

		/*
		 * Get the update flag.
		 */
		result = omapi_get_value_str(mo, NULL, "update", &tv);
		if (result == ISC_R_SUCCESS) {
			result = omapi_get_int_value(&update, tv->value);
			omapi_data_valuedereference(&tv,
						    "omapi_message_process");
			if (result != ISC_R_SUCCESS) {
				return (omapi_protocol_send_status(po, NULL,
						 result, message->id,
						 "invalid update flag value"));
			}
		} else
			update = 0;

		/*
		 * Get the exclusive flag.
		 */
		result = omapi_get_value_str(mo, NULL, "exclusive", &tv);
		if (result == ISC_R_SUCCESS) {
			result = omapi_get_int_value(&exclusive, tv->value);
			omapi_data_valuedereference(&tv,
						    "omapi_message_process");
			if (result != ISC_R_SUCCESS) {
				return (omapi_protocol_send_status(po, NULL,
					      result, message->id,
					      "invalid exclusive flag value"));
			}
		} else
			exclusive = 0;

		/*
		 * If we weren't given a type, look the object up with
		 * the handle.
		 */
		if (type == NULL) {
			if (create != 0) {
				return (omapi_protocol_send_status(po, NULL,
						 OMAPI_R_INVALIDARG,
						 message->id,
						 "type required on create"));
			}
			goto refresh;
		}

		/*
		 * If the type doesn't provide a lookup method, we can't
		 * look up the object.
		 */
		if (type->lookup == NULL) {
			return (omapi_protocol_send_status(po, NULL,
					     ISC_R_NOTIMPLEMENTED, message->id,
					     "unsearchable object type"));
		}

		if (message->object == NULL) {
			return (omapi_protocol_send_status(po, NULL,
						   ISC_R_NOTFOUND, message->id,
						   "no lookup key specified"));
		}
		result = (*(type->lookup))(&object, NULL, message->object);

		if (result != ISC_R_SUCCESS &&
		    result != ISC_R_NOTFOUND &&
		    result != OMAPI_R_NOKEYS) {
			return (omapi_protocol_send_status(po, NULL, 
						      result, message->id,
						      "object lookup failed"));
		}

		/*
		 * If we didn't find the object and we aren't supposed to
		 * create it, return an error.
		 */
		if (result == ISC_R_NOTFOUND && create == 0) {
			return (omapi_protocol_send_status(po, NULL,
					   ISC_R_NOTFOUND, message->id,
					   "no object matches specification"));
		}			

		/*
		 * If we found an object, we're supposed to be creating an
		 * object, and we're not supposed to have found an object,
		 * return an error.
		 */
		if (result == ISC_R_SUCCESS && create != 0 && exclusive != 0) {
			OBJECT_DEREF(&object, "omapi_message_process");
			return (omapi_protocol_send_status(po, NULL,
					   ISC_R_EXISTS, message->id,
					   "specified object already exists"));
		}

		/*
		 * If we're creating the object, do it now.
		 */
		if (object == NULL) {
			result = omapi_object_create(&object, NULL, type);
			if (result != ISC_R_SUCCESS) {
				return (omapi_protocol_send_status(po, NULL,
						   result, message->id,
						   "can't create new object"));
			}
		}

		/*
		 * If we're updating it, do so now.
		 */
		if (create != 0 || update != 0) {
			result = omapi_object_update(object, NULL,
						     message->object,
						     message->handle);
			if (result != ISC_R_SUCCESS) {
				OBJECT_DEREF(&object, "omapi_message_process");
				return (omapi_protocol_send_status(po, NULL,
						       result, message->id,
						       "can't update object"));
			}
		}
		
		/*
		 * Now send the new contents of the object back in response.
		 */
		goto send;

	      case OMAPI_OP_REFRESH:
	      refresh:
		result = omapi_handle_lookup(&object, message->handle);
		if (result != ISC_R_SUCCESS) {
			return (omapi_protocol_send_status(po, NULL,
							result, message->id,
							"no matching handle"));
		}
	      send:		
		result = omapi_protocol_send_update(po, NULL,
						    message->id, object);
		OBJECT_DEREF(&object, "omapi_message_process");
		return (result);

	      case OMAPI_OP_UPDATE:
		if (m->object != NULL) {
			OBJECT_REF(&object, m->object,
				   "omapi_message_process");
		} else {
			result = omapi_handle_lookup(&object, message->handle);
			if (result != ISC_R_SUCCESS) {
				return (omapi_protocol_send_status(po, NULL,
							result, message->id,
							"no matching handle"));
			}
		}

		result = omapi_object_update(object, NULL, message->object,
					     message->handle);
		if (result != ISC_R_SUCCESS) {
			OBJECT_DEREF(&object, "omapi_message_process");
			if (message->rid == 0)
				return (omapi_protocol_send_status(po, NULL,
						       result, message->id,
						       "can't update object"));
			if (m != NULL)
				omapi_signal((omapi_object_t *)m,
					     "status", result, NULL);
			return (ISC_R_SUCCESS);
		}
		if (message->rid == 0)
			result = omapi_protocol_send_status(po, NULL,
							    ISC_R_SUCCESS,
							    message->id, NULL);
		if (m != NULL)
			omapi_signal((omapi_object_t *)m, "status",
				     ISC_R_SUCCESS, NULL);
		return (result);

	      case OMAPI_OP_NOTIFY:
		return (omapi_protocol_send_status(po, NULL,
						ISC_R_NOTIMPLEMENTED,
						message->id,
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
		result = omapi_get_value_str(mo, NULL, "result", &tv);
		if (result == ISC_R_SUCCESS) {
			result = omapi_get_int_value(&wsi, tv->value);
			waitstatus = wsi;
			omapi_data_valuedereference(&tv,
						    "omapi_message_process");
			if (result != ISC_R_SUCCESS)
				waitstatus = ISC_R_UNEXPECTED;
		} else
			waitstatus = ISC_R_UNEXPECTED;

		result = omapi_get_value_str(mo, NULL, "message", &tv);
		omapi_signal((omapi_object_t *)m, "status", waitstatus, tv);
		if (result == ISC_R_SUCCESS)
			omapi_data_valuedereference(&tv,
						    "omapi_message_process");
		return (ISC_R_SUCCESS);

	      case OMAPI_OP_DELETE:
		result = omapi_handle_lookup(&object, message->handle);
		if (result != ISC_R_SUCCESS) {
			return (omapi_protocol_send_status(po, NULL,
							result, message->id,
							"no matching handle"));
		}

		if (object->type->remove == NULL)
			return (omapi_protocol_send_status(po, NULL,
					     ISC_R_NOTIMPLEMENTED, message->id,
					     "no remove method for object"));

		result = (*(object->type->remove))(object, NULL);
		OBJECT_DEREF(&object, "omapi_message_process");

		return (omapi_protocol_send_status(po, NULL, result,
						   message->id, NULL));
	}
	return (ISC_R_NOTIMPLEMENTED);
}
