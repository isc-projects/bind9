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
 * Functions supporting the object management protocol.
 */
#include <stddef.h>		/* NULL */
#include <stdlib.h>		/* random */
#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/error.h>

#include <omapi/private.h>

typedef enum {
	omapi_protocol_intro_wait,
	omapi_protocol_header_wait,
	omapi_protocol_signature_wait,
	omapi_protocol_name_wait,
	omapi_protocol_name_length_wait,
	omapi_protocol_value_wait,
	omapi_protocol_value_length_wait
} omapi_protocol_state_t;

typedef struct {
	OMAPI_OBJECT_PREAMBLE;
} omapi_protocol_listener_object_t;

typedef struct {
	OMAPI_OBJECT_PREAMBLE;
	unsigned int			header_size;		
	unsigned int			protocol_version;
	isc_uint32_t			next_xid;
	omapi_object_t *		authinfo; /* Default authinfo. */

	omapi_protocol_state_t		state;	/* Input state. */
	/* XXXDCL make isc_boolean_t */
	/*
	 * True when reading message-specific values.
	 */
	int				reading_message_values;
	omapi_message_object_t *	message;	/* Incoming message. */
	omapi_data_string_t *		name;		/* Incoming name. */
	omapi_typed_data_t *		value;		/* Incoming value. */
} omapi_protocol_object_t;

/*
 * OMAPI protocol header, version 1.00
 */
typedef struct {
	unsigned int authlen;  /* Length of authenticator. */
	unsigned int authid;   /* Authenticator object ID. */
	unsigned int op;       /* Opcode. */
	omapi_handle_t handle; /* Handle of object being operated on, or 0. */
	unsigned int id;	/* Transaction ID. */
	unsigned int rid;       /* ID of transaction responding to. */
} omapi_protocol_header_t;

isc_result_t
omapi_protocol_connect(omapi_object_t *h, const char *server_name,
		       int port, omapi_object_t *authinfo)
{
	isc_result_t result;
	omapi_protocol_object_t *obj;

	obj = isc_mem_get(omapi_mctx, sizeof(*obj));
	if (obj == NULL)
		return (ISC_R_NOMEMORY);
	memset(obj, 0, sizeof(*obj));
	obj->object_size = sizeof(*obj);
	obj->refcnt = 1;
	obj->type = omapi_type_protocol;

	result = omapi_connection_toserver((omapi_object_t *)obj,
					   server_name, port);
	if (result != ISC_R_SUCCESS) {
		OBJECT_DEREF(&obj, "omapi_protocol_connect");
		return (result);
	}
	OBJECT_REF(&h->outer, obj, "omapi_protocol_connect");
	OBJECT_REF(&obj->inner, h, "omapi_protocol_connect");

	/*
	 * Send the introductory message.
	 */
	result = omapi_protocol_send_intro((omapi_object_t *)obj,
					   OMAPI_PROTOCOL_VERSION,
					   sizeof(omapi_protocol_header_t));
	if (result != ISC_R_SUCCESS) {
		OBJECT_DEREF(&obj, "omapi_protocol_connect");
		return (result);
	}

	if (authinfo)
		OBJECT_REF(&obj->authinfo, authinfo, "omapi_protocol_connect");
	OBJECT_DEREF(&obj, "omapi_protocol_accept");
	return (ISC_R_SUCCESS);
}

/*
 * Send the protocol introduction message.
 */
isc_result_t
omapi_protocol_send_intro(omapi_object_t *h, unsigned int ver,
			  unsigned int hsize)
{
	isc_result_t result;
	isc_task_t *task;
	omapi_protocol_object_t *p;
	omapi_connection_object_t *connection;

	REQUIRE(h != NULL && h->type == omapi_type_protocol);

	p = (omapi_protocol_object_t *)h;
	connection = (omapi_connection_object_t *)h->outer;

	if (h->outer == NULL || h->outer->type != omapi_type_connection)
		return (ISC_R_NOTCONNECTED);

	result = omapi_connection_putuint32((omapi_object_t *)connection,
					     ver);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = omapi_connection_putuint32((omapi_object_t *)connection,
					     hsize);

	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Require the other end to send an intro - this kicks off the
	 * protocol input state machine.
	 */
	p->state = omapi_protocol_intro_wait;
	result = omapi_connection_require((omapi_object_t *)connection, 8);
	if (result != ISC_R_SUCCESS && result != OMAPI_R_NOTYET)
		return (result);

	/*
	 * Make up an initial transaction ID for this connection.
	 * XXXDCL better generator than random()?
	 */
	p->next_xid = random();

	connection_send(connection);

	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_protocol_send_message(omapi_object_t *po, omapi_object_t *id,
			    omapi_object_t *mo, omapi_object_t *omo)
{
	omapi_protocol_object_t *p;
	omapi_object_t *c;
	omapi_message_object_t *m;
	omapi_message_object_t *om;
	isc_task_t *task;
	isc_result_t result;

	REQUIRE(po != NULL && po->type == omapi_type_protocol &&
		po->outer != NULL && po->outer->type == omapi_type_connection);
	REQUIRE(mo != NULL && mo->type == omapi_type_message);
	REQUIRE(omo == NULL || omo->type == omapi_type_message);

	p = (omapi_protocol_object_t *)po;
	c = (omapi_object_t *)(po->outer);
	m = (omapi_message_object_t *)mo;
	om = (omapi_message_object_t *)omo;

	/* XXXTL Write the authenticator length */
	result = omapi_connection_putuint32(c, 0);
	if (result != ISC_R_SUCCESS)
		return (result);

	/* XXXTL Write the ID of the authentication key we're using. */
	result = omapi_connection_putuint32(c, 0);
	if (result != ISC_R_SUCCESS) {
		omapi_disconnect(c, OMAPI_FORCE_DISCONNECT);
		return (result);
	}

	/*
	 * Write the opcode.
	 */
	result = omapi_connection_putuint32(c, m->op);
	if (result != ISC_R_SUCCESS) {
		omapi_disconnect(c, OMAPI_FORCE_DISCONNECT);
		return (result);
	}

	/*
	 * Write the handle.  If we've been given an explicit handle, use
	 * that.   Otherwise, use the handle of the object we're sending.
	 * The caller is responsible for arranging for one of these handles
	 * to be set (or not).
	 */
	result = omapi_connection_putuint32(c, (m->h ? m->h
						 : (m->object ?
						    m->object->handle
						    : 0)));
	if (result != ISC_R_SUCCESS) {
		omapi_disconnect(c, OMAPI_FORCE_DISCONNECT);
		return (result);
	}

	/*
	 * Set and write the transaction ID.
	 */
	m->id = p->next_xid++;
	result = omapi_connection_putuint32(c, m->id);
	if (result != ISC_R_SUCCESS) {
		omapi_disconnect(c, OMAPI_FORCE_DISCONNECT);
		return (result);
	}

	/*
	 * Write the transaction ID of the message to which this is a
	 * response, if there is such a message.
	 */
	result = omapi_connection_putuint32(c, om ? om->id : m->rid);
	if (result != ISC_R_SUCCESS) {
		omapi_disconnect(c, OMAPI_FORCE_DISCONNECT);
		return (result);
	}

	/*
	 * Stuff out the name/value pairs specific to this message.
	 */
	result = omapi_stuff_values(c, id, (omapi_object_t *)m);
	if (result != ISC_R_SUCCESS) {
		omapi_disconnect(c, OMAPI_FORCE_DISCONNECT);
		return (result);
	}

	/*
	 * Write the zero-length name that terminates the list of name/value
	 * pairs specific to the message.
	 */
	result = omapi_connection_putuint16(c, 0);
	if (result != ISC_R_SUCCESS) {
		omapi_disconnect(c, OMAPI_FORCE_DISCONNECT);
		return (result);
	}

	/*
	 * Stuff out all the published name/value pairs in the object that's
	 * being sent in the message, if there is one.
	 */
	if (m->object != NULL) {
		result = omapi_stuff_values(c, id, m->object);
		if (result != ISC_R_SUCCESS) {
			omapi_disconnect(c, OMAPI_FORCE_DISCONNECT);
			return (result);
		}
	}

	/*
	 * Write the zero-length name that terminates the list of name/value
	 * pairs for the associated object.
	 */
	result = omapi_connection_putuint16(c, 0);
	if (result != ISC_R_SUCCESS) {
		omapi_disconnect(c, OMAPI_FORCE_DISCONNECT);
		return (result);
	}

	/* XXXTL Write the authenticator... */


	connection_send((omapi_connection_object_t *)c);

	return (ISC_R_SUCCESS);
}
					  
isc_result_t
omapi_protocol_signal_handler(omapi_object_t *h, const char *name, va_list ap)
{
	isc_result_t result;
	omapi_protocol_object_t *p;
	omapi_object_t *connection;
	isc_uint16_t nlen;
	isc_uint32_t vlen;

	REQUIRE(h != NULL && h->type == omapi_type_protocol);

	p = (omapi_protocol_object_t *)h;

	/*
	 * Not a signal we recognize?
	 */
	if (strcmp(name, "ready") != 0)
		PASS_SIGNAL(h);

	INSIST(p->outer != NULL && p->outer->type == omapi_type_connection);

	connection = p->outer;

	/*
	 * We get here because we requested that we be woken up after
	 * some number of bytes were read, and that number of bytes
	 * has in fact been read.
	 */
	switch (p->state) {
	case omapi_protocol_intro_wait:
		/*
		 * Get protocol version and header size in network
		 * byte order.
		 */
		omapi_connection_getuint32(connection,
					    (isc_uint32_t *)
					    &p->protocol_version);
		omapi_connection_getuint32(connection,
					    (isc_uint32_t *)&p->header_size);
	
		/*
		 * We currently only support the current protocol version.
		 */
		if (p->protocol_version != OMAPI_PROTOCOL_VERSION) {
			omapi_disconnect(connection, OMAPI_FORCE_DISCONNECT);
			return (ISC_R_VERSIONMISMATCH);
		}

		if (p->header_size < sizeof(omapi_protocol_header_t)) {
			omapi_disconnect(connection, OMAPI_FORCE_DISCONNECT);
			return (ISC_R_PROTOCOLERROR);
		}

		result = omapi_signal_in(h->inner, "ready");
		if (result != ISC_R_SUCCESS)
			/* XXXDCL disconnect? */
			return (result);

	to_header_wait:
		/*
		 * The next thing we're expecting is a message header.
		 */
		p->state = omapi_protocol_header_wait;

		/*
		 * Register a need for the number of bytes in a
		 * header, and if we already have that many, process
		 * them immediately.
		 */
		if ((omapi_connection_require(connection, p->header_size))
		    != ISC_R_SUCCESS)
			break;
		/*
		 * If we already have the data, fall through.
		 */

	case omapi_protocol_header_wait:
		result = omapi_message_new((omapi_object_t **)&p->message,
					   "omapi_protocol_signal_handler");
		if (result != ISC_R_SUCCESS) {
			omapi_disconnect(connection, OMAPI_FORCE_DISCONNECT);
			return (result);
		}

		/*
		 * Swap in the header.
		 */
		omapi_connection_getuint32(connection,
					  (isc_uint32_t *)&p->message->authid);

		/* XXXTL bind the authenticator here! */
		omapi_connection_getuint32(connection,
					 (isc_uint32_t *)&p->message->authlen);
		omapi_connection_getuint32(connection,
					    (isc_uint32_t *)&p->message->op);
		omapi_connection_getuint32(connection,
					  (isc_uint32_t *)&p->message->handle);
		omapi_connection_getuint32(connection,
					    (isc_uint32_t *)&p->message->id);
		omapi_connection_getuint32(connection,
					    (isc_uint32_t *)&p->message->rid);

		/*
		 * If there was any extra header data, skip over it.
		 */
		if (p->header_size > sizeof(omapi_protocol_header_t)) {
			omapi_connection_copyout(0, connection,
					    (p->header_size -
					     sizeof(omapi_protocol_header_t)));
		}
						     
		/*
		 * XXXTL must compute partial signature across the preceding
		 * bytes.  Also, if authenticator specifies encryption as well
		 * as signing, we may have to decrypt the data on the way in.
		 */

		/*
		 * First we read in message-specific values, then object
		 * values.
		 */
		p->reading_message_values = 1;

	need_name_length:
		/*
		 * The next thing we're expecting is length of the
		 * first name.
		 */
		p->state = omapi_protocol_name_length_wait;

		/*
		 * Wait for a 16-bit length.
		 */
		if (omapi_connection_require(connection, 2) != ISC_R_SUCCESS)
			break;
		/*
		 * If it's already here, fall through.
		 */

	case omapi_protocol_name_length_wait:
		result = omapi_connection_getuint16(connection, &nlen);
		if (result != ISC_R_SUCCESS) {
			omapi_disconnect(connection, OMAPI_FORCE_DISCONNECT);
			return (result);
		}

		/*
		 * A zero-length name means that we're done reading name+value
		 * pairs.
		 */
		if (nlen == 0) {
			/*
			 * If we've already read in the object, we are
			 * done reading the message, but if we've just
			 * finished reading in the values associated
			 * with the message, we need to read the
			 * object.
			 */
			if (p->reading_message_values) {
				p->reading_message_values = 0;
				goto need_name_length;
			}

			/*
			 * If the authenticator length is zero, there's no
			 * signature to read in, so go straight to processing
			 * the message.
			 */
			if (p->message->authlen == 0)
				goto message_done;

			/*
			 * The next thing we're expecting is the
			 * message signature.
			 */
			p->state = omapi_protocol_signature_wait;

			/*
			 * Wait for the number of bytes specified for
			 * the authenticator.  If we already have it,
			 * go read it in.
			 */
			if (omapi_connection_require(connection,
						     p->message->authlen)
			    == ISC_R_SUCCESS)
				goto signature_wait;
			break;
		}

		/*
		 * Allocate a buffer for the name.
		 */
		result = omapi_data_newstring(&p->name, nlen,
					      "omapi_protocol_signal_handler");
		if (result != ISC_R_SUCCESS) {
			omapi_disconnect(connection, OMAPI_FORCE_DISCONNECT);
			return (result);
		}
		p->state = omapi_protocol_name_wait;
		if (omapi_connection_require(connection, nlen) !=
		    ISC_R_SUCCESS)
			break;

		/*
		 * If it's already here, fall through.
		 * */
					     
	case omapi_protocol_name_wait:
		result = omapi_connection_copyout(p->name->value, connection,
						  p->name->len);
		if (result != ISC_R_SUCCESS) {
			omapi_disconnect(connection, OMAPI_FORCE_DISCONNECT);
			return (result);
		}

		/*
		 * Wait for a 32-bit length.
		 */
		p->state = omapi_protocol_value_length_wait;
		if (omapi_connection_require(connection, 4) != ISC_R_SUCCESS)
			break;

		/*
		 * If it's already here, fall through.
		 */

	case omapi_protocol_value_length_wait:
		omapi_connection_getuint32(connection, &vlen);

		/*
		 * Zero-length values are allowed - if we get one, we
		 * don't have to read any data for the value - just
		 * get the next one, if there is a next one.
		 */
		if (vlen == 0)
			goto insert_new_value;

		result = omapi_data_new(&p->value,
					      omapi_datatype_data, vlen,
					      "omapi_protocol_signal_handler");
		if (result != ISC_R_SUCCESS) {
			omapi_disconnect(connection, OMAPI_FORCE_DISCONNECT);
			return (result);
		}

		p->state = omapi_protocol_value_wait;
		if (omapi_connection_require(connection, vlen) != ISC_R_SUCCESS)
			break;
		/*
		 * If it's already here, fall through.
		 */
					     
	case omapi_protocol_value_wait:
		result = omapi_connection_copyout(p->value->u.buffer.value,
						  connection,
						  p->value->u.buffer.len);
		if (result != ISC_R_SUCCESS) {
			omapi_disconnect(connection, OMAPI_FORCE_DISCONNECT);
			return (result);
		}

	insert_new_value:
		if (p->reading_message_values != 0) {
			result = omapi_set_value((omapi_object_t *)p->message,
						 p->message->id_object,
						 p->name, p->value);
		} else {
			if (p->message->object == NULL) {
				/*
				 * We need a generic object to hang off of the
				 * incoming message.
				 */
				result = omapi_generic_new(&p->message->object,
					      "omapi_protocol_signal_handler");
				if (result != ISC_R_SUCCESS) {
					omapi_disconnect(connection,
						       OMAPI_FORCE_DISCONNECT);
					return (result);
				}
			}
			result = (omapi_set_value
				  ((omapi_object_t *)p->message->object,
				   p->message->id_object,
				   p->name, p->value));
		}
		if (result != ISC_R_SUCCESS) {
			omapi_disconnect(connection, OMAPI_FORCE_DISCONNECT);
			return (result);
		}
		omapi_data_stringdereference(&p->name,
					      "omapi_protocol_signal_handler");
		omapi_data_dereference(&p->value,
				       "omapi_protocol_signal_handler");
		goto need_name_length;

	signature_wait:
	case omapi_protocol_signature_wait:
		result = omapi_data_new(&p->message->authenticator,
					omapi_datatype_data,
					p->message->authlen);

		if (result != ISC_R_SUCCESS) {
			omapi_disconnect(connection, OMAPI_FORCE_DISCONNECT);
			return (result);
		}
		result = (omapi_connection_copyout
			  (p->message->authenticator->u.buffer.value,
			   connection, p->message->authlen));
		if (result != ISC_R_SUCCESS) {
			omapi_disconnect(connection, OMAPI_FORCE_DISCONNECT);
			return (result);
		}

		/* XXXTL now do something to verify the signature. */

		/*
		 * Process the message.
		 */
	message_done:
		result = omapi_message_process((omapi_object_t *)p->message,
					       h);
		if (result != ISC_R_SUCCESS) {
			omapi_disconnect(connection, OMAPI_FORCE_DISCONNECT);
			return (result);
		}

		/* XXXTL unbind the authenticator. */
		OBJECT_DEREF(&p->message, "omapi_protocol_signal_handler");

		/*
		 * Now wait for the next message.
		 */
		goto to_header_wait;		

	default:
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "unknown state in "
				 "omapi_protocol_signal_handler: %d\n",
				 p->state);

		break;
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_protocol_set_value(omapi_object_t *h, omapi_object_t *id,
			 omapi_data_string_t *name, omapi_typed_data_t *value)
{
	REQUIRE(h != NULL && h->type == omapi_type_protocol);

	if (h->inner != NULL && h->inner->type->set_value != NULL)
		return (*(h->inner->type->set_value))(h->inner, id,
						      name, value);
	return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_protocol_get_value(omapi_object_t *h, omapi_object_t *id,
			 omapi_data_string_t *name,
			 omapi_value_t **value)
{
	REQUIRE(h != NULL && h->type == omapi_type_protocol);
	
	if (h->inner != NULL && h->inner->type->get_value != NULL)
		return (*(h->inner->type->get_value))(h->inner, id,
						      name, value);
	return (ISC_R_NOTFOUND);
}

void
omapi_protocol_destroy(omapi_object_t *h, const char *name) {
	omapi_protocol_object_t *p;

	REQUIRE(h != NULL && h->type == omapi_type_protocol);

	p = (omapi_protocol_object_t *)h;

	if (p->message != NULL)
		OBJECT_DEREF(&p->message, name);

	if (p->authinfo != NULL)
		OBJECT_DEREF(&p->authinfo, name);
}

/*
 * Write all the published values associated with the object through the
 * specified connection.
 */

isc_result_t
omapi_protocol_stuff_values(omapi_object_t *c, omapi_object_t *id,
			    omapi_object_t *h)
{
	REQUIRE(h != NULL && h->type == omapi_type_protocol);

	if (h->inner != NULL && h->inner->type->stuff_values != NULL)
		return (*(h->inner->type->stuff_values))(c, id, h->inner);
	return (ISC_R_SUCCESS);
}

/*
 * Set up a listener for the omapi protocol.    The handle stored points to
 * a listener object, not a protocol object.
 */

isc_result_t
omapi_protocol_listen(omapi_object_t *h, int port, int max) {
	isc_result_t result;
	omapi_protocol_listener_object_t *obj;

	obj = isc_mem_get(omapi_mctx, sizeof(*obj));
	if (obj == NULL)
		return (ISC_R_NOMEMORY);
	memset(obj, 0, sizeof(*obj));
	obj->object_size = sizeof(*obj);
	obj->refcnt = 1;
	obj->type = omapi_type_protocol_listener;

	OBJECT_REF(&h->outer, obj, "omapi_protocol_listen");
	OBJECT_REF(&obj->inner, h, "omapi_protocol_listen");

	result = omapi_listener_listen((omapi_object_t *)obj, port, max);

	OBJECT_DEREF(&obj, "omapi_protocol_listen");
	return (result);
}

/*
 * Signal handler for protocol listener - if we get a connect signal,
 * create a new protocol connection, otherwise pass the signal down.
 */

isc_result_t
omapi_protocol_listener_signal(omapi_object_t *h, const char *name, va_list ap)
{
	isc_result_t result;
	omapi_object_t *c;
	omapi_protocol_object_t *obj;
	omapi_protocol_listener_object_t *p;

	REQUIRE(h != NULL && h->type == omapi_type_protocol_listener);

	p = (omapi_protocol_listener_object_t *)h;

	/*
	 * Not a signal we recognize?
	 */
	if (strcmp(name, "connect") != 0) {
		if (p->inner != NULL && p->inner->type->signal_handler != NULL)
			return (*(p->inner->type->signal_handler))(p->inner,
								   name, ap);
		return (ISC_R_NOTFOUND);
	}

	c = va_arg(ap, omapi_object_t *);

	INSIST(c != NULL && c->type == omapi_type_connection);

	obj = isc_mem_get(omapi_mctx, sizeof(*obj));
	if (obj == NULL)
		return (ISC_R_NOMEMORY);
	memset(obj, 0, sizeof(*obj));
	obj->object_size = sizeof(*obj);
	obj->refcnt = 1;
	obj->type = omapi_type_protocol;

	OBJECT_REF(&obj->outer, c, "omapi_protocol_accept");
	OBJECT_REF(&c->inner, obj, "omapi_protocol_accept");

	/*
	 * Send the introductory message.
	 */
	result = omapi_protocol_send_intro((omapi_object_t *)obj,
					   OMAPI_PROTOCOL_VERSION,
					   sizeof(omapi_protocol_header_t));

	if (result != ISC_R_SUCCESS)
		omapi_disconnect(c, OMAPI_FORCE_DISCONNECT);

	OBJECT_DEREF(&obj, "omapi_protocol_accept");
	return (result);
}

isc_result_t
omapi_protocol_listener_set_value(omapi_object_t *h, omapi_object_t *id,
				  omapi_data_string_t *name,
				  omapi_typed_data_t *value)
{
	REQUIRE(h != NULL && h->type == omapi_type_protocol_listener);

	if (h->inner != NULL && h->inner->type->set_value != NULL)
		return (*(h->inner->type->set_value))(h->inner, id,
						      name, value);
	return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_protocol_listener_get_value(omapi_object_t *h, omapi_object_t *id,
				  omapi_data_string_t *name,
				  omapi_value_t **value)
{
	REQUIRE(h != NULL && h->type == omapi_type_protocol_listener);

	if (h->inner != NULL && h->inner->type->get_value != NULL)
		return (*(h->inner->type->get_value))(h->inner, id,
						      name, value);
	return (ISC_R_NOTFOUND);
}

void
omapi_protocol_listener_destroy(omapi_object_t *h, const char *name) {
	REQUIRE(h != NULL && h->type == omapi_type_protocol_listener);

	(void)name;		/* Unused. */
}

/*
 * Write all the published values associated with the object through the
 * specified connection.
 */

isc_result_t
omapi_protocol_listener_stuff(omapi_object_t *c, omapi_object_t *id,
			      omapi_object_t *h)
{

	REQUIRE(h != NULL && h->type == omapi_type_protocol_listener);

	if (h->inner != NULL && h->inner->type->stuff_values != NULL)
		return (*(h->inner->type->stuff_values)) (c, id, h->inner);
	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_protocol_send_status(omapi_object_t *po, omapi_object_t *id,
			   isc_result_t waitstatus,
			   unsigned int rid, const char *msg)
{
	isc_result_t result;
	omapi_object_t *message = NULL;

	REQUIRE(po != NULL && po->type == omapi_type_protocol);

	result = omapi_message_new(&message, "omapi_protocol_send_status");
	if (result != ISC_R_SUCCESS)
		return (result);

	result = omapi_set_int_value(message, NULL, "op", OMAPI_OP_STATUS);

	if (result == ISC_R_SUCCESS)
		result = omapi_set_int_value(message, NULL, "rid", (int)rid);

	if (result == ISC_R_SUCCESS)
		result = omapi_set_int_value(message, NULL, "result",
					     (int)waitstatus);

	/*
	 * If a message has been provided, send it.
	 */
	if (result == ISC_R_SUCCESS && msg != NULL)
		result = omapi_set_string_value(message, NULL, "message", msg);

	if (result != ISC_R_SUCCESS) {
		OBJECT_DEREF(&message, "omapi_protocol_send_status");
		return (result);
	}

	return (omapi_protocol_send_message(po, id, message, NULL));
}

isc_result_t
omapi_protocol_send_update(omapi_object_t *po, omapi_object_t *id,
			   unsigned int rid, omapi_object_t *object)
{
	isc_result_t result;
	omapi_object_t *message = NULL;

	REQUIRE(po != NULL && po->type == omapi_type_protocol);

	result = omapi_message_new(&message, "omapi_protocol_send_update");
	if (result != ISC_R_SUCCESS)
		return (result);

	result = omapi_set_int_value(message, NULL, "op", OMAPI_OP_UPDATE);

	if (result == ISC_R_SUCCESS && rid != 0) {
		omapi_handle_t handle;

		result = omapi_set_int_value(message, NULL, "rid", (int)rid);

		if (result == ISC_R_SUCCESS)
			result = omapi_object_handle(&handle, object);

		if (result == ISC_R_SUCCESS)
			result = omapi_set_int_value(message, NULL,
						     "handle", (int)handle);
	}		
		
	if (result == ISC_R_SUCCESS)
		result = omapi_set_object_value(message, NULL,
						"object", object);

	if (result != ISC_R_SUCCESS) {
		OBJECT_DEREF(&message, "dhcpctl_open_object");
		return (result);
	}

	return (omapi_protocol_send_message(po, id, message, NULL));
}
