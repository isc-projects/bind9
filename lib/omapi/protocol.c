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
 * Functions supporting the object management protocol.
 */
#include <stddef.h>		/* NULL */
#include <stdlib.h>		/* random */
#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/error.h>

#include <omapi/private.h>

/*
 * OMAPI protocol header, version 1.00
 */
typedef struct omapi_protocolheader {
	unsigned int	authlen; /* Length of authenticator. */
	unsigned int	authid;	 /* Authenticator object ID. */
	unsigned int	op;	 /* Operation code. */
	omapi_handle_t	handle;	 /* Handle of object being operated on or 0. */
	unsigned int	id;	 /* Transaction ID. */
	unsigned int	rid;	 /* ID of transaction responding to. */
} omapi_protocolheader_t;

isc_result_t
omapi_protocol_connect(omapi_object_t *h, const char *server_name,
		       int port, omapi_object_t *authinfo)
{
	isc_result_t result;
	omapi_protocol_t *obj = NULL;

	REQUIRE(h != NULL && server_name != NULL);
	REQUIRE(port != 0);

	result = omapi_object_create((omapi_object_t **)&obj,
				     omapi_type_protocol, sizeof(*obj));
	if (result != ISC_R_SUCCESS)
		return (result);

	OBJECT_REF(&h->outer, obj);
	OBJECT_REF(&obj->inner, h);

	/*
	 * Drop this function's direct reference to the protocol object
	 * so that connect_toserver or send_intro can free the connection
	 * and protocol objects in the event of an error.
	 */
	OBJECT_DEREF(&obj);

	result = connect_toserver(h->outer, server_name, port);

	/*
	 * Send the introductory message.  This will also wait (via
	 * connection_send) for the server's introductory message before
	 * proceeding.  While the original design for OMAPI declared that this
	 * was to be entirely asynchronous, it just won't work for the client
	 * side program to go storming ahead, making calls that try to use the
	 * connection object, when it is possible that the thread that reads
	 * the socket will wake up with the server's intro message, find some
	 * sort of problem, and then blow away the connection object while the
	 * client program is asynchronously trying to use it.  (This could be
	 * done, of course, with a lot more thread locking than currently
	 * happens.)
	 *
	 * If send_intro fails, the connection is already destroyed.
  	 */
	if (result == ISC_R_SUCCESS)
		result = send_intro(h->outer, OMAPI_PROTOCOL_VERSION);

	if (authinfo != NULL)
		OBJECT_REF(&((omapi_protocol_t *)h->outer)->authinfo,authinfo);

	return (result);
}

void
omapi_protocol_disconnect(omapi_object_t *handle, isc_boolean_t force) {
	omapi_protocol_t *protocol;
	omapi_connection_t *connection;

	REQUIRE(handle != NULL);

	protocol = (omapi_protocol_t *)handle->outer;

	if (protocol == NULL)
		return;		/* Already disconnected. */

	INSIST(protocol->type == omapi_type_protocol);

	connection = (omapi_connection_t *)protocol->outer;

	INSIST(connection != NULL &&
	       connection->type == omapi_type_connection);

	omapi_connection_disconnect((omapi_object_t *)connection, force);
}

/*
 * Send the protocol introduction message.
 */
isc_result_t
send_intro(omapi_object_t *h, unsigned int ver) {
	isc_result_t result;
	omapi_protocol_t *p;
	omapi_connection_t *connection;

	REQUIRE(h != NULL && h->type == omapi_type_protocol);
	REQUIRE(h->outer != NULL && h->outer->type == omapi_type_connection);

	p = (omapi_protocol_t *)h;
	connection = (omapi_connection_t *)h->outer;

	result = omapi_connection_putuint32((omapi_object_t *)connection, ver);

	if (result == ISC_R_SUCCESS)
		result =
		    omapi_connection_putuint32((omapi_object_t *)connection,
					       sizeof(omapi_protocolheader_t));

	/*
	 * Require the other end to send an intro - this kicks off the
	 * protocol input state machine.  This does not use connection_require
	 * to set the number of bytes required because then a socket recv would
	 * be queued.  To simplify the MT issues, the library only expects to
	 * have one task outstanding at a time, so the number of bytes
	 * that will be expected is set here, but the actual recv for
	 * them is not queued until after the send event posts.
	 */
	if (result == ISC_R_SUCCESS) {
		p->state = omapi_protocol_intro_wait;
		connection->bytes_needed = 8;

		/*
		 * Make up an initial transaction ID for this connection.
		 * XXXDCL better generator than random()?
		 */
		p->next_xid = random();

		result = connection_send(connection);

		/*
		 * The client waited for the result; the server did not.
		 * The server's result will always be ISC_R_SUCCESS.
		 *
		 * If the client's result is not ISC_R_SUCCESS, the connection
		 * was already closed by the socket event handler that got
		 * the error.
		 */
	} else
		/*
		 * One of the calls to omapi_connection_put* failed.  As of the
		 * time of writing this comment, that would pretty much only
		 * happen if the required output buffer space could be
		 * dynamically allocated.
		 *
		 * The server is in listener_accept, so the connection can just
		 * be freed right here; listener_accept will not try to
		 * use it when this function exits.
		 *
		 * The client is in omapi_protocol_connect, its driving thread.
		 * It too has no events pending, so the connection will
		 * be freed.
		 */
		omapi_connection_disconnect(h->outer, OMAPI_FORCE_DISCONNECT);

	return (result);
}

/*
 * Set up a listener for the omapi protocol.
 */
isc_result_t
omapi_protocol_listen(omapi_object_t *manager, isc_sockaddr_t *addr,
		      dns_acl_t *acl, int max,
		      isc_taskaction_t destroy_action, void *destroy_arg)
{
	return (omapi_listener_listen((omapi_object_t *)manager, addr,
				      acl, max, destroy_action, destroy_arg));
}

isc_result_t
send_status(omapi_object_t *po, isc_result_t waitstatus,
	    unsigned int rid, const char *msg)
{
	isc_result_t result;
	omapi_object_t *message = NULL;

	REQUIRE(po != NULL && po->type == omapi_type_protocol);
	REQUIRE(po->outer != NULL && po->outer->type == omapi_type_connection);
	REQUIRE(! ((omapi_connection_t *)po->outer)->is_client);

	result = omapi_message_create(&message);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = omapi_object_setinteger(message, "op", OMAPI_OP_STATUS);

	if (result == ISC_R_SUCCESS)
		result = omapi_object_setinteger(message, "rid", (int)rid);

	if (result == ISC_R_SUCCESS)
		result = omapi_object_setinteger(message, "result",
						 (int)waitstatus);

	/*
	 * If a message has been provided, send it.
	 */
	if (result == ISC_R_SUCCESS && msg != NULL)
		result = omapi_object_setstring(message, "message", msg);

	if (result == ISC_R_SUCCESS)
		result = omapi_message_send(message, po);

	OBJECT_DEREF(&message);

	return (result);
}

isc_result_t
send_update(omapi_object_t *po, unsigned int rid, omapi_object_t *object) {
	isc_result_t result;
	omapi_object_t *message = NULL;

	REQUIRE(po != NULL && po->type == omapi_type_protocol);
	REQUIRE(! ((omapi_connection_t *)po->outer)->is_client);

	result = omapi_message_create(&message);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = omapi_object_setinteger(message, "op", OMAPI_OP_UPDATE);

	if (result == ISC_R_SUCCESS && rid != 0) {
		omapi_handle_t handle;

		result = omapi_object_setinteger(message, "rid", (int)rid);

		if (result == ISC_R_SUCCESS)
			result = object_gethandle(&handle, object);

		if (result == ISC_R_SUCCESS)
			result = omapi_object_setinteger(message, "handle",
							 (int)handle);
	}		
		
	if (result == ISC_R_SUCCESS)
		result = omapi_object_setobject(message, "object", object);

	if (result == ISC_R_SUCCESS)
		result = omapi_message_send(message, po);

	OBJECT_DEREF(&message);

	return (result);
}

static isc_result_t
dispatch_messages(omapi_protocol_t *protocol,
		  omapi_connection_t *connection)
{
	isc_uint16_t nlen;
	isc_uint32_t vlen;
	isc_result_t result;

	/*
	 * XXXDCL figure out how come when this function throws
	 * an error, it does not seem to be seen by the driving program.
	 * (this comment may no longer be true, but bears testing anyway)
	 */

	/*
	 * We get here because we requested that we be woken up after
	 * some number of bytes were read, and that number of bytes
	 * has in fact been read.
	 */
	switch (protocol->state) {
	case omapi_protocol_intro_wait:
		/*
		 * Get protocol version and header size in network byte order.
		 */
		connection_getuint32(connection, &protocol->protocol_version);
		connection_getuint32(connection, &protocol->header_size);
	
		/*
		 * Currently only the current protocol version is supported.
		 */
		if (protocol->protocol_version != OMAPI_PROTOCOL_VERSION)
			return (OMAPI_R_VERSIONMISMATCH);

		if (protocol->header_size < sizeof(omapi_protocolheader_t))
			return (OMAPI_R_PROTOCOLERROR);

		/*
		 * The next thing that shows up on incoming connections
		 * should be a message header.
		 */
		protocol->state = omapi_protocol_header_wait;

		/*
		 * The client needs to have bytes_needed primed for the
		 * size of a message header, so that when send_done runs,
		 * it can kick off an isc_socket_recv (via connection_require)
		 * to get the server's response.  It does this in
		 * omapi_message_send, so nothing need be done here now.
		 *
		 * The server needs to actually kick off its recv now to
		 * be ready for the first message from the client.  The
		 * server's startup path looks like this:
		 * 1 server sends intro, bytes_needed is set to intro size (8).
		 * 2 send_done posts, recv of 8 for intro is queued.
		 * 3 recv_done posts, calls the protocol_signalhandler and
		 *	ends up here.
		 */
		if (connection->is_client) {
			result = OMAPI_R_NOTYET;
			break;
		}

		/*
		 * Register a need for the number of bytes in a header, and if
		 * that many are here already, process them immediately.
		 */
		result = connection_require(connection, protocol->header_size);
		if (result != ISC_R_SUCCESS)
			break;

		/* FALLTHROUGH */

	case omapi_protocol_header_wait:
		result = omapi_message_create((omapi_object_t **)
					      &protocol->message);
		if (result != ISC_R_SUCCESS)
			break;

		if (protocol->key != NULL) {
			protocol->verify_result =
				dst_verify(DST_SIGMODE_INIT, protocol->key,
					   &protocol->dstctx, NULL, NULL);
			protocol->dst_update = ISC_TRUE;
		}

		/*
		 * Fetch the header values.
		 */
		/* XXXDCL authid is unused */
		connection_getuint32(connection, &protocol->message->authid);
		/* XXXTL bind the authenticator here! */
		connection_getuint32(connection, &protocol->message->authlen);
		connection_getuint32(connection, &protocol->message->op);
		connection_getuint32(connection, &protocol->message->h);
		connection_getuint32(connection, &protocol->message->id);
		connection_getuint32(connection, &protocol->message->rid);

		/*
		 * If there was any extra header data, skip over it,
		 * because it has no use in this version of the protocol.
		 */
		if (protocol->header_size > sizeof(omapi_protocolheader_t))
			connection_copyout(NULL, connection,
					   (protocol->header_size -
					    sizeof(omapi_protocolheader_t)));

		/*
		 * XXXTL must compute partial signature across the preceding
		 * bytes.  Also, if authenticator specifies encryption as well
		 * as signing, we may have to decrypt the data on the way in.
		 */

		/*
		 * After reading the header, first read in message-specific
		 * values, then object values.
		 */
		protocol->reading_message_values = ISC_TRUE;

	need_name_length:
		/*
		 * Need to get the 16-bit length of the value's name.
		 */
		protocol->state = omapi_protocol_name_length_wait;
		result = connection_require(connection, 2);
		if (result != ISC_R_SUCCESS)
			break;

		/* FALLTHROUGH */
	case omapi_protocol_name_length_wait:
		connection_getuint16(connection, &nlen);

		/*
		 * A zero-length name signals the end of name+value pairs.
		 */
		if (nlen == 0) {
			/*
			 * If the message values were being read, now
			 * the object values need to be read.  Otherwise
			 * move on to reading the authenticator.
			 */
			if (protocol->reading_message_values) {
				protocol->reading_message_values = ISC_FALSE;
				/*
				 * The goto could be removed by setting the
				 * state and doing omapi_connection_require()
				 * here, then returning the result to
				 * protocol_signalhandler which would call
				 * this function immediately if the result
				 * was ISC_R_SUCCESS, but that seems even
				 * more obtuse than using goto.
				 */
				goto need_name_length;
			}

			/*
			 * If the authenticator length is zero, there's no
			 * signature to read in, so go straight to processing
			 * the message.
			 */
			if (protocol->message->authlen == 0)
				goto message_done;

			/*
			 * The next thing that is expected is the message
			 * signature.
			 */
			protocol->state = omapi_protocol_signature_wait;

			/* Wait for the number of bytes specified for the
			 * authenticator.  If they are all here, go read it in.
			 * As noted above, the goto could be removed by
			 * returning the result to the caller no matter
			 * what its value, because the protocol_signalhandler
			 * would just call this function right back, but
			 * something seems more obtuse about that than goto.
			 */
			result = connection_require(connection,
						   protocol->message->authlen);
			if (result == ISC_R_SUCCESS)
				goto signature_wait;
			else
				break;
		}

		/*
		 * Non-zero name length.  Allocate a buffer for the name
		 * then wait for all its bytes to be available.
		 */
		result = omapi_string_create(&protocol->name, nlen);
		if (result != ISC_R_SUCCESS)
			break;

		protocol->state = omapi_protocol_name_wait;
		result = connection_require(connection, nlen);
		if (result != ISC_R_SUCCESS)
			break;

		/* FALLTHROUGH */
	case omapi_protocol_name_wait:
		connection_copyout(protocol->name->value, connection,
				   protocol->name->len);

		/*
		 * Wait for the 32-bit length of the value.
		 */
		protocol->state = omapi_protocol_value_length_wait;
		result = connection_require(connection, 4);
		if (result != ISC_R_SUCCESS)
			break;

		/* FALLTHROUGH */
	case omapi_protocol_value_length_wait:
		connection_getuint32(connection, &vlen);

		/*
		 * Zero-length values are allowed; they are for deleted
		 * values.  If the value length is zero, skip the read but
		 * still store the name with its zero length value.
		 */
		if (vlen == 0)
			goto insert_new_value;

		result = omapi_data_create(&protocol->value,
					   omapi_datatype_data, vlen);
		if (result != ISC_R_SUCCESS)
			break;

		/*
		 * Check to see if all the bytes of the value are here.
		 */
		protocol->state = omapi_protocol_value_wait;
		result = connection_require(connection, vlen);
		if (result != ISC_R_SUCCESS)
			break;

		/* FALLTHROUGH */
	case omapi_protocol_value_wait:
		connection_copyout(protocol->value->u.buffer.value,
				   connection,
				   protocol->value->u.buffer.len);

		/*
		 * Silence the gcc message "warning: `result' might be used
		 * uninitialized in this function"
		 */
		result = ISC_R_SUCCESS;

	insert_new_value:

		if (protocol->reading_message_values)
			result = omapi_object_set((omapi_object_t *)
						  protocol->message,
						  protocol->name,
						  protocol->value);

		else {
			if (protocol->message->object == NULL) {
				/*
				 * Create a generic object to receive the
				 * values of the object in the incoming
				 * message.
				 */
				result = omapi_object_create(&protocol->
							     message->object,
							     NULL, 0);
				if (result != ISC_R_SUCCESS)
					break;
			}

			result = omapi_object_set((omapi_object_t *)
						  protocol->message->object,
						  protocol->name,
						  protocol->value);
		}
		if (result != ISC_R_SUCCESS)
			break;

		omapi_string_dereference(&protocol->name);
		omapi_data_dereference(&protocol->value);

		goto need_name_length;

	signature_wait:
	case omapi_protocol_signature_wait:
		result = omapi_data_create(&protocol->message->authenticator,
					   omapi_datatype_data,
					   protocol->message->authlen);

		if (result != ISC_R_SUCCESS)
			return (result);

		/*
		 * Turn off the dst_verify updating while the signature
		 * bytes are copied; they are not part of what was signed.
		 */
		protocol->dst_update = ISC_FALSE;

		connection_copyout(protocol->message->authenticator->
				   u.buffer.value,
				   connection,
				   protocol->message->authlen);

		protocol->signature_in.base =
			protocol->message->authenticator->u.buffer.value;
		protocol->signature_in.length = protocol->message->authlen;

		/* XXXTL now do something to verify the signature. */

		/* FALLTHROUGH */
	message_done:
		/*
		 * Hail, hail, the gang's all here!  The whole message
		 * has been read in, so process it.  Even if an error
		 * is returned, a bit of cleanup has to be done, but
		 * it can't muck with the result assigned here.
		 */
		result = message_process((omapi_object_t *)protocol->message,
					 (omapi_object_t *)protocol);

		/* XXXTL unbind the authenticator. */

		/*
		 * Free the message object.
		 */
		OBJECT_DEREF(&protocol->message);

		/*
		 * The next thing the protocol reads will be a new message.
		 */
		protocol->state = omapi_protocol_header_wait;

		/*
		 * Now, if message_process had indicated an error, let it be
		 * returned from here.
		 */
		if (result != ISC_R_SUCCESS)
			break;

		/*
		 * The next recv will be queued from send_done.  On the
		 * server, this will be after it has sent its reply to the
		 * just-processed message by using omapi_message_send.
		 * On the client it will happen after it sends its
		 * next message with omapi_message_send.
		 *
		 * The OMAPI_R_NOTYET return value tells protocol_signalhandler
		 * that to return ISC_R_SUCCESS back to recv_done.
		 */
		result = OMAPI_R_NOTYET;
		break;

	default:
		UNEXPECTED_ERROR(__FILE__, __LINE__, "unknown state in "
				 "omapi_protocol_signal_handler: %d",
				 protocol->state);
		result = ISC_R_UNEXPECTED;
		break;
	}

	return (result);
}

static isc_result_t
protocol_signalhandler(omapi_object_t *h, const char *name, va_list ap) {
	isc_result_t result;
	omapi_protocol_t *p;
	omapi_object_t *connection;
	omapi_connection_t *c;

	REQUIRE(h != NULL && h->type == omapi_type_protocol);

	p = (omapi_protocol_t *)h;
	c = (omapi_connection_t *)p->outer;

	/*
	 * Not a signal we recognize?
	 */
	if (strcmp(name, "ready") != 0)
		return (omapi_object_passsignal(h, name, ap));

	INSIST(p->outer != NULL && p->outer->type == omapi_type_connection);

	connection = p->outer;

	do {
		result = dispatch_messages(p, c);
	} while (result == ISC_R_SUCCESS);

	/*
	 * Getting "not yet" means more data is needed before another message
	 * can be processed.
	 */
	if (result == OMAPI_R_NOTYET)
		result = ISC_R_SUCCESS;

	return (result);
}

static isc_result_t
protocol_setvalue(omapi_object_t *h, omapi_string_t *name, omapi_data_t *value)
{
	omapi_protocol_t *p;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(h != NULL && h->type == omapi_type_protocol);

	p = (omapi_protocol_t *)h;

	if (omapi_string_strcmp(name, "auth-name") == 0) {
		p->authname = omapi_data_strdup(omapi_mctx, value);
		if (p->authname == NULL)
			return (ISC_R_NOMEMORY);

	} else if (omapi_string_strcmp(name, "auth-algorithm") == 0) {
		p->algorithm = omapi_data_getint(value);
		if (p->algorithm == 0)
			/*
			 * XXXDCL better error?
			 */
			return (DST_R_UNSUPPORTEDALG);

	} else
		return (omapi_object_passsetvalue(h, name, value));

	/*
	 * XXXDCL if either auth-name or auth-algorithm is not in the incoming
	 * message, then the client will not get a meaningful error message
	 * in reply.  this is bad.
	 *
	 * ... it is a general problem in the current omapi design ...
	 */
	if (p->authname != NULL && p->algorithm != 0) {
		unsigned int sigsize;

		result = auth_makekey(p->authname, p->algorithm, &p->key);

		if (result == ISC_R_SUCCESS)
			result = dst_sig_size(p->key, &sigsize);

		if (result == ISC_R_SUCCESS)
			result = isc_buffer_allocate(omapi_mctx,
						     &p->signature_out,
						     sigsize,
						     ISC_BUFFERTYPE_GENERIC);

		if (result != ISC_R_SUCCESS) {
			if (p->key != NULL)
				dst_key_free(p->key);
			isc_mem_put(omapi_mctx, p->authname,
				    strlen(p->authname) + 1);
			p->authname = NULL;
			p->algorithm = 0;
			p->key = NULL;
		}
	}

	return (result);
}

static isc_result_t
protocol_getvalue(omapi_object_t *h, omapi_string_t *name,
		  omapi_value_t **value)
{
	REQUIRE(h != NULL && h->type == omapi_type_protocol);
	
	return (omapi_object_passgetvalue(h, name, value));
}

static void
protocol_destroy(omapi_object_t *h) {
	omapi_protocol_t *p;

	REQUIRE(h != NULL && h->type == omapi_type_protocol);

	p = (omapi_protocol_t *)h;

	if (p->message != NULL)
		OBJECT_DEREF(&p->message);

	if (p->authinfo != NULL)
		OBJECT_DEREF(&p->authinfo);

	if (p->authname != NULL) {
		isc_mem_put(omapi_mctx, p->authname, strlen(p->authname) + 1);
		p->authname = NULL;
	}

	if (p->signature_out != NULL) {
		isc_buffer_free(&p->signature_out);
		p->signature_out = NULL;
	}

	if (p->key != NULL) {
		dst_key_free(p->key);
		p->key = NULL;
	}
}

static isc_result_t
protocol_stuffvalues(omapi_object_t *connection, omapi_object_t *h) {
	REQUIRE(h != NULL && h->type == omapi_type_protocol);

	return (omapi_object_passstuffvalues(connection, h));
}

isc_result_t
protocol_init(void) {
	return (omapi_object_register(&omapi_type_protocol, "protocol",
				      protocol_setvalue,
				      protocol_getvalue,
				      protocol_destroy,
				      protocol_signalhandler,
				      protocol_stuffvalues,
				      NULL, NULL, NULL));
}
