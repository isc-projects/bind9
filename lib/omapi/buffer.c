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

/* $Id: buffer.c,v 1.3 2000/01/04 20:04:37 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Buffer access functions for the object management protocol.
 */
#include <errno.h>
#include <stddef.h>		/* NULL */
#include <unistd.h>		/* read */

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/socket.h>

#include <omapi/private.h>

void
omapi_connection_read(isc_task_t *task, isc_event_t *event) {
	isc_buffer_t *buffer;
	isc_socket_t *socket;
	isc_socketevent_t *socketevent;
	omapi_connection_object_t *connection;

	socket = event->sender;
	socketevent = (isc_socketevent_t *)event;
	connection = event->arg;

	buffer = ISC_LIST_HEAD(socketevent->bufferlist);

	if (socketevent->result != ISC_R_SUCCESS) {
		/*
		 * Abandon this socket.
		 */
		isc_socket_detach(&socket);

		/* XXXDCL nope, not right at all */
		ISC_LIST_UNLINK(socketevent->bufferlist, buffer, link);
		isc_buffer_free(&buffer);

		isc_event_free(&event);
		isc_task_shutdown(task);
		return;
	}

	connection->in_bytes += socketevent->n;

	/* XXXDCL more screwage */
	while (buffer != NULL) {
		ISC_LIST_APPEND(connection->input_buffers, buffer, link);
		buffer = ISC_LIST_NEXT(buffer, link);
	}

	while (connection->bytes_needed <= connection->in_bytes)
		omapi_signal(event->arg, "ready", connection);

	/*
	 * Queue up another recv task.
	 */
	isc_socket_recvv(socket, &connection->input_buffers,
			 connection->bytes_needed - connection->in_bytes,
			 task, omapi_connection_read, connection);

	isc_event_free(&event);

}

void
omapi_connection_written(isc_task_t *task, isc_event_t *event) {
	isc_buffer_t *buffer;
	isc_socket_t *socket;
	isc_socketevent_t *socketevent;
	omapi_connection_object_t *connection;

	socket = event->sender;
	socketevent = (isc_socketevent_t *)event;
	connection = event->arg;

	/* XXXDCL more screwage */
	buffer = ISC_LIST_HEAD(socketevent->bufferlist);
	while (buffer != NULL) {
		ISC_LIST_ENQUEUE(connection->output_buffers, buffer, link);
		buffer = ISC_LIST_NEXT(buffer, link);
	}
	buffer = ISC_LIST_HEAD(connection->output_buffers);

	if (socketevent->result != ISC_R_SUCCESS) {
		/*
		 * Abandon this socket.
		 */
		isc_socket_detach(&socket);

		/* XXXDCL nope, not right at all */
		ISC_LIST_UNLINK(connection->output_buffers, buffer, link);
		isc_buffer_free(&buffer);
		isc_event_free(&event);
		isc_task_shutdown(task);
		OBJECT_DEREF(&connection, "omapi_connection_written");
		return;
	}

	connection->out_bytes -= socketevent->n;
	isc_buffer_compact(buffer);

	if (connection->out_bytes > 0)
		isc_socket_sendv(socket, &connection->output_buffers, task,
				 omapi_connection_written, connection);

	return;
}

/*
 * Put some bytes into the output buffer for a connection.
 */
isc_result_t
omapi_connection_copyin(omapi_object_t *h, unsigned char *bufp,
			unsigned int len)
{
	omapi_connection_object_t *connection;
	isc_buffer_t *obuffer;

	REQUIRE(h != NULL && h->type == omapi_type_connection);

	connection = (omapi_connection_object_t *)h;

	obuffer = ISC_LIST_HEAD(connection->output_buffers);
	/* XXXDCL check for space first */
	isc_buffer_putmem(obuffer, bufp, len);

	connection->out_bytes += len;

	return (ISC_R_SUCCESS);
}

/*
 * Copy some bytes from the input buffer, and advance the input buffer
 * pointer beyond the bytes copied out.
 */

isc_result_t
omapi_connection_copyout(unsigned char *buf, omapi_object_t *h,
			 unsigned int size)
{
	omapi_connection_object_t *connection;
	isc_buffer_t *ibuffer;

	REQUIRE(h != NULL && h->type == omapi_type_connection);

	connection = (omapi_connection_object_t *)h;

	if (size > connection->in_bytes)
		return (ISC_R_NOMORE);
	
	ibuffer = ISC_LIST_HEAD(connection->input_buffers);

	(void)memcpy(buf, ibuffer->base, size);
	isc_buffer_forward(ibuffer, size);
	isc_buffer_compact(ibuffer);
	
	connection->in_bytes -= size;

	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_connection_get_uint32(omapi_object_t *c, isc_uint32_t *value) {
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
omapi_connection_put_uint32(omapi_object_t *c, isc_uint32_t value) {
	isc_uint32_t inbuf;

	inbuf = htonl(value);
	
	return (omapi_connection_copyin(c, (unsigned char *)&inbuf,
					sizeof(inbuf)));
}

isc_result_t
omapi_connection_get_uint16(omapi_object_t *c, isc_uint16_t *value) {
	isc_uint16_t inbuf;
	isc_result_t result;

	result = omapi_connection_copyout((unsigned char *)&inbuf, c,
					  sizeof(inbuf));
	if (result != ISC_R_SUCCESS)
		return (result);

	*value = ntohs (inbuf);
	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_connection_put_uint16(omapi_object_t *c, isc_uint32_t value) {
	isc_uint16_t inbuf;

	REQUIRE(value < 65536);

	inbuf = htons((isc_uint16_t)value);
	
	return (omapi_connection_copyin(c, (unsigned char *)&inbuf,
					sizeof(inbuf)));
}

isc_result_t
omapi_connection_write_typed_data(omapi_object_t *c, omapi_typed_data_t *data)
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
		result = omapi_connection_put_uint32(c, sizeof(isc_uint32_t));
		if (result != ISC_R_SUCCESS)
			return (result);
		return (omapi_connection_put_uint32(c, ((isc_uint32_t)
							(data->u.integer))));

	      case omapi_datatype_string:
	      case omapi_datatype_data:
		result = omapi_connection_put_uint32(c, data->u.buffer.len);
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
		result = omapi_connection_put_uint32(c, sizeof(handle));
		if (result != ISC_R_SUCCESS)
			return (result);
		return (omapi_connection_put_uint32(c, handle));
	}

	UNEXPECTED_ERROR(__FILE__, __LINE__,
			 "unknown type in omapi_connection_write_typed_data: "
			 "%d\n", data->type);
	return (ISC_R_UNEXPECTED);
}

isc_result_t
omapi_connection_put_name(omapi_object_t *c, const char *name) {
	isc_result_t result;
	unsigned int len = strlen(name);

	if (len > 65535)
		/* XXXDCL better error? */
		return (ISC_R_FAILURE);

	result = omapi_connection_put_uint16(c, len);
	if (result != ISC_R_SUCCESS)
		return (result);

	return (omapi_connection_copyin(c, (char *)name, len));
}

isc_result_t
omapi_connection_put_string(omapi_object_t *c, const char *string) {
	isc_result_t result;
	unsigned int len;

	if (string != NULL)
		len = strlen(string);
	else
		len = 0;

	result = omapi_connection_put_uint32(c, len);

	if (result == ISC_R_SUCCESS && len > 0)
		result = omapi_connection_copyin(c, (char *)string, len);
	return (result);
}

isc_result_t
omapi_connection_put_handle(omapi_object_t *c, omapi_object_t *h) {
	isc_result_t result;
	omapi_handle_t handle;

	if (h != NULL) {
		result = omapi_object_handle(&handle, h);
		if (result != ISC_R_SUCCESS)
			return (result);
	} else
		handle = 0;	/* The null handle. */

	result = omapi_connection_put_uint32(c, sizeof(handle));

	if (result == ISC_R_SUCCESS)
		result = omapi_connection_put_uint32(c, handle);

	return (result);
}
