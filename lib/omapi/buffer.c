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

/* $Id: buffer.c,v 1.2 1999/11/02 04:01:31 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Buffer access functions for the object management protocol.
 */
#include <errno.h>
#include <stddef.h>		/* NULL */
#include <unistd.h>		/* read */

#include <isc/assertions.h>
#include <isc/error.h>

#include <omapi/omapip_p.h>

/*
 * Make sure that at least len bytes are in the input buffer, and if not,
 * read enough bytes to make up the difference.
 */

isc_result_t
omapi_connection_reader(omapi_object_t *h) {
	omapi_buffer_t *buffer;
	isc_result_t result;
	unsigned int read_len;
	int read_status;
	omapi_connection_object_t *c;
	unsigned int bytes_to_read;

	REQUIRE(h != NULL && h->type == omapi_type_connection);

	c = (omapi_connection_object_t *)h;

	/*
	 * See if there are enough bytes.
	 */
	if (c->in_bytes >= OMAPI_BUFFER_SIZE - 1 &&
	    c->in_bytes > c->bytes_needed)
		return (ISC_R_SUCCESS);

	if (c->inbufs) {
		for (buffer = c->inbufs; buffer->next; buffer = buffer->next)
			;
		if (BUFFER_BYTES_FREE(buffer) == 0) {
			result = omapi_buffer_new(&buffer->next,
						  "omapi_private_read");
			if (result != ISC_R_SUCCESS)
				return (result);
			buffer = buffer->next;
		}

	} else {
		result = omapi_buffer_new(&c->inbufs, "omapi_private_read");
		if (result != ISC_R_SUCCESS)
			return (result);
		buffer = c->inbufs;
	}

	bytes_to_read = BUFFER_BYTES_FREE(buffer);

	while (bytes_to_read > 0) {
		if (buffer->tail > buffer->head)
			read_len = sizeof(buffer->data) - buffer->tail;
		else
			read_len = buffer->head - buffer->tail;

		read_status = read(c->socket, &buffer->data[buffer->tail],
				   read_len);
		if (read_status < 0) {
			if (errno == EWOULDBLOCK)
				break;
			else if (errno == EIO)
				return (ISC_R_IOERROR);
			else if (errno == ECONNRESET) {
				omapi_disconnect(h, OMAPI_CLEAN_DISCONNECT);
				return (ISC_R_SHUTTINGDOWN);
			} else
				return (ISC_R_UNEXPECTED);
		}

		/*
		 * If we got a zero-length read, as opposed to EWOULDBLOCK,
		 * the remote end closed the connection.
		 */
		if (read_status == 0) {
			omapi_disconnect(h, OMAPI_CLEAN_DISCONNECT);
			return (ISC_R_SHUTTINGDOWN);
		}
		buffer->tail += read_status;
		c->in_bytes += read_status;
		if (buffer->tail == sizeof(buffer->data))
			buffer->tail = 0;
		/*
		 * Comparison between signed and unsigned.
		 * The cast is ok because read_status < 0 was checked above.
		 */
		if ((unsigned int)read_status < read_len)
			break;
		bytes_to_read -= read_status;
	}

	if (c->bytes_needed <= c->in_bytes)
		omapi_signal(h, "ready", c);

	return (ISC_R_SUCCESS);
}

/*
 * Put some bytes into the output buffer for a connection.
 */

isc_result_t
omapi_connection_copyin(omapi_object_t *h, const unsigned char *bufp,
			unsigned int len)
{
	omapi_buffer_t *buffer;
	isc_result_t result;
	unsigned int bytes_copied = 0;
	unsigned int copy_len;
	omapi_connection_object_t *c;

	REQUIRE(h != NULL && h->type == omapi_type_connection);

	c = (omapi_connection_object_t *)h;

	if (c->outbufs) {
		for (buffer = c->outbufs;
		     buffer->next; buffer = buffer->next)
			;
	} else {
		result = omapi_buffer_new(&c->outbufs,
					  "omapi_private_buffer_copyin");
		if (result != ISC_R_SUCCESS)
			return (result);
		buffer = c->outbufs;
	}

	while (bytes_copied < len) {
		/*
		 * If there is no space available in this buffer,
		 * allocate a new one.
		 */
		if (BUFFER_BYTES_FREE (buffer) == 0) {
			result = omapi_buffer_new(&buffer->next,
						"omapi_private_buffer_copyin");
			if (result != ISC_R_SUCCESS)
				return (result);
			buffer = buffer->next;
		}

		if (buffer->tail > buffer->head)
			copy_len = sizeof(buffer->data) - buffer->tail;
		else
			copy_len = buffer->head - buffer->tail;

		if (copy_len > (len - bytes_copied))
			copy_len = len - bytes_copied;

		memcpy (&buffer->data[buffer->tail],
			&bufp[bytes_copied], copy_len);
		buffer->tail += copy_len;
		c->out_bytes += copy_len;
		bytes_copied += copy_len;
		if (buffer->tail == sizeof(buffer->data))
			buffer->tail = 0;
	}
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
	unsigned int bytes_remaining;
	unsigned int bytes_this_copy;
	unsigned int first_byte;
	omapi_buffer_t *buffer;
	unsigned char *bufp;
	omapi_connection_object_t *c;

	REQUIRE(h != NULL && h->type == omapi_type_connection);

	c = (omapi_connection_object_t *)h;

	if (size > c->in_bytes)
		return (ISC_R_NOMORE);
	bufp = buf;
	bytes_remaining = size;
	buffer = c->inbufs;

	while (bytes_remaining > 0) {
		if (buffer == NULL)
			return (ISC_R_UNEXPECTED);

		if (BYTES_IN_BUFFER(buffer) != 0) {
			if (buffer->head == sizeof(buffer->data) - 1)
				first_byte = 0;
			else
				first_byte = buffer->head + 1;

			if (first_byte > buffer->tail)
				bytes_this_copy = sizeof(buffer->data) -
						  first_byte;
			else
				bytes_this_copy =
					buffer->tail - first_byte;

			if (bytes_this_copy > bytes_remaining)
				bytes_this_copy = bytes_remaining;
			if (bufp != NULL) {
				memcpy(bufp, &buffer->data[first_byte],
					bytes_this_copy);
				bufp += bytes_this_copy;
			}
			bytes_remaining -= bytes_this_copy;
			buffer->head = first_byte + bytes_this_copy - 1;
			c->in_bytes -= bytes_this_copy;
		}
			
		if (BYTES_IN_BUFFER (buffer) == 0)
			buffer = buffer->next;
	}

	/*
	 * Get rid of any input buffers that we emptied.
	 */
	buffer = NULL;
	while (c->inbufs != NULL && BYTES_IN_BUFFER(c->inbufs) == 0) {
		if (c->inbufs->next != NULL) {
			omapi_buffer_reference(&buffer,
					       c->inbufs->next,
					       "omapi_private_buffer_copyout");
			omapi_buffer_dereference(&c->inbufs->next,
					       "omapi_private_buffer_copyout");
		}
		omapi_buffer_dereference(&c->inbufs,
					 "omapi_private_buffer_copyout");
		if (buffer != NULL) {
			omapi_buffer_reference(&c->inbufs, buffer,
					       "omapi_private_buffer_copyout");
			omapi_buffer_dereference(&buffer,
					       "omapi_private_buffer_copyout");
		}
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_connection_writer(omapi_object_t *h) {
	int bytes_written;
	unsigned int bytes_this_write;
	unsigned int first_byte;
	omapi_buffer_t *buffer;
	omapi_connection_object_t *c;

	REQUIRE(h != NULL && h->type == omapi_type_connection);

	c = (omapi_connection_object_t *)h;

	/*
	 * Already flushed.
	 */
	if (c->out_bytes == 0)
		return (ISC_R_SUCCESS);

	buffer = c->outbufs;

	while (c->out_bytes > 0) {
		if (buffer == NULL)
			return (ISC_R_UNEXPECTED);

		if (BYTES_IN_BUFFER (buffer) != 0) {
			if (buffer->head == sizeof(buffer->data) - 1)
				first_byte = 0;
			else
				first_byte = buffer->head + 1;

			if (first_byte > buffer->tail)
				bytes_this_write = (sizeof(buffer->data) -
						    first_byte);
			else
				bytes_this_write = buffer->tail - first_byte;

			bytes_written = write(c->socket,
					      &buffer->data[first_byte],
					      bytes_this_write);
			/*
			 * If the write failed with EWOULDBLOCK or we wrote
			 * zero bytes, a further write would block, so we have
			 * flushed as much as we can for now.   Other errors
			 * are really errors.
			 */
			if (bytes_written < 0) {
				if (errno == EWOULDBLOCK || errno == EAGAIN)
					return (ISC_R_SUCCESS);
				else if (errno == EPIPE)
					return (ISC_R_NOCONN);
				else if (errno == EFBIG || errno == EDQUOT)
					return (ISC_R_NORESOURCES);
				else if (errno == ENOSPC)
					return (ISC_R_NOSPACE);
				else if (errno == EIO)
					return (ISC_R_IOERROR);
				else if (errno == ECONNRESET)
					return (ISC_R_SHUTTINGDOWN);
				else
					return (ISC_R_UNEXPECTED);
			}
			if (bytes_written == 0)
				return (ISC_R_SUCCESS);

			buffer->head = first_byte + bytes_written - 1;
			c->out_bytes -= bytes_written;

			/*
			 * If we didn't finish out the write, we filled the
			 * O.S. output buffer and a further write would block,
			 * so stop trying to flush now.
			 *
			 * bytes_written was already checked to not be < 0,
			 * so the cast is ok.
			 */

			if ((unsigned int)bytes_written != bytes_this_write)
				return (ISC_R_SUCCESS);
		}

		if (BYTES_IN_BUFFER (buffer) == 0)
			buffer = buffer->next;
	}
		
	/*
	 * Get rid of any output buffers we emptied.
	 */
	buffer = NULL;
	while (c->outbufs != NULL && BYTES_IN_BUFFER(c->outbufs) == 0) {
		if (c->outbufs->next != NULL) {
			omapi_buffer_reference(&buffer, c->outbufs->next,
					       "omapi_private_flush");
			omapi_buffer_dereference(&c->outbufs->next,
						 "omapi_private_flush");
		}

		omapi_buffer_dereference(&c->outbufs, "omapi_private_flush");

		if (buffer != NULL) {
			omapi_buffer_reference(&c->outbufs, buffer,
					       "omapi_private_flush");
			omapi_buffer_dereference(&buffer,
						 "omapi_private_flush");
		}
	}
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

	return (omapi_connection_copyin(c, (const unsigned char *)name, len));
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
		result = omapi_connection_copyin(c,
						 (const unsigned char *)string,
						 len);
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
