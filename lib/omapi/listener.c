/* listener.c

   Subroutines that support the generic listener object. */

/*
 * Copyright (c) 1996-1999 Internet Software Consortium.
 * Use is subject to license terms which appear in the file named
 * ISC-LICENSE that should have accompanied this file when you
 * received it.   If a file named ISC-LICENSE did not accompany this
 * file, or you are not sure the one you have is correct, you may
 * obtain an applicable copy of the license at:
 *
 *             http://www.isc.org/isc-license-1.0.html. 
 *
 * This file is part of the ISC DHCP distribution.   The documentation
 * associated with this file is listed in the file DOCUMENTATION,
 * included in the top-level directory of this release.
 *
 * Support and other services are available for ISC products - see
 * http://www.isc.org for more information.
 */

#include <omapip/omapip_p.h>

isc_result_t omapi_listen (omapi_object_t *h,
			   int port,
			   int max)
{
	struct hostent *he;
	int hix;
	isc_result_t status;
	omapi_listener_object_t *obj;

	/* Get the handle. */
	obj = (omapi_listener_object_t *)malloc (sizeof *obj);
	if (!obj)
		return ISC_R_NOMEMORY;
	memset (obj, 0, sizeof *obj);
	obj -> refcnt = 1;
	obj -> type = omapi_type_listener;

	/* Connect this object to the inner object. */
	status = omapi_object_reference (&h -> outer, (omapi_object_t *)obj,
					 "omapi_protocol_listen");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "omapi_protocol_listen");
		return status;
	}
	status = omapi_object_reference (&obj -> inner, h,
					 "omapi_protocol_listen");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "omapi_protocol_listen");
		return status;
	}

	/* Set up the address on which we will listen... */
	obj -> address.sin_port = htons (port);
	obj -> address.sin_addr.s_addr = htonl (INADDR_ANY);

	/* Create a socket on which to listen. */
	obj -> socket = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (!obj -> socket) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "omapi_listen");
		if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS)
			return ISC_R_NORESOURCES;
		return ISC_R_UNEXPECTED;
	}
	
	/* Try to bind to the wildcard address using the port number
           we were given. */
	if (bind (obj -> socket,
		  (struct sockaddr *)&obj -> address, sizeof obj -> address)) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "omapi_listen");
		if (errno == EADDRINUSE)
			return ISC_R_ADDRNOTAVAIL;
		if (errno == EPERM)
			return ISC_R_NOPERM;
		return ISC_R_UNEXPECTED;
	}

	/* Now tell the kernel to listen for connections. */
	if (listen (obj -> socket, max)) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "omapi_listen");
		return ISC_R_UNEXPECTED;
	}

	if (fcntl (obj -> socket, F_SETFL, O_NONBLOCK) < 0) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "omapi_connect");
		return ISC_R_UNEXPECTED;
	}

	status = omapi_register_io_object ((omapi_object_t *)obj,
					   omapi_listener_readfd, 0,
					   omapi_accept, 0, 0);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "omapi_listen");
		return status;
	}

	return ISC_R_SUCCESS;
}

/* Return the socket on which the dispatcher should wait for readiness
   to read, for a listener object. */
int omapi_listener_readfd (omapi_object_t *h)
{
	omapi_listener_object_t *l;

	if (h -> type != omapi_type_listener)
		return -1;
	l = (omapi_listener_object_t *)h;
	
	return l -> socket;
}

/* Reader callback for a listener object.   Accept an incoming connection. */
isc_result_t omapi_accept (omapi_object_t *h)
{
	isc_result_t status;
	int len;
	omapi_connection_object_t *obj;
	omapi_listener_object_t *listener;

	if (h -> type != omapi_type_listener)
		return ISC_R_INVALIDARG;
	listener = (omapi_listener_object_t *)h;
	
	/* Get the handle. */
	obj = (omapi_connection_object_t *)malloc (sizeof *obj);
	if (!obj)
		return ISC_R_NOMEMORY;
	memset (obj, 0, sizeof *obj);
	obj -> refcnt = 1;
	obj -> type = omapi_type_connection;

	/* Accept the connection. */
	len = sizeof obj -> remote_addr;
	obj -> socket =
		accept (listener -> socket,
			((struct sockaddr *)
			 &(obj -> remote_addr)), &len);
	if (obj -> socket < 0) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "omapi_accept");
		if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS)
			return ISC_R_NORESOURCES;
		return ISC_R_UNEXPECTED;
	}
	
	obj -> state = omapi_connection_connected;

	status = omapi_register_io_object ((omapi_object_t *)obj,
					   omapi_connection_readfd,
					   omapi_connection_writefd,
					   omapi_connection_reader,
					   omapi_connection_writer,
					   omapi_connection_reaper);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "omapi_accept");
		return status;
	}

	omapi_object_reference (&obj -> listener, (omapi_object_t *)listener,
				"omapi_accept");

	status = omapi_signal (h, "connect", obj);

	/* Lose our reference to the connection, so it'll be gc'd when it's
	   reaped. */
	omapi_object_dereference ((omapi_object_t **)&obj, "omapi_accept");
	return status;
}

isc_result_t omapi_listener_set_value (omapi_object_t *h,
				      omapi_object_t *id,
				      omapi_data_string_t *name,
				      omapi_typed_data_t *value)
{
	if (h -> type != omapi_type_listener)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> set_value)
		return (*(h -> inner -> type -> set_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t omapi_listener_get_value (omapi_object_t *h,
				       omapi_object_t *id,
				       omapi_data_string_t *name,
				       omapi_value_t **value)
{
	if (h -> type != omapi_type_listener)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> get_value)
		return (*(h -> inner -> type -> get_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t omapi_listener_destroy (omapi_object_t *h, const char *name)
{
	omapi_listener_object_t *l;

	if (h -> type != omapi_type_listener)
		return ISC_R_INVALIDARG;
	l = (omapi_listener_object_t *)(h);
	
	if (l -> socket != -1) {
		close (l -> socket);
		l -> socket = -1;
	}
	return ISC_R_SUCCESS;
}

isc_result_t omapi_listener_signal_handler (omapi_object_t *h,
					    const char *name, va_list ap)
{
	if (h -> type != omapi_type_listener)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> signal_handler)
		return (*(h -> inner -> type -> signal_handler)) (h -> inner,
								  name, ap);
	return ISC_R_NOTFOUND;
}

/* Write all the published values associated with the object through the
   specified connection. */

isc_result_t omapi_listener_stuff_values (omapi_object_t *c,
					  omapi_object_t *id,
					  omapi_object_t *l)
{
	int i;

	if (l -> type != omapi_type_listener)
		return ISC_R_INVALIDARG;

	if (l -> inner && l -> inner -> type -> stuff_values)
		return (*(l -> inner -> type -> stuff_values)) (c, id,
								l -> inner);
	return ISC_R_SUCCESS;
}

