/* omapip_p.h

   Private master include file for the OMAPI library. */

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

#ifndef __OMAPIP_OMAPIP_P_H__
#define __OMAPIP_OMAPIP_P_H__

#ifndef __CYGWIN32__
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#if defined (NSUPDATE)
# include <arpa/nameser.h>
# include <resolv.h>
#endif

#include <netdb.h>
#else
#define fd_set cygwin_fd_set
#include <sys/types.h>
#endif
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>

#include "cdefs.h"
#include "osdep.h"

#include <isc/result.h>

#include <omapip/omapip.h>

/* OMAPI protocol header, version 1.00 */
typedef struct {
	unsigned authlen;	/* Length of authenticator. */
	unsigned authid;	/* Authenticator object ID. */
	unsigned op;		/* Opcode. */
	omapi_handle_t handle;	/* Handle of object being operated on,
                                   or zero. */
	unsigned id;		/* Transaction ID. */
	unsigned rid;	/* ID of transaction to which this is a response. */
} omapi_protocol_header_t;

#define OMAPI_PROTOCOL_VERSION	100

#define OMAPI_OP_OPEN		1
#define OMAPI_OP_REFRESH	2
#define	OMAPI_OP_UPDATE		3
#define OMAPI_OP_NOTIFY		4
#define OMAPI_OP_STATUS		5
#define OMAPI_OP_DELETE		6

typedef enum {
	omapi_connection_unconnected,
	omapi_connection_connecting,
	omapi_connection_connected,
	omapi_connection_disconnecting,
	omapi_connection_closed
} omapi_connection_state_t;

typedef enum {
	omapi_protocol_intro_wait,
	omapi_protocol_header_wait,
	omapi_protocol_signature_wait,
	omapi_protocol_name_wait,
	omapi_protocol_name_length_wait,
	omapi_protocol_value_wait,
	omapi_protocol_value_length_wait
} omapi_protocol_state_t;

typedef struct __omapi_message_object {
	OMAPI_OBJECT_PREAMBLE;
	struct __omapi_message_object *next, *prev;
	omapi_object_t *object;
	omapi_object_t *notify_object;
	unsigned authlen;
	omapi_typed_data_t *authenticator;
	unsigned authid;
	omapi_object_t *id_object;
	unsigned op;
	omapi_handle_t h;
	unsigned id;
	unsigned rid;
} omapi_message_object_t;

typedef struct {
	OMAPI_OBJECT_PREAMBLE;
	unsigned header_size;		
	unsigned protocol_version;
	u_int32_t next_xid;
	omapi_object_t *authinfo; /* Default authinfo to use. */

	omapi_protocol_state_t state;	/* Input state. */
	int reading_message_values;	/* True if reading message-specific
					   values. */
	omapi_message_object_t *message;	/* Incoming message. */
	omapi_data_string_t *name;	/* Incoming name. */
	omapi_typed_data_t *value;	/* Incoming value. */
} omapi_protocol_object_t;

typedef struct {
	OMAPI_OBJECT_PREAMBLE;
} omapi_protocol_listener_object_t;

#include <omapip/buffer.h>

typedef struct __omapi_connection_object {
	OMAPI_OBJECT_PREAMBLE;
	int socket;		/* Connection socket. */
	omapi_connection_state_t state;
	struct sockaddr_in remote_addr;
	struct sockaddr_in local_addr;
	u_int32_t bytes_needed;	/* Bytes of input needed before wakeup. */
	u_int32_t in_bytes;	/* Bytes of input already buffered. */
	omapi_buffer_t *inbufs;
	u_int32_t out_bytes;	/* Bytes of output in buffers. */
	omapi_buffer_t *outbufs;
	omapi_object_t *listener;	/* Listener that accepted this
					   connection, if any. */
} omapi_connection_object_t;

typedef struct __omapi_listener_object {
	OMAPI_OBJECT_PREAMBLE;
	int socket;		/* Connection socket. */
	struct sockaddr_in address;
} omapi_listener_object_t;

typedef struct __omapi_io_object {
	OMAPI_OBJECT_PREAMBLE;
	struct __omapi_io_object *next;
	int (*readfd) (omapi_object_t *);
	int (*writefd) (omapi_object_t *);
	isc_result_t (*reader) (omapi_object_t *);
	isc_result_t (*writer) (omapi_object_t *);
	isc_result_t (*reaper) (omapi_object_t *);
} omapi_io_object_t;

typedef struct __omapi_generic_object {
	OMAPI_OBJECT_PREAMBLE;
	omapi_value_t **values;
	int nvalues, va_max;
} omapi_generic_object_t;

typedef struct __omapi_waiter_object {
	OMAPI_OBJECT_PREAMBLE;
	int ready;
	struct __omapi_waiter_object *next;
} omapi_waiter_object_t;

#define OMAPI_HANDLE_TABLE_SIZE 120

typedef struct __omapi_handle_table {
	omapi_handle_t first, limit;
	omapi_handle_t next;
	int leafp;
	union {
		omapi_object_t *object;
		struct __omapi_handle_table *table;
	} children [OMAPI_HANDLE_TABLE_SIZE];
} omapi_handle_table_t;

#include <omapip/alloc.h>
#endif /* __OMAPIP_OMAPIP_P_H__ */
