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
 * Test code for OMAPI.
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/commandline.h>
#include <isc/mem.h>
#include <isc/result.h>

#include <omapi/omapip.h>

char *progname;
isc_mem_t *mctx;

/*
 * Two different structures are used in this program to store the
 * value of interest on both the client and the server, but the
 * same structure can be used on each if desired.
 */
typedef struct server_object {
	OMAPI_OBJECT_PREAMBLE;
	unsigned long value;
} server_object_t;

typedef struct client_object {
	OMAPI_OBJECT_PREAMBLE;
	int waitresult;
	unsigned long value;
} client_object_t;

static server_object_t master_data;

static omapi_object_type_t *server_type;
static omapi_object_type_t *client_type;

/*
 * This is a string that names the registry of objects of type server_object_t.
 */
#define SERVER_OBJECT_TYPE "test-data"

/*
 * This is the name of the variable that is being manipulated in the server.
 * Note that it necessarily has no direct relevance to the *real* name of
 * the variable (but of course, making them the same would make for clearer
 * programming.
 */
#define MASTER_VALUE "amount"

/*
 * Create an OMAPI message on the client that requests an object on the
 * server be opened.  If the boolean 'update' is given, then the value
 * of the client's object will set the value of the server's object,
 * otherwise the server just refreshes the values in the client's object
 * with the master data.
 */
static isc_result_t
open_object(omapi_object_t *handle, omapi_object_t *manager,
	    isc_boolean_t update) {
	omapi_object_t *message = NULL;

	REQUIRE(handle->type == client_type);

	/*
	 * Create a new message object to store the information that will
	 * be sent to the server.
	 */
	ENSURE(omapi_message_new(&message, "open_object") == ISC_R_SUCCESS);

	/*
	 * Specify the OPEN operation, and the UPDATE option if requested.
	 */
	ENSURE(omapi_set_int_value(message, NULL, "op", OMAPI_OP_OPEN)
	       == ISC_R_SUCCESS);
	if (update)
		ENSURE(omapi_set_boolean_value(message, NULL, "update", 1)
		       == ISC_R_SUCCESS);

	/*
	 * Tell the server the type of the object being opened; it needs
	 * to know this so that it can apply the proper object methods
	 * for lookup/setvalue.
	 */
	ENSURE(omapi_set_string_value(message, NULL, "type",SERVER_OBJECT_TYPE)
	       == ISC_R_SUCCESS);

	/*
	 * Associate the client object with the message, so that it
	 * will have its values stuffed in the message.  Without it,
	 * the OPEN operation will fail because there is no name/value
	 * pair to use as a key for looking up the desired object at
	 * the server.
	 */
	ENSURE(omapi_set_object_value(message, NULL, "object", handle)
	       == ISC_R_SUCCESS);

	/*
	 * Add the new message to the list of known messages.
	 * XXXDCL Why exactly?
	 */
	ENSURE(omapi_message_register(message) == ISC_R_SUCCESS);

	/*
	 * Deliver the message to the server.  The manager's outer object
	 * is the connection object to the server.
	 */
	return (omapi_protocol_send_message(manager->outer, NULL, message,
					   NULL));
}

/*
 * client_setvalue() is called on the client by omapi_message_process() when
 * the server replies to the OPEN operation with its own REFRESH message
 * for the client.  It is how the client learns what data is on the server.
 */
static isc_result_t
client_setvalue(omapi_object_t *handle, omapi_object_t *id,
		omapi_data_string_t *name, omapi_typed_data_t *value)

{
	client_object_t *client;
	unsigned long server_value;

	REQUIRE(handle->type == client_type);

	(void)id;		/* Unused. */

	client = (client_object_t *)handle;

	/*
	 * Only the MASTER_VALUE value has meaning in this program.
	 */
	if (omapi_ds_strcmp(name, MASTER_VALUE) == 0) {
	
		ENSURE(omapi_get_int_value(&server_value, value)
		       == ISC_R_SUCCESS);

		client->value = server_value;

		return (ISC_R_SUCCESS);
	} else if (omapi_ds_strcmp(name, "remote-handle") == 0) {
		/*
		 * The server will also set "remote-handle" to let the client
		 * have an identifier for the object on the server that could
		 * be used with the other OMAPI operations, such as
		 * OMAPI_OP_DELETE.  The value of remote-handle is an integer,
		 * fetched with:
		 *    omapi_get_int_value(&remote_handle, value).
		 *
		 * It is not used by this test program.
		 */
		return (ISC_R_SUCCESS);
	}

	fprintf(stderr, "client_setvalue: unknown name: '%s'\n", name->value);

	return (ISC_R_NOTFOUND);
}

/*
 * This function is used by omapi_message_send to publish the values of
 * the data in a client object.
 */
static isc_result_t
client_stuffvalues(omapi_object_t *connection, omapi_object_t *id,
		   omapi_object_t *handle)
{
	client_object_t *client;

	REQUIRE(handle->type == client_type);

	(void)id;		/* Unused. */

	client = (client_object_t *)handle;

	/*
	 * Write the MASTER_VALUE name, followed by the value length,
	 * follwed by its value.
	 */
	ENSURE(omapi_connection_putname(connection, MASTER_VALUE)
	       == ISC_R_SUCCESS);

	ENSURE(omapi_connection_putuint32(connection, sizeof(isc_uint32_t))
	       == ISC_R_SUCCESS);

	ENSURE(omapi_connection_putuint32(connection, client->value)
	       == ISC_R_SUCCESS);

	return (ISC_R_SUCCESS);
}

static isc_result_t
client_signalhandler(omapi_object_t *handle, const char *name, va_list ap) {
	client_object_t *client;

	REQUIRE(handle->type == client_type);

	client = (client_object_t *)handle;

	/*
	 * omapi_connection_wait puts an omapi_waiter_object_t on
	 * the inside of the client object.
	 */
	if (strcmp(name, "updated") == 0) {
		client->waitresult = ISC_R_SUCCESS;

		/*
		 * Signal the waiter object that the operation is complete.
		 */
		return (omapi_signal_in(handle->inner, "ready"));
	}

	/*
	 * "status" will be signalled with the waitresult of the operation.
	 */
        if (strcmp(name, "status") == 0) {
                client->waitresult = va_arg(ap, isc_result_t);

		/*
		 * Signal the waiter object that the operation is complete.
		 */
                return (omapi_signal_in(handle->inner, "ready"));
        }

	/*
	 * Pass any unknown signal to the internal waiter object.
	 * (This normally does not happen.)
	 */
	fprintf(stderr, "client_signalhandler: unknown signal: %s", name);
        if (client->inner && client->inner->type->signal_handler != NULL)
		return ((*(client->inner->type->signal_handler))(client->inner,
								 name, ap));

	return ISC_R_SUCCESS;
}

/*
 * This is the function that is called when an incoming OMAPI_OP_OPEN
 * message is received with either the create or update option set.
 * It is called once for each name/value pair in the message's object
 * value list.
 *
 * (Primary caller: omapi_message_process())
 */
static isc_result_t
server_setvalue(omapi_object_t *handle, omapi_object_t *id,
		omapi_data_string_t *name, omapi_typed_data_t *value)
{
	unsigned long new_value;

	(void)id;		/* Unused. */

	ENSURE(handle == (omapi_object_t *)&master_data);

	/*
	 * Only one name is supported for this object, MASTER_VALUE.
	 */
	if (omapi_ds_strcmp(name, MASTER_VALUE) == 0) {
		fprintf(stderr, "existing value: %lu\n", master_data.value);

		ENSURE(omapi_get_int_value(&new_value, value)
		       == ISC_R_SUCCESS);

		master_data.value = new_value;
		fprintf(stderr, "new value: %lu\n", master_data.value);

		return (ISC_R_SUCCESS);
	}

	fprintf(stderr, "server_setvalue: unknown name: '%s'\n", name->value);
	return (ISC_R_NOTFOUND);
}

/*
 * This is the function that is called when an incoming OMAPI_OP_OPEN
 * message is received.  It is normally supposed to look up the object
 * in the server that corresponds to the key data (name/value pair(s))
 * in 'ref'.
 *
 * (Primary caller: omapi_message_process())
 */
static isc_result_t
server_lookup(omapi_object_t **server_object, omapi_object_t *id,
	      omapi_object_t *ref)
{
	/*
	 * For this test program, there is only one static structure
	 * which is being used, so ref is not needed.
	 */
	(void)ref;
	(void)id;

	*server_object = (omapi_object_t *)&master_data;

	return (ISC_R_SUCCESS);
}

/*
 * This function is called when the server is sending a reply to a client
 * that opened an object of its type.  It needs to output all published
 * name/value pairs for the object, and will typically also put the data
 * for any inner objects (but in this program, there will be no inner
 * objects).
 */
static isc_result_t
server_stuffvalues(omapi_object_t *connection, omapi_object_t *id,
		   omapi_object_t *handle)
{
	server_object_t *master = (server_object_t *)handle;

	(void)id;		/* Unused. */

	/*
	 * Write the MASTER_VALUE name, followed by the value length,
	 * follwed by its value.
	 */
	ENSURE(omapi_connection_putname(connection, MASTER_VALUE)
	       == ISC_R_SUCCESS);

	ENSURE(omapi_connection_putuint32(connection, sizeof(isc_uint32_t))
	       == ISC_R_SUCCESS);

	ENSURE(omapi_connection_putuint32(connection, master->value)
	       == ISC_R_SUCCESS);

	return (ISC_R_SUCCESS);
}

static void
do_connect(const char *host, int port) {
	omapi_object_t *manager;
	omapi_object_t *connection;
	omapi_object_t *omapi_client;
	client_object_t *client;

	ENSURE(omapi_object_type_register(&client_type, "client",
					  client_setvalue,
					  NULL,   /* getvalue */
					  NULL,   /* destroy */
					  client_signalhandler,
					  client_stuffvalues,
					  NULL,    /* lookup */
					  NULL,    /* create */
					  NULL)    /* remove */
	       == ISC_R_SUCCESS);

	/*
	 * Create the top level object which will manage the
	 * connection to the server.
	 */
	manager = NULL;
	ENSURE(omapi_generic_new(&manager, "main")
	       == ISC_R_SUCCESS);

	ENSURE(omapi_protocol_connect(manager, host, port, NULL)
	       == ISC_R_SUCCESS);

	connection = manager->outer->outer;

	/*
	 * Wait to be connected.
	 */
	ENSURE(omapi_connection_wait(manager, connection, NULL)
	       == ISC_R_SUCCESS);

	/*
	 * Create the client's object.
	 */
	client = malloc(sizeof(client_object_t));
	ENSURE(client != NULL);

	memset(client, 0, sizeof(client_object_t));
	client->type = client_type;
	client->refcnt = 1;

	omapi_client = (omapi_object_t *)client;

	/*
	 * The object needs to have a name/value pair created for it
	 * even before it contacts the server so the server will know
	 * that there is an object that needs values filled in.  This
	 * name/value is created with the value of 0, but any interger
	 * value would work.
	 */
	ENSURE(omapi_set_int_value(omapi_client, NULL, MASTER_VALUE, 0)
	       == ISC_R_SUCCESS);

	ENSURE(open_object(omapi_client, manager, ISC_FALSE)
	       == ISC_R_SUCCESS);

	ENSURE(omapi_connection_wait(omapi_client, connection, NULL)
	       == ISC_R_SUCCESS);

	ENSURE(client->waitresult == ISC_R_SUCCESS);

	/*
	 * Set the new value to be stored at the server and reopen the
	 * server object with an UPDATE operation.
	 */
	fprintf(stderr, "existing value: %lu\n", client->value);
	client->value *= 2;
	fprintf(stderr, "new value: %lu\n", client->value);

	ENSURE(open_object(omapi_client, manager, ISC_TRUE)
	       == ISC_R_SUCCESS);

	ENSURE(omapi_connection_wait(omapi_client, connection, NULL)
	       == ISC_R_SUCCESS);

	ENSURE(client->waitresult == ISC_R_SUCCESS);

	/*
	 * Close the connection and wait to be disconnected.
	 * XXXDCL This problem has been biting my butt for two days
	 * straight!  I am totally zoning on how to best accomplish
	 * making disconnection be either sync or async, and some
	 * internal thread race conditions i am having in the omapi library.
	 * grr grr grr grr GRRRRR
	 * at the moment things work ok enough by requiring that
	 * the connection be waited before calling omapi_connection_disconnect
	 * and sleeping a moment.  clearly this is BOGUS
	 */
	sleep(1);
	omapi_connection_disconnect(connection, ISC_FALSE);

	ENSURE(client->waitresult == ISC_R_SUCCESS);

	/*
	 * Free the protocol manager.
	 */
       omapi_object_dereference(&manager, "do_connect");
}

static void
do_listen(int port) {
	omapi_object_t *listener;

	/*
	 * Create the manager for handling incoming server connections.
	 */
	listener = NULL;
	ENSURE(omapi_generic_new(&listener, "main")
	       == ISC_R_SUCCESS);

	/*
	 * Register the server_object.  The SERVER_OBJECT_TYPE is what
	 * a client would need to specify as a value for the name "type"
	 * when * contacting the server in order to be able to find objects
	 * server_type.
	 */
	ENSURE(omapi_object_type_register(&server_type, SERVER_OBJECT_TYPE,
					  server_setvalue,
					  NULL, /* setvalue */
					  NULL, /* destroy */
					  NULL, /* signalhandler */
					  server_stuffvalues,
					  server_lookup,
					  NULL, /* create */
					  NULL) /* remove */
	       == NULL);

	/*
	 * Initialize the server_object data.
	 */
	master_data.type = server_type;
	master_data.value = 2;

	/*
	 * Start listening for connections.
	 */
	ENSURE(omapi_protocol_listen(listener, port, 1)
	       == ISC_R_SUCCESS);

	fprintf(stderr, "SERVER STARTED\n");

	/*
	 * Loop forever getting connections.
	 */
	omapi_dispatch(NULL);
}

int
main (int argc, char **argv) {
	isc_boolean_t show_final_mem = ISC_FALSE;
	int ch;

	progname = strrchr(*argv, '/');
	if (progname != NULL)
		progname++;
	else
		progname = *argv;

	while ((ch = isc_commandline_parse(argc, argv, "m")) != -1) {
		switch (ch) {
		case 'm':
			show_final_mem = ISC_TRUE;
			break;
		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	ENSURE(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	ENSURE(omapi_init(mctx) == ISC_R_SUCCESS);

	if (argc > 1 && strcmp(argv[0], "listen") == 0) {
		if (argc < 2) {
			fprintf(stderr, "Usage: %s listen port\n", progname);
			exit (1);
		}

		do_listen(atoi(argv[1]));

	} else if (argc > 1 && !strcmp (argv[0], "connect")) {
		if (argc < 3) {
			fprintf(stderr, "Usage: %s connect address port\n",
				progname);
			exit (1);
		}

		do_connect(argv[1], atoi(argv[2]));

	} else {
		fprintf(stderr, "Usage: %s [-m] [listen | connect] ...\n",
			progname);
		exit (1);
	}

	omapi_shutdown();

	if (show_final_mem)
		isc_mem_stats(mctx, stderr);

	return (0);
}
