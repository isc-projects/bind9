/*
 * Copyright (C) 1996-2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: omapi_test.c,v 1.27 2000/08/01 01:13:09 tale Exp $ */

/*
 * Test code for OMAPI.
 */
#include <config.h>

#include <stdlib.h>

#include <isc/commandline.h>
#include <isc/condition.h>
#include <isc/entropy.h>
#include <isc/mem.h>
#include <isc/socket.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dst/dst.h>
#include <dst/result.h>

#include <omapi/omapi.h>

char *progname;
isc_mem_t *mctx;

isc_boolean_t error_noobject = ISC_FALSE;
isc_boolean_t error_nosig = ISC_FALSE;
isc_boolean_t error_badsig = ISC_FALSE;
isc_boolean_t error_unknownsig = ISC_FALSE;
isc_boolean_t error_denyall = ISC_FALSE;

/*
 * Two different structures are used in this program to store the
 * value of interest on both the client and the server, but the
 * same structure can be used on each if desired (with the other variables
 * that are not in common between them being stored elsewhere).
 */
typedef struct server_object {
	OMAPI_OBJECT_PREAMBLE;
	unsigned long value;
	isc_boolean_t target_reached;
} server_object_t;

typedef struct client_object {
	OMAPI_OBJECT_PREAMBLE;
	unsigned long value;
} client_object_t;

static server_object_t master_data;

static omapi_objecttype_t *server_type;
static omapi_objecttype_t *client_type;

static isc_condition_t waiter;
static isc_mutex_t mutex;

/*
 * This is a string that names the registry of objects of type server_object_t.
 */
#define SERVER_OBJECT_TYPE "test-data"

/*
 * This is the name of the variable that is being manipulated in the server.
 * Note that it necessarily has no direct relevance to the *real* name of
 * the variable (but of course, making them the same would make for clearer
 * programming).
 */
#define MASTER_VALUE "amount"

#define KEY1_NAME "test-key"
#define KEY2_NAME "another-key"

/*
 * Create an OMAPI message on the client that requests an object on the
 * server be opened.  If the boolean 'update' is given, then the value
 * of the client's object will set the value of the server's object,
 * otherwise the server just refreshes the values in the client's object
 * with the master data.
 */
static isc_result_t
open_object(omapi_object_t *handle, omapi_object_t *manager,
	    isc_boolean_t update)
{
	omapi_object_t *message = NULL;

	REQUIRE(handle->type == client_type);

	/*
	 * Create a new message object to store the information that will
	 * be sent to the server.
	 */
	RUNTIME_CHECK(omapi_message_create(&message) == ISC_R_SUCCESS);

	/*
	 * Specify the OPEN operation, and the UPDATE option if requested.
	 */
	RUNTIME_CHECK(omapi_object_setinteger(message, "op", OMAPI_OP_OPEN)
		      == ISC_R_SUCCESS);
	if (update)
		RUNTIME_CHECK(omapi_object_setboolean(message, "update",
						      ISC_TRUE)
			      == ISC_R_SUCCESS);

	/*
	 * Tell the server the type of the object being opened; it needs
	 * to know this so that it can apply the proper object methods
	 * for lookup/setvalue.
	 */
	RUNTIME_CHECK(omapi_object_setstring(message, "type",
					     SERVER_OBJECT_TYPE)
		      == ISC_R_SUCCESS);

	/*
	 * Associate the client object with the message, so that it
	 * will have its values stuffed in the message.  Without it,
	 * the OPEN operation will fail because there is no name/value
	 * pair to use as a key for looking up the desired object at
	 * the server.
	 */
	if (! error_noobject)
		RUNTIME_CHECK(omapi_object_setobject(message, "object", handle)
			      == ISC_R_SUCCESS);

	/*
	 * Set up an object that will receive the "status" signal in its
	 * signal handler when the response is received from the server.
	 * This is not needed as a general rule, because normally the
	 * the object associated with the name "object" in the message
	 * is what gets that message.  However, in this case the
	 * particular error that is being tested when error_noobject is true
	 * is one where no item named "object" has been set, so not only
	 * can it not be used as a key when the server gets the message,
	 * it can't be used to get the "status" signal on the client
	 * when the server's "no key" error message comes back.
	 *
	 * If both "object" and "notify-object" are set, only the latter
	 * will receive the signal (as currently written; it was originally
	 * the other way 'round).  In this particular case it hardly matters,
	 * as both "object" and "notify-object" are the same object.
	 */
	RUNTIME_CHECK(omapi_object_setobject(message, "notify-object", handle)
		      == ISC_R_SUCCESS);

	/*
	 * Add the new message to the list of known messages.  When the
	 * server's response comes back, the client will verify that
	 * the response was for a message it really sent.
	 */
	omapi_message_register(message);

	/*
	 * Deliver the message to the server.  The manager's outer object
	 * is the connection object to the server.
	 */
	RUNTIME_CHECK(omapi_message_send(message, manager) == ISC_R_SUCCESS);

	/*
	 * Free the message.
	 */
	omapi_message_unregister(message);
	omapi_object_dereference(&message);

	return (ISC_R_SUCCESS);
}

/*
 * client_setvalue() is called on the client by the library's internal
 * message_process() function when the server replies to the OPEN operation
 * with its own REFRESH message for the client.  It is how the client learns
 * what data is on the server.
 */
static isc_result_t
client_setvalue(omapi_object_t *handle, omapi_string_t *name,
		omapi_data_t *value)

{
	isc_region_t region;
	client_object_t *client;

	REQUIRE(handle->type == client_type);

	client = (client_object_t *)handle;

	/*
	 * Only the MASTER_VALUE value has meaning in this program.
	 */
	if (omapi_string_strcmp(name, MASTER_VALUE) == 0) {
		client->value = omapi_data_getint(value);

		return (ISC_R_SUCCESS);
	} else if (omapi_string_strcmp(name, "remote-handle") == 0) {
		/*
		 * The server will also set "remote-handle" to let the client
		 * have an identifier for the object on the server that could
		 * be used with the other OMAPI operations, such as
		 * OMAPI_OP_DELETE.  The value of remote-handle is an integer,
		 * fetched with:
		 *    omapi_data_getint(&remote_handle, value).
		 *
		 * It is not used by this test program.
		 */
		return (ISC_R_SUCCESS);
	}

	omapi_string_totext(name, &region);
	fprintf(stderr, "client_setvalue: unknown name: '%.*s'\n",
		(int)region.length, region.base);

	return (ISC_R_NOTFOUND);
}

/*
 * This function is used by omapi_message_send to publish the values of
 * the data in a client object.
 */
static isc_result_t
client_stuffvalues(omapi_object_t *connection, omapi_object_t *handle) {
	client_object_t *client;

	REQUIRE(handle->type == client_type);

	client = (client_object_t *)handle;

	/*
	 * Write the MASTER_VALUE name, followed by the value length,
	 * follwed by its value.
	 */
	RUNTIME_CHECK(omapi_connection_putname(connection, MASTER_VALUE)
		      == ISC_R_SUCCESS);

	RUNTIME_CHECK(omapi_connection_putuint32(connection,
						 sizeof(isc_uint32_t))
		      == ISC_R_SUCCESS);

	RUNTIME_CHECK(omapi_connection_putuint32(connection, client->value)
		      == ISC_R_SUCCESS);

	return (ISC_R_SUCCESS);
}

static isc_result_t
client_signalhandler(omapi_object_t *handle, const char *name, va_list ap) {
	client_object_t *client;
	omapi_value_t *tv;
	isc_region_t region;
	isc_boolean_t expected;

	REQUIRE(handle->type == client_type);

	client = (client_object_t *)handle;

	if (strcmp(name, "updated") == 0) {
		client->waitresult = ISC_R_SUCCESS;

	} else if (strcmp(name, "status") == 0) {
		/*
		 * "status" is signalled with the result of the message's
		 * operation.
		 */
		client->waitresult = va_arg(ap, isc_result_t);

		expected = ISC_TF((error_noobject &&
				   client->waitresult == ISC_R_NOTFOUND) ||
				  (error_nosig &&
				   client->waitresult == ISC_R_NOPERM) ||
				  (error_badsig &&
				   client->waitresult == DST_R_VERIFYFAILURE));

		if (client->waitresult != ISC_R_SUCCESS)
			fprintf(stderr, "%s: message status: %s (%s)\n",
				progname,
				isc_result_totext(client->waitresult),
				expected ? "expected" : "UNEXPECTED");

		tv = va_arg(ap, omapi_value_t *);
		if (tv != NULL) {
			omapi_value_getregion(tv, &region);
			fprintf(stderr, "%s: additional text provided: %.*s\n",
				progname, (int)region.length, region.base);
		}

        } else {
		/*
		 * Pass any unknown signal any internal object.
		 * (This normally does not happen; there is no
		 * inner object, nor anything else being signalled.)
		 */
		fprintf(stderr, "%s: client_signalhandler: unknown signal: %s",
			progname, name);
		return (omapi_object_passsignal(handle, name, ap));
	}

	return (ISC_R_SUCCESS);
}

/*
 * This is the function that is called when an incoming OMAPI_OP_OPEN
 * message is received with either the create or update option set.
 * It is called once for each name/value pair in the message's object
 * value list.
 *
 * (Primary caller: message_process())
 */
static isc_result_t
server_setvalue(omapi_object_t *handle, omapi_string_t *name,
		omapi_data_t *value)
{
	isc_region_t region;

	RUNTIME_CHECK(handle == (omapi_object_t *)&master_data);

	/*
	 * Only one name is supported for this object, MASTER_VALUE.
	 */
	if (omapi_string_strcmp(name, MASTER_VALUE) == 0) {
		fprintf(stderr, "existing value: %lu\n", master_data.value);

		master_data.value = omapi_data_getint(value);
		fprintf(stderr, "new value: %lu\n", master_data.value);

		/*
		 * 32 is an arbitrary disconnect point.
		 */
		if (master_data.value >= 32) {
			master_data.target_reached = ISC_TRUE;
			SIGNAL(&waiter);
		}

		return (ISC_R_SUCCESS);
	}

	omapi_string_totext(name, &region);
	fprintf(stderr, "server_setvalue: unknown name: '%.*s'\n",
		(int)region.length, region.base);

	return (ISC_R_NOTFOUND);
}

/*
 * This is the function that is called by the library's internal
 * message_process() function when an incoming OMAPI_OP_OPEN
 * message is received.  It is normally supposed to look up the object
 * in the server that corresponds to the key data (name/value pair(s))
 * in 'ref'.
 */
static isc_result_t
server_lookup(omapi_object_t **server_object, omapi_object_t *key) {
	/*
	 * For this test program, there is only one static structure
	 * which is being used, so key is not needed.
	 */
	UNUSED(key);

	omapi_object_reference(server_object, (omapi_object_t *)&master_data);

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
server_stuffvalues(omapi_object_t *connection, omapi_object_t *handle) {
	server_object_t *master = (server_object_t *)handle;

	/*
	 * Write the MASTER_VALUE name, followed by the value length,
	 * follwed by its value.
	 */
	RUNTIME_CHECK(omapi_connection_putname(connection, MASTER_VALUE)
		      == ISC_R_SUCCESS);

	RUNTIME_CHECK(omapi_connection_putuint32(connection,
						 sizeof(isc_uint32_t))
		      == ISC_R_SUCCESS);

	RUNTIME_CHECK(omapi_connection_putuint32(connection, master->value)
		      == ISC_R_SUCCESS);

	return (ISC_R_SUCCESS);
}

static void
do_connect(const char *host, int port) {
	omapi_object_t *manager;
	omapi_object_t *omapi_client = NULL;
	client_object_t *client = NULL;
	isc_result_t result;
	const char *key;
	const char *bad_secret1 = "this secret is wrong";
	const char *bad_secret2 = "Yet Another Secret";

	RUNTIME_CHECK(omapi_object_register(&client_type, "client",
					    client_setvalue,
					    NULL,	/* getvalue */
					    NULL,	/* destroy */
					    client_signalhandler,
					    client_stuffvalues,
					    NULL,	/* lookup */
					    NULL,	/* create */
					    NULL)	/* remove */
		      == ISC_R_SUCCESS);

	/*
	 * Create the top level object which will manage the
	 * connection to the server.
	 */
	manager = NULL;
	RUNTIME_CHECK(omapi_object_create(&manager, NULL, 0)
		      == ISC_R_SUCCESS);

	result = omapi_protocol_connect(manager, host, port, NULL);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "%s: omapi_protocol_connect: %s\n",
			progname, isc_result_totext(result));
		omapi_object_dereference(&manager);
		return;
	}

	/*
	 * Authenticate to the server.
	 */
	key = KEY1_NAME;

	if (error_badsig) {
		omapi_auth_deregister(KEY1_NAME);

		RUNTIME_CHECK(omapi_auth_register(KEY1_NAME,
						  OMAPI_AUTH_HMACMD5,
						  bad_secret1,
						  strlen(bad_secret1))
			      == ISC_R_SUCCESS);
	} else if (error_unknownsig) {
		RUNTIME_CHECK(omapi_auth_register(KEY2_NAME,
						  OMAPI_AUTH_HMACMD5,
						  bad_secret2,
						  strlen(bad_secret2))
			      == ISC_R_SUCCESS);

		key = KEY2_NAME;
	}

	if (! error_nosig) {
		result = omapi_auth_use(manager, key, OMAPI_AUTH_HMACMD5);

		if (result != ISC_R_SUCCESS)
			fprintf(stderr, "%s: omapi_auth_use: %s (%s)\n",
				progname, isc_result_totext(result),
				(error_unknownsig && result == ISC_R_NOTFOUND)
				? "expected" : "UNEXPECTED");
	}

	if (result == ISC_R_SUCCESS) {
		/*
		 * Create the client's object.
		 */
		omapi_object_create((omapi_object_t **)&client, client_type,
				    sizeof(client_object_t));
		omapi_client = (omapi_object_t *)client;

		/*
		 * The object needs to have a name/value pair created for it
		 * even before it contacts the server so the server will know
		 * that there is an object that needs values filled in.  This
		 * name/value is created with the value of 0, but any interger
		 * value would work.
		 */
		RUNTIME_CHECK(omapi_object_setinteger(omapi_client,
						      MASTER_VALUE, 0)
			      == ISC_R_SUCCESS);

		RUNTIME_CHECK(open_object(omapi_client, manager, ISC_FALSE)
			      == ISC_R_SUCCESS);

		if (client->waitresult == ISC_R_SUCCESS) {
			/*
			 * Set the new value to be stored at the server and
			 * reopen the server object with an UPDATE operation.
			 */
			fprintf(stderr, "existing value: %lu\n",
				client->value);
			client->value *= 2;
			if (client->value == 0)		/* Check overflow. */
				client->value = 1;
			fprintf(stderr, "new value: %lu\n", client->value);

			RUNTIME_CHECK(open_object(omapi_client, manager,
						  ISC_TRUE)
				      == ISC_R_SUCCESS);

			RUNTIME_CHECK(client->waitresult == ISC_R_SUCCESS);
		}
	}

	/*
	 * Close the connection and wait to be disconnected.
	 */
	omapi_protocol_disconnect(manager, OMAPI_CLEAN_DISCONNECT);

	/*
	 * Free the protocol manager and client object.
	 */
	omapi_object_dereference(&manager);

	if (omapi_client != NULL)
		omapi_object_dereference(&omapi_client);
}

static void
listen_done(isc_task_t *task, isc_event_t *event) {
	omapi_object_t *listener = event->ev_arg;

	UNUSED(task);

	fprintf(stderr, "SERVER STOPPED\n");

	isc_event_free(&event);

	omapi_object_dereference(&listener);
	omapi_lib_destroy();
}

static isc_boolean_t
verify_connection(isc_sockaddr_t *sockaddr, void *arg) {
	/* XXXDCL test the connection verification code */
	UNUSED(sockaddr);
	UNUSED(arg);

	return (ISC_TRUE);
}

static isc_boolean_t
verify_key(const char *name, unsigned int algorithm, void *arg) {
	/* XXXDCL test the key verification code */
	UNUSED(name);
	UNUSED(algorithm);
	UNUSED(arg);

	return (ISC_TRUE);
}

static void
do_listen(int port) {
	omapi_object_t *listener = NULL;
	isc_sockaddr_t sockaddr;
	struct in_addr inaddr;
	dns_acl_t *acl;

	/*
	 * Create the manager for handling incoming server connections.
	 */
	RUNTIME_CHECK(omapi_object_create(&listener, NULL, 0)
		      == ISC_R_SUCCESS);

	/*
	 * Register the server_object.  The SERVER_OBJECT_TYPE is what
	 * a client would need to specify as a value for the name "type"
	 * when contacting the server in order to be able to find objects
	 * server_type.
	 */
	RUNTIME_CHECK(omapi_object_register(&server_type, SERVER_OBJECT_TYPE,
					    server_setvalue,
					    NULL, 	/* getvalue */
					    NULL,	/* destroy */
					    NULL,	/* signalhandler */
					    server_stuffvalues,
					    server_lookup,
					    NULL,	/* create */
					    NULL)	/* remove */
		      == ISC_R_SUCCESS);

	/*
	 * Initialize the server_object data.
	 */
	master_data.type = server_type;
	master_data.refcnt = 1;
	master_data.value = 2;
	master_data.target_reached = ISC_FALSE;

	LOCK(&mutex);

	/*
	 * Set the access control list for valid connections.
	 */
	if (error_denyall)
		RUNTIME_CHECK(dns_acl_none(mctx, &acl) == ISC_R_SUCCESS);
	else
		RUNTIME_CHECK(dns_acl_any(mctx, &acl) == ISC_R_SUCCESS);

	/*
	 * Start listening for connections.
	 */
	inaddr.s_addr = INADDR_ANY;
	isc_sockaddr_fromin(&sockaddr, &inaddr, port);
	RUNTIME_CHECK(omapi_protocol_listen(listener, &sockaddr,
					    verify_connection, verify_key,
					    listen_done, listener)
		      == ISC_R_SUCCESS);

	fprintf(stderr, "SERVER STARTED\n");

	/*
	 * Lose one reference to the acl; the omapi library holds another
	 * reference and should free it when it is done.
	 */
	dns_acl_detach(&acl);

	/*
	 * Block until done.  "Done" is when server_setvalue has reached
	 * its trigger value.
	 */
	do {
		WAIT(&waiter, &mutex);
	} while (! master_data.target_reached);

	omapi_listener_shutdown(listener);
}

#undef ARG_IS
#define ARG_IS(s) (strcmp(isc_commandline_argument, (s)) == 0)

int
main(int argc, char **argv) {
	isc_boolean_t show_final_mem = ISC_FALSE;
	isc_socketmgr_t *socketmgr = NULL;
	isc_taskmgr_t *taskmgr = NULL;
	isc_entropy_t *entropy = NULL;
	const char *secret = "shhh, this is a secret";
	int ch;

	progname = strrchr(*argv, '/');
	if (progname != NULL)
		progname++;
	else
		progname = *argv;

	while ((ch = isc_commandline_parse(argc, argv, "e:m")) != -1) {
		switch (ch) {
		case 'e':
			if (ARG_IS("noobject"))
				error_noobject = ISC_TRUE;

			else if (ARG_IS("nosig"))
				error_nosig = ISC_TRUE;

			else if (ARG_IS("badsig"))
				error_badsig = ISC_TRUE;

			else if (ARG_IS("unknownsig"))
				error_unknownsig = ISC_TRUE;

			else if (ARG_IS("denyall"))
				error_denyall = ISC_TRUE;
			else {
				fprintf(stderr, "Unknown forced error: %s\n",
					isc_commandline_argument);
				fprintf(stderr, "Valid forced errors: "
					"noobject nosig badsig unknownsig\n");
				exit(1);
			}

			break;
		case 'm':
			show_final_mem = ISC_TRUE;
			break;
		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_taskmgr_create(mctx, 1, 0, &taskmgr)
		      == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr)
		      == ISC_R_SUCCESS);

	RUNTIME_CHECK(omapi_lib_init(mctx, taskmgr, socketmgr)
		      == ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_mutex_init(&mutex) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_condition_init(&waiter) == ISC_R_SUCCESS);

	/*
	 * Initialize the signature library.
	 */
	RUNTIME_CHECK(isc_entropy_create(mctx, &entropy) == ISC_R_SUCCESS);
	RUNTIME_CHECK(dst_lib_init(mctx, entropy, 0) == ISC_R_SUCCESS);

	/*
	 * The secret key is shared on both the client and server side.
	 */
	RUNTIME_CHECK(omapi_auth_register(KEY1_NAME, OMAPI_AUTH_HMACMD5,
					  secret, strlen(secret))
		      == ISC_R_SUCCESS);

	if (argc >= 1 && strcmp(argv[0], "listen") == 0) {
		if (argc != 2) {
			fprintf(stderr, "Usage: %s listen port\n", progname);
			exit (1);
		}

		do_listen(atoi(argv[1]));

	} else if (argc >= 1 && !strcmp (argv[0], "connect")) {
		if (argc != 3) {
			fprintf(stderr, "Usage: %s connect address port\n",
				progname);
			exit (1);
		}

		do_connect(argv[1], atoi(argv[2]));

		omapi_lib_destroy();

	} else {
		fprintf(stderr, "Usage: %s [-m] [listen | connect] ...\n",
			progname);
		exit (1);
	}

	isc_socketmgr_destroy(&socketmgr);
	isc_taskmgr_destroy(&taskmgr);

	dst_lib_destroy();
	isc_entropy_detach(&entropy);

	if (show_final_mem)
		isc_mem_stats(mctx, stderr);

	isc_mem_destroy(&mctx);

	return (0);
}
