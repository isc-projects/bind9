/*
 * Copyright (C) 2000  Internet Software Consortium.
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

/* $Id: rndc.c,v 1.7 2000/03/18 00:53:11 tale Exp $ */

/* 
 * Principal Author: DCL
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/commandline.h>
#include <isc/mem.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/util.h>

#include <named/omapi.h>

char *progname;
isc_mem_t *mctx;

typedef struct ndc_object {
	OMAPI_OBJECT_PREAMBLE;
} ndc_object_t;

static ndc_object_t ndc_g_ndc;
static omapi_objecttype_t *ndc_type;

/*
 * Send a control command to the server.
 */
static isc_result_t
send_command(omapi_object_t *manager, char *command) {
	omapi_object_t *message = NULL;
	isc_result_t result;

	REQUIRE(manager != NULL && command != NULL);

	/*
	 * Create a new message object to store the information that will
	 * be sent to the server.
	 */
	result = omapi_message_create(&message);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Specify the OPEN operation, with the UPDATE option if requested.
	 */
	result = omapi_object_setinteger(message, "op", OMAPI_OP_OPEN);

	if (result == ISC_R_SUCCESS)
		result = omapi_object_setboolean(message, "update", ISC_TRUE);

	/*
	 * Tell the server the type of the object being opened; it needs
	 * to know this so that it can apply the proper object methods
	 * for lookup/setvalue.
	 */
	if (result == ISC_R_SUCCESS)
		result = omapi_object_setstring(message, "type",
						NS_OMAPI_CONTROL);

	/*
	 * Associate the ndc object with the message, so that it will have its
	 * values stuffed in the message.  Without it, the OPEN operation will
	 * fail because there is no name/value pair to use as a key for looking
	 * up the desired object at the server; this is true even though the
	 * particular object being accessed on the server does not need a key
	 * to be found.
	 *
	 * This object will also have its signal handler called with a
	 * "status" signal that sends the result of the operation on the
	 * server.
	 */
	if (result == ISC_R_SUCCESS)
		result = omapi_object_setobject(message, "object",
						(omapi_object_t *)&ndc_g_ndc);

	/*
	 * Create a generic object to be the outer object for ndc_g_ndc, to
	 * handle the job of storing the command and stuffing it into the
	 * message.
	 *
	 * XXXDCL provide API so client does not need to refer to the
	 * outer member -- does not even need to know about how the whole
	 * outer/inner thing works.
	 */
	if (result == ISC_R_SUCCESS)
		result = omapi_object_create(&ndc_g_ndc.outer, NULL, 0);

	/*
	 * Set the command being sent.
	 */
	if (result == ISC_R_SUCCESS)
		result = omapi_object_setboolean((omapi_object_t *)&ndc_g_ndc,
						 command, ISC_TRUE);

	if (result == ISC_R_SUCCESS) {
		/*
		 * Add the new message to the list of known messages.  When the
		 * server's response comes back, the client will verify that
		 * the response was for a message it really sent.
		 */
		omapi_message_register(message);

		/*
		 * Deliver the message to the server and await its
		 * response.
		 */
		result = omapi_message_send(message, manager);
	}

	/*
	 * Free the generic object and the message.
	 */
	if (ndc_g_ndc.outer != NULL)
		omapi_object_dereference(&ndc_g_ndc.outer);

	omapi_message_unregister(message);
	omapi_object_dereference(&message);

	return (result);
}

/*
 * The signal handler gets the "status" signals when the server's response
 * is processed.  It also gets the "updated" signal after all the values
 * from the server have been incorporated via ndc_setvalue.
 */
static isc_result_t
ndc_signalhandler(omapi_object_t *handle, const char *name, va_list ap) {
	ndc_object_t *ndc;
	omapi_value_t *tv;
	isc_region_t region;
	isc_result_t result;

	REQUIRE(handle->type == ndc_type);

	ndc = (ndc_object_t *)handle;

	if (strcmp(name, "status") == 0) {
		/*
		 * "status" is signalled with the result of the message's
		 * operation.
		 */
		ndc->waitresult = va_arg(ap, isc_result_t);

		if (ndc->waitresult != ISC_R_SUCCESS) {
			fprintf(stderr, "%s: operation failed: %s",
				progname, isc_result_totext(ndc->waitresult));

			tv = va_arg(ap, omapi_value_t *);
			if (tv != NULL) {
				omapi_value_getregion(tv, &region);
				fprintf(stderr, " (%.*s)",
					(int)region.length, region.base);
			}
			fprintf(stderr, "\n");
		}

		/*
		 * Even if the waitresult was not ISC_R_SUCCESS, the processing
		 * by the function still was.
		 */
		result = ISC_R_SUCCESS;

	} else if (strcmp(name, "updated") == 0) {
		/*
		 * Nothing to do, really.
		 */
		result = ISC_R_SUCCESS;

        } else {
		/*
		 * Pass any unknown signal any internal object.
		 * (This normally does not happen; there is no
		 * inner object, nor anything else being signalled.)
		 */
		fprintf(stderr, "%s: ndc_signalhandler: unknown signal: %s",
			progname, name);
		result = omapi_object_passsignal(handle, name, ap);
	}

	return (result);
}

static void
usage(void) {
	fprintf(stderr, "\
Usage: %s [-p port] [-m] server command [command ...]\n\
\n\
Where command is one of the following for named:\n\
\n\
  *status	Display ps(1) status of named.\n\
  *dumpdb	Dump database and cache to /var/tmp/named_dump.db.\n\
  reload	Reload configuration file and zones.\n\
  *stats	Dump statistics to /var/tmp/named.stats.\n\
  *trace	Increment debugging level by one.\n\
  *notrace	Set debugging level to 0.\n\
  *querylog	Toggle query logging.\n\
  *stop		Stop the server.\n\
  *restart	Restart the server.\n\
\n\
* == not yet implemented\n",
		progname);
}

#undef DO
#define DO(name, function) \
	do { \
		if (result == ISC_R_SUCCESS) { \
			result = function; \
			if (result != ISC_R_SUCCESS) \
				fprintf(stderr, "%s: %s: %s\n", progname, \
					name, isc_result_totext(result)); \
		} \
	} while (0)

int
main(int argc, char **argv) {
	isc_socketmgr_t *socketmgr;
	isc_taskmgr_t *taskmgr;
	omapi_object_t *omapimgr = NULL;
	isc_boolean_t show_final_mem = ISC_FALSE;
	isc_result_t result = ISC_R_SUCCESS;
	char *command, *server;
	unsigned int port = NS_OMAPI_PORT;
	int ch;

	progname = strrchr(*argv, '/');
	if (progname != NULL)
		progname++;
	else
		progname = *argv;

	while ((ch = isc_commandline_parse(argc, argv, "mp:")) != -1) {
		switch (ch) {
		case 'm':
			show_final_mem = ISC_TRUE;
			break;

		case 'p':
			port = atoi(isc_commandline_argument);
			if (port > 65535) {
				fprintf(stderr, "%s: port out of range\n",
					progname);
				exit(1);
			}
			break;

		case '?':
			usage();
			exit(1);
			break;
		default:
			fprintf(stderr, "%s: unexpected error parsing "
				"command arguments: got %c\n", progname, ch);
			exit(1);
			break;
		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc < 2) {
		usage();
		exit(1);
	}

	server = *argv;

	DO("create memory context", isc_mem_create(0, 0, &mctx));
	DO("create socket manager", isc_socketmgr_create(mctx, &socketmgr));
	DO("create task manager", isc_taskmgr_create(mctx, 1, 0, &taskmgr));

	DO("initialize omapi",  omapi_lib_init(mctx, taskmgr, socketmgr));

	DO("register omapi object",
	   omapi_object_register(&ndc_type, "ndc",
				 NULL,			/* setvalue */
				 NULL,			/* getvalue */
				 NULL,			/* destroy */
				 ndc_signalhandler,
				 NULL,			/* stuffvalues */
				 NULL,			/* lookup */
				 NULL,			/* create */
				 NULL));		/* remove */

	/*
	 * Initialize the static ndc_g_ndc variable (normally this is done
	 * by omapi_object_create on a dynamic variable).
	 */
	ndc_g_ndc.refcnt = 1;
	ndc_g_ndc.type = ndc_type;

	DO("create protocol manager",
	   omapi_object_create(&omapimgr, NULL, 0));

	DO("connect", omapi_protocol_connect(omapimgr, server, port, NULL));

	/*
	 * Preload the waitresult as successful.
	 */
	ndc_g_ndc.waitresult = ISC_R_SUCCESS;

	while ((command = *++argv) != NULL &&
	       result == ISC_R_SUCCESS &&
	       ndc_g_ndc.waitresult == ISC_R_SUCCESS) {

		if (strcmp(command, "dumpdb") == 0) {
			result = ISC_R_NOTIMPLEMENTED;
			
		} else if (strcmp(command, "notrace") == 0) {
			result = ISC_R_NOTIMPLEMENTED;

		} else if (strcmp(command, "querylog") == 0 ||
			   strcmp(command, "qrylog") == 0) {
			result = ISC_R_NOTIMPLEMENTED;

		} else if (strcmp(command, "reload") == 0) {
			result = send_command(omapimgr, command);

		} else if (strcmp(command, "restart") == 0) {
			result = ISC_R_NOTIMPLEMENTED;

		} else if (strcmp(command, "stats") == 0) {
			result = ISC_R_NOTIMPLEMENTED;

		} else if (strcmp(command, "status") == 0) {
			result = ISC_R_NOTIMPLEMENTED;

		} else if (strcmp(command, "stop") == 0) {
			result = ISC_R_NOTIMPLEMENTED;

		} else if (strcmp(command, "trace") == 0) {
			result = ISC_R_NOTIMPLEMENTED;
		}

		if (result == ISC_R_NOTIMPLEMENTED)
			fprintf(stderr, "%s: '%s' is not yet implemented\n",
				progname, command);

		else if (result != ISC_R_SUCCESS)
			fprintf(stderr, "%s: protocol failure: %s\n",
				progname, isc_result_totext(result));

		else if (ndc_g_ndc.waitresult != ISC_R_SUCCESS)
			fprintf(stderr, "%s: %s command failure: %s\n",
				progname, command,
				isc_result_totext(ndc_g_ndc.waitresult));

		else
			fprintf(stdout, "%s: %s command successful\n",
				progname, command);
	}

	/*
	 * Close the connection and wait to be disconnected.  The connection
	 * is only still open if the protocol object is still attached
	 * to the omapimgr.
	 */
	if (omapimgr != NULL) {
		omapi_protocol_disconnect(omapimgr, OMAPI_CLEAN_DISCONNECT);

		/*
		 * Free the protocol manager.
		 */
		omapi_object_dereference(&omapimgr);
	}

	isc_socketmgr_destroy(&socketmgr);
	isc_taskmgr_destroy(&taskmgr);

	omapi_lib_destroy();

	if (mctx != NULL) {
		if (show_final_mem)
			isc_mem_stats(mctx, stderr);

		isc_mem_destroy(&mctx);
	}

	if (result != ISC_R_SUCCESS || ndc_g_ndc.waitresult != ISC_R_SUCCESS)
		exit(1);

	return (0);
}
