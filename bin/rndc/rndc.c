/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
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

/* $Id: rndc.c,v 1.37.2.4 2001/03/29 18:23:18 gson Exp $ */

/*
 * Principal Author: DCL
 */

#include <config.h>

#include <stdlib.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/entropy.h>
#include <isc/mem.h>
#include <isc/socket.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/confndc.h>
#include <dns/result.h>

#include <dst/dst.h>

#include <omapi/result.h>

#include <named/omapi.h>

static const char *progname;
static const char *conffile = RNDC_SYSCONFDIR "/rndc.conf";
static const char *version = VERSION;

static isc_boolean_t verbose;
static isc_mem_t *mctx;

typedef struct ndc_object {
	OMAPI_OBJECT_PREAMBLE;
} ndc_object_t;

#define REGION_FMT(x) (int)(x)->length, (x)->base

static ndc_object_t ndc_g_ndc;
static omapi_objecttype_t *ndc_type;

static void
notify(const char *fmt, ...) {
	va_list ap;

	if (verbose) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fputs("\n", stderr);
	}
}

/*
 * Send a control command to the server.  'command' is the command
 * name, and 'args' is a space-delimited sequence of words, the
 * first being the command name itself.
 */
static isc_result_t
send_command(omapi_object_t *manager, char *command, char *args) {
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
	result = omapi_object_setstring((omapi_object_t *)&ndc_g_ndc,
					command, args);

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
	notify("ndc_signalhandler: %s", name);

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

static isc_result_t
ndc_setvalue(omapi_object_t *handle, omapi_string_t *name,
	     omapi_data_t *value)
{
	isc_region_t region;
/*
	isc_result_t result;
	char *message;
*/

	INSIST(handle == (omapi_object_t *)&ndc_g_ndc);

	UNUSED(value);
	UNUSED(handle);

	omapi_string_totext(name, &region);
	notify("ndc_setvalue: %.*s\n", REGION_FMT(&region));

	return (ISC_R_SUCCESS);
}

static void
usage(void) {
	fprintf(stderr, "\
Usage: %s [-c config] [-s server] [-p port] [-y key] command\n\
\n\
command is one of the following:\n\
\n\
  reload	Reload configuration file and zones.\n\
  reload zone [class [view]]\n\
		Reload a single zone.\n\
  refresh zone [class [view]]\n\
		Schedule immediate maintenance for a zone.\n\
  stats		Write server statistics to the statistics file.\n\
  querylog	Toggle query logging.\n\
  dumpdb	Dump cache(s) to the dump file (named_dump.db).\n\
  stop		Save pending updates to master files and stop the server.\n\
  halt		Stop the server without saving pending updates.\n\
  *status	Display ps(1) status of named.\n\
  *trace	Increment debugging level by one.\n\
  *notrace	Set debugging level to 0.\n\
  *restart	Restart the server.\n\
\n\
* == not yet implemented\n\
Version: %s\n",
		progname, version);
}

#undef DO
#define DO(name, function) \
	do { \
		result = function; \
		if (result != ISC_R_SUCCESS) { \
			fprintf(stderr, "%s: %s: %s\n", progname, \
				name, isc_result_totext(result)); \
			exit(1); \
		} else \
			notify(name); \
	} while (0)

int
main(int argc, char **argv) {
	isc_boolean_t show_final_mem = ISC_FALSE;
	isc_entropy_t *entropy = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	isc_socketmgr_t *socketmgr = NULL;
	isc_taskmgr_t *taskmgr = NULL;
	omapi_object_t *omapimgr = NULL;
	dns_c_ndcctx_t *config = NULL;
	dns_c_ndcopts_t *configopts = NULL;
	dns_c_ndcserver_t *server = NULL;
	dns_c_kdeflist_t *keys = NULL;
	dns_c_kdef_t *key = NULL;
	const char *keyname = NULL;
	char secret[1024];
	isc_buffer_t secretbuf;
	char *command, *args, *p;
	size_t argslen;
	const char *servername = NULL;
	const char *host = NULL;
	unsigned int port = NS_OMAPI_PORT;
	unsigned int algorithm;
	int ch;
	int i;

	progname = strrchr(*argv, '/');
	if (progname != NULL)
		progname++;
	else
		progname = *argv;

	omapi_result_register();
	dns_result_register();

	while ((ch = isc_commandline_parse(argc, argv, "c:Mmp:s:Vy:"))
	       != -1) {
		switch (ch) {
		case 'c':
			conffile = isc_commandline_argument;
			break;

		case 'M':
			isc_mem_debugging = 1;
			break;

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

		case 's':
			servername = isc_commandline_argument;
			break;
		case 'V':
			verbose = ISC_TRUE;
			break;
		case 'y':
			keyname = isc_commandline_argument;
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

	if (argc < 1) {
		usage();
		exit(1);
	}

	DO("create memory context", isc_mem_create(0, 0, &mctx));
	DO("create socket manager", isc_socketmgr_create(mctx, &socketmgr));
	DO("create task manager", isc_taskmgr_create(mctx, 1, 0, &taskmgr));

	DO("create entropy pool", isc_entropy_create(mctx, &entropy));
	/* XXXDCL probably should use ISC_ENTROPY_GOOD.  talk with graff. */
	DO("initialize digital signatures",
	   dst_lib_init(mctx, entropy, 0));

	DO(conffile, dns_c_ndcparseconf(conffile, mctx, &config));

	(void)dns_c_ndcctx_getoptions(config, &configopts);

	if (servername == NULL && configopts != NULL)
		(void)dns_c_ndcopts_getdefserver(configopts, &servername);

	if (servername != NULL)
		result = dns_c_ndcctx_getserver(config, servername, &server);
	else {
		fprintf(stderr, "%s: no server specified and no default\n",
			progname);
		exit(1);
	}

	/*
	 * Look for the name of the key to use.
	 */
	if (keyname != NULL)
		;		/* Was set on command line, do nothing. */
	else if (server != NULL)
		DO("get key for server", dns_c_ndcserver_getkey(server,
								&keyname));
	else if (configopts != NULL)
		DO("get default key",
		   dns_c_ndcopts_getdefkey(configopts, &keyname));
	else {
		fprintf(stderr, "%s: no key for server and no default\n",
			progname);
		exit(1);
	}

	/*
	 * Get the key's definition.
	 */
	DO("get config key list", dns_c_ndcctx_getkeys(config, &keys));
	DO("get key definition", dns_c_kdeflist_find(keys, keyname, &key));

	/* XXX need methods for structure access? */
	INSIST(key->secret != NULL);
	INSIST(key->algorithm != NULL);

	if (strcasecmp(key->algorithm, "hmac-md5") == 0)
		algorithm = OMAPI_AUTH_HMACMD5;
	else {
		fprintf(stderr, "%s: unsupported algorithm: %s\n",
			progname, key->algorithm);
		exit(1);
	}

	isc_buffer_init(&secretbuf, secret, sizeof(secret));
	DO("decode base64 secret",
	   isc_base64_decodestring(mctx, key->secret, &secretbuf));

	if (server != NULL)
		(void)dns_c_ndcserver_gethost(server, &host);

	if (host == NULL)
		host = servername;

	DO("initialize omapi",  omapi_lib_init(mctx, taskmgr, socketmgr));

	DO("register omapi object",
	   omapi_object_register(&ndc_type, "ndc",
				 ndc_setvalue,		/* setvalue */
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

	DO("register local authenticator",
	   omapi_auth_register(keyname, algorithm, isc_buffer_base(&secretbuf),
			       isc_buffer_usedlength(&secretbuf)));

	DO("create protocol manager", omapi_object_create(&omapimgr, NULL, 0));

	DO("connect", omapi_protocol_connect(omapimgr, host, (in_port_t)port,
					     NULL));

	DO("send remote authenticator",
	   omapi_auth_use(omapimgr, keyname, algorithm));

	/*
	 * Preload the waitresult as successful.
	 */
	ndc_g_ndc.waitresult = ISC_R_SUCCESS;

	command = *argv;

	/*
	 * Convert argc/argv into a space-delimited command string
	 * similar to what the user might enter in interactive mode
	 * (if that were implemented).
	 */
	argslen = 0;
	for (i = 0; i < argc; i++)
		argslen += strlen(argv[i]) + 1;

	args = isc_mem_get(mctx, argslen);
	if (args == NULL)
		DO("isc_mem_get", ISC_R_NOMEMORY);

	p = args;
	for (i = 0; i < argc; i++) {
		size_t len = strlen(argv[i]);
		memcpy(p, argv[i], len);
		p += len;
		*p++ = ' ';
	}

	p--;
	*p++ = '\0';
	INSIST(p == args + argslen);

	notify(command);

	if (strcmp(command, "notrace") == 0 ||
	    strcmp(command, "restart") == 0 ||
	    strcmp(command, "status") == 0 ||
	    strcmp(command, "trace") == 0) {
		result = ISC_R_NOTIMPLEMENTED;
	} else {
		result = send_command(omapimgr, command, args);
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
		printf("%s: %s command successful\n",
		       progname, command);

	isc_mem_put(mctx, args, argslen);

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

	dns_c_ndcctx_destroy(&config);

	omapi_lib_destroy();

	dst_lib_destroy();
	isc_entropy_detach(&entropy);

	isc_socketmgr_destroy(&socketmgr);
	isc_taskmgr_destroy(&taskmgr);

	if (mctx != NULL) {
		if (show_final_mem)
			isc_mem_stats(mctx, stderr);

		isc_mem_destroy(&mctx);
	}

	if (result != ISC_R_SUCCESS || ndc_g_ndc.waitresult != ISC_R_SUCCESS)
		exit(1);

	return (0);
}
