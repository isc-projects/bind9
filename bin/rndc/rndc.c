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

/* $Id: rndc.c,v 1.42 2001/02/16 00:41:43 bwelling Exp $ */

/*
 * Principal Author: DCL
 */

#include <config.h>

#include <stdlib.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/socket.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/util.h>

#include <isccfg/cfg.h>

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
Usage: %s [-c config] [-s server] [-p port] [-y key] [-z zone] [-v view]\n\
	command [command ...]\n\
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
  trace		Increment debugging level by one.\n\
  trace level	Change the debugging level.\n\
  notrace	Set debugging level to 0.\n\
  *status	Display ps(1) status of named.\n\
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
	isc_result_t result = ISC_R_SUCCESS;
	isc_socketmgr_t *socketmgr = NULL;
	isc_taskmgr_t *taskmgr = NULL;
	isc_log_t *log = NULL;
	isc_logconfig_t *logconfig = NULL;
	isc_logdestination_t logdest;
	omapi_object_t *omapimgr = NULL;
	cfg_parser_t *pctx = NULL;
	cfg_obj_t *config = NULL;
	cfg_obj_t *options = NULL;
	cfg_obj_t *servers = NULL;
	cfg_obj_t *server = NULL;
	cfg_obj_t *defkey = NULL;
	cfg_obj_t *keys = NULL;
	cfg_obj_t *key = NULL;
	cfg_obj_t *secretobj = NULL;
	cfg_obj_t *algorithmobj = NULL;
	cfg_listelt_t *elt;
	const char *keyname = NULL;
	const char *secret;
	const char *algorithm;
	char secretarray[1024];
	isc_buffer_t secretbuf;
	char *command, *args, *p;
	size_t argslen;
	const char *servername = NULL;
	int alg;
	unsigned int port = NS_OMAPI_PORT;
	int ch;
	int i;

	progname = strrchr(*argv, '/');
	if (progname != NULL)
		progname++;
	else
		progname = *argv;

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

	DO("create logging context", isc_log_create(mctx, &log, &logconfig));
	isc_log_setcontext(log);
	DO("setting log tag", isc_log_settag(logconfig, progname));
	logdest.file.stream = stderr;
	logdest.file.name = NULL;
	logdest.file.versions = ISC_LOG_ROLLNEVER;
	logdest.file.maximum_size = 0;
	DO("creating log channel",
	   isc_log_createchannel(logconfig, "stderr",
		   		 ISC_LOG_TOFILEDESC, ISC_LOG_INFO, &logdest,
				 ISC_LOG_PRINTTAG|ISC_LOG_PRINTLEVEL));
	DO("enabling log channel", isc_log_usechannel(logconfig, "stderr",
						      NULL, NULL));

	DO("create parser", cfg_parser_create(mctx, log, &pctx));
	result = cfg_parse_file(pctx, conffile, &cfg_type_rndcconf, &config);
	if (result != ISC_R_SUCCESS)
		exit(1);

	(void)cfg_map_get(config, "options", &options);

	if (servername == NULL && options != NULL) {
		cfg_obj_t *defserverobj = NULL;
		(void)cfg_map_get(options, "default-server", &defserverobj);
		if (defserverobj != NULL)
			servername = cfg_obj_asstring(defserverobj);
	}

	if (servername == NULL) {
		fprintf(stderr, "%s: no server specified and no default\n",
			progname);
		exit(1);
	}

	cfg_map_get(config, "server", &servers);
	if (servers != NULL) {
		for (elt = cfg_list_first(servers);
		     elt != NULL; 
		     elt = cfg_list_next(elt))
		{
			const char *name;
			server = cfg_listelt_value(elt);
			name = cfg_obj_asstring(cfg_map_getname(server));
			if (strcasecmp(name, servername) == 0)
				break;
			server = NULL;
		}
	}

	/*
	 * Look for the name of the key to use.
	 */
	if (keyname != NULL)
		;		/* Was set on command line, do nothing. */
	else if (server != NULL)
		DO("get key for server", cfg_map_get(server, "key", &defkey));
	else if (options != NULL) {
		DO("get default key", cfg_map_get(options, "default-key",
						  &defkey));
	} else {
		fprintf(stderr, "%s: no key for server and no default\n",
			progname);
		exit(1);
	}
	keyname = cfg_obj_asstring(defkey);

	/*
	 * Get the key's definition.
	 */
	DO("get config key list", cfg_map_get(config, "key", &keys));
	for (elt = cfg_list_first(keys);
	     elt != NULL; 
	     elt = cfg_list_next(elt))
	{
		key = cfg_listelt_value(elt);
		if (strcasecmp(cfg_obj_asstring(cfg_map_getname(key)),
			       keyname) == 0)
			break;
		key = NULL;
	}

	(void)cfg_map_get(key, "secret", &secretobj);
	(void)cfg_map_get(key, "algorithm", &algorithmobj);
	if (secretobj == NULL || algorithmobj == NULL) {
		fprintf(stderr, "%s: key must have algorithm and secret\n",
			progname);
		exit(1);
	}
	secret = cfg_obj_asstring(secretobj);
	algorithm = cfg_obj_asstring(algorithmobj);

	if (strcasecmp(algorithm, "hmac-md5") == 0)
		alg = OMAPI_AUTH_HMACMD5;
	else {
		fprintf(stderr, "%s: unsupported algorithm: %s\n",
			progname, algorithm);
		exit(1);
	}

	isc_buffer_init(&secretbuf, secretarray, sizeof(secretarray));
	DO("decode base64 secret",
	   isc_base64_decodestring(mctx, secret, &secretbuf));

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
	   omapi_auth_register(keyname, alg, isc_buffer_base(&secretbuf),
			       isc_buffer_usedlength(&secretbuf)));

	DO("create protocol manager", omapi_object_create(&omapimgr, NULL, 0));

	DO("connect", omapi_protocol_connect(omapimgr, servername,
					     (in_port_t)port, NULL));

	DO("send remote authenticator",
	   omapi_auth_use(omapimgr, keyname, alg));

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

	if (strcmp(command, "restart") == 0 ||
	    strcmp(command, "status") == 0) {
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

	cfg_obj_destroy(pctx, &config);
	cfg_parser_destroy(&pctx);

	omapi_lib_destroy();

	isc_socketmgr_destroy(&socketmgr);
	isc_taskmgr_destroy(&taskmgr);
	isc_log_destroy(&log);
	isc_log_setcontext(NULL);

	if (show_final_mem)
		isc_mem_stats(mctx, stderr);

	isc_mem_destroy(&mctx);

	if (result != ISC_R_SUCCESS || ndc_g_ndc.waitresult != ISC_R_SUCCESS)
		exit(1);

	return (0);
}
