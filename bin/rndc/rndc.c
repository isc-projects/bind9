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

/* $Id: rndc.c,v 1.53 2001/04/11 20:37:39 bwelling Exp $ */

/*
 * Principal Author: DCL
 */

#include <config.h>

#include <stdlib.h>
#include <netdb.h>

#include <isc/app.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/socket.h>
#include <isc/stdtime.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/util.h>

#include <isccfg/cfg.h>

#include <isccc/alist.h>
#include <isccc/base64.h>
#include <isccc/cc.h>
#include <isccc/ccmsg.h>
#include <isccc/result.h>
#include <isccc/sexpr.h>
#include <isccc/types.h>
#include <isccc/util.h>

#define NS_CONTROL_PORT		953

#ifdef HAVE_ADDRINFO
#ifdef HAVE_GETADDRINFO
#ifdef HAVE_GAISTRERROR
#define USE_GETADDRINFO
#endif
#endif
#endif

#ifndef USE_GETADDRINFO
extern int h_errno;
#endif

static const char *progname;
static const char *conffile = RNDC_SYSCONFDIR "/rndc.conf";
static const char *version = VERSION;
static unsigned int remoteport = NS_CONTROL_PORT;
static const char *servername = NULL;
static isc_socketmgr_t *socketmgr = NULL;
static unsigned char databuf[2048];
static isccc_ccmsg_t ccmsg;
static char *args;
static isc_boolean_t have_ipv4, have_ipv6;
static isccc_region_t secret;
static isc_boolean_t verbose;
static isc_boolean_t failed = ISC_FALSE;
static isc_mem_t *mctx;
char *command;

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

static void
usage(void) {
	fprintf(stderr, "\
Usage: %s [-c config] [-s server] [-p port] [-y key] [-V] command\n\
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
  flush		Flushes the server's cache.\n\
  *status	Display ps(1) status of named.\n\
  *restart	Restart the server.\n\
\n\
* == not yet implemented\n\
Version: %s\n",
		progname, version);
}

static void            
fatal(const char *format, ...) {
	va_list args;

	fprintf(stderr, "%s: ", progname);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(1);
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


static void
get_address(const char *host, in_port_t port, isc_sockaddr_t *sockaddr) {
	struct in_addr in4;
	struct in6_addr in6;
#ifdef USE_GETADDRINFO
	struct addrinfo *res = NULL, hints;
	int result;
#else
	struct hostent *he;
#endif

	/*
	 * Assume we have v4 if we don't have v6, since setup_libs
	 * fatal()'s out if we don't have either.
	 */
	if (have_ipv6 && inet_pton(AF_INET6, host, &in6) == 1)
		isc_sockaddr_fromin6(sockaddr, &in6, port);
	else if (inet_pton(AF_INET, host, &in4) == 1)
		isc_sockaddr_fromin(sockaddr, &in4, port);
	else {
#ifdef USE_GETADDRINFO
		memset(&hints, 0, sizeof(hints));
		if (!have_ipv6)
			hints.ai_family = PF_INET;
		else if (!have_ipv4)
			hints.ai_family = PF_INET6;
		else
			hints.ai_family = PF_UNSPEC;
		isc_app_block();
		result = getaddrinfo(host, NULL, &hints, &res);
		isc_app_unblock();
		if (result != 0)
			fatal("Couldn't find server '%s': %s",
			      host, gai_strerror(result));
		memcpy(&sockaddr->type.sa,res->ai_addr, res->ai_addrlen);
		sockaddr->length = res->ai_addrlen;
		isc_sockaddr_setport(sockaddr, port);
		freeaddrinfo(res);
#else
		isc_app_block();
		he = gethostbyname(host);
		isc_app_unblock();
		if (he == NULL)
			fatal("Couldn't find server '%s' (h_errno=%d)",
			      host, h_errno);
		INSIST(he->h_addrtype == AF_INET);
		isc_sockaddr_fromin(sockaddr,
				    (struct in_addr *)(he->h_addr_list[0]),
				    port);
#endif
	}
}

static void
rndc_senddone(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;

	UNUSED(task);

	if (sevent->result != ISC_R_SUCCESS)
		fatal("send failed: %s", isc_result_totext(sevent->result));
	isc_event_free(&event);
}

static void
rndc_recvdone(isc_task_t *task, isc_event_t *event) {
	isc_socket_t *sock = ccmsg.sock;
	isccc_sexpr_t *response = NULL;
	isccc_sexpr_t *data;
	isccc_region_t source;
	char *errormsg = NULL;
	isc_result_t result;

	if (ccmsg.result == ISC_R_EOF) {
		fprintf(stderr, "%s: connection to remote host closed\n",
			progname);
		fprintf(stderr,
			"This may indicate that the remote server is using "
			"an older version of the\n"
			"command protocol, this host is not authorized "
			"to connect, or the key is invalid.\n");
		exit(1);
	}

	if (ccmsg.result != ISC_R_SUCCESS)
		fatal("recv failed: %s", isc_result_totext(ccmsg.result));

	source.rstart = isc_buffer_base(&ccmsg.buffer);
	source.rend = isc_buffer_used(&ccmsg.buffer);
	DO("parse message", isccc_cc_fromwire(&source, &response, &secret));
	data = isccc_alist_lookup(response, "_data");
	if (data == NULL)
		fatal("no data section in response");
	result = isccc_cc_lookupstring(data, "err", &errormsg);
	if (result == ISC_R_SUCCESS) {
		failed = ISC_TRUE;
		fprintf(stderr, "%s: '%s' failed: %s\n",
			progname, command, errormsg);
	}
	else if (result != ISC_R_NOTFOUND)
		fprintf(stderr, "%s: parsing response failed: %s\n",
			progname, isc_result_totext(result));

	isc_event_free(&event);
	isccc_sexpr_free(&response);
	isc_socket_detach(&sock);
	isc_task_shutdown(task);
	isc_app_shutdown();
}

static void
rndc_connected(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;
	isc_socket_t *sock = event->ev_sender;
	isccc_sexpr_t *request = NULL;
	isccc_sexpr_t *data;
	isccc_time_t now;
	isccc_region_t message;
	isc_region_t r;
	isc_uint32_t len;
	isc_buffer_t b;
	isc_result_t result;

	if (sevent->result != ISC_R_SUCCESS)
		fatal("connect failed: %s", isc_result_totext(sevent->result));

	isc_stdtime_get(&now);
	DO("create message", isccc_cc_createmessage(1, NULL, NULL, random(),
						    now, now + 60, &request));
	data = isccc_alist_lookup(request, "_data");
	if (data == NULL)
		fatal("_data section missing");
	if (isccc_cc_definestring(data, "type", args) == NULL)
		fatal("out of memory");
	message.rstart = databuf + 4;
	message.rend = databuf + sizeof(databuf);
	DO("render message", isccc_cc_towire(request, &message, &secret));
	len = sizeof(databuf) - REGION_SIZE(message);
	isc_buffer_init(&b, databuf, 4);
	isc_buffer_putuint32(&b, len - 4);
	r.length = len;
	r.base = databuf;

	isccc_ccmsg_init(mctx, sock, &ccmsg);
	isccc_ccmsg_setmaxsize(&ccmsg, 1024);

	DO("schedule recv", isccc_ccmsg_readmessage(&ccmsg, task,
						    rndc_recvdone, NULL));
	DO("send message", isc_socket_send(sock, &r, task, rndc_senddone,
					   NULL));
	isc_event_free(&event);
	
}

static void
rndc_start(isc_task_t *task, isc_event_t *event) {
	isc_sockaddr_t addr;
	isc_socket_t *sock = NULL;
	isc_result_t result;

	isc_event_free(&event);

	get_address(servername, remoteport, &addr);
	DO("create socket", isc_socket_create(socketmgr,
					      isc_sockaddr_pf(&addr),
					      isc_sockettype_tcp, &sock));
	DO("connect", isc_socket_connect(sock, &addr, task, rndc_connected,
					 NULL));
}

int
main(int argc, char **argv) {
	isc_boolean_t show_final_mem = ISC_FALSE;
	isc_result_t result = ISC_R_SUCCESS;
	isc_taskmgr_t *taskmgr = NULL;
	isc_task_t *task = NULL;
	isc_log_t *log = NULL;
	isc_logconfig_t *logconfig = NULL;
	isc_logdestination_t logdest;
	cfg_parser_t *pctx = NULL;
	cfg_obj_t *config = NULL;
	cfg_obj_t *options = NULL;
	cfg_obj_t *servers = NULL;
	cfg_obj_t *server = NULL;
	cfg_obj_t *defkey = NULL;
	cfg_obj_t *keys = NULL;
	cfg_obj_t *key = NULL;
	cfg_obj_t *defport = NULL;
	cfg_obj_t *secretobj = NULL;
	cfg_obj_t *algorithmobj = NULL;
	cfg_listelt_t *elt;
	const char *keyname = NULL;
	const char *secretstr;
	const char *algorithm;
	isc_boolean_t portset = ISC_FALSE;
	char secretarray[1024];
	char *p;
	size_t argslen;
	int ch;
	int i;

	isc_app_start();

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
			remoteport = atoi(isc_commandline_argument);
			if (remoteport > 65535) {
				fprintf(stderr, "%s: port out of range\n",
					progname);
				exit(1);
			}
			portset = ISC_TRUE;
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
	DO("create task", isc_task_create(taskmgr, 0, &task));

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
	else if (server != NULL) {
		DO("get key for server", cfg_map_get(server, "key", &defkey));
		keyname = cfg_obj_asstring(defkey);
	} else if (options != NULL) {
		DO("get default key", cfg_map_get(options, "default-key",
						  &defkey));
		keyname = cfg_obj_asstring(defkey);
	} else {
		fprintf(stderr, "%s: no key for server and no default\n",
			progname);
		exit(1);
	}

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
	}
	if (elt == NULL) {
		fprintf(stderr, "%s: no key definition for name %s\n",
			progname, keyname);
		exit(1);
	}

	(void)cfg_map_get(key, "secret", &secretobj);
	(void)cfg_map_get(key, "algorithm", &algorithmobj);
	if (secretobj == NULL || algorithmobj == NULL) {
		fprintf(stderr, "%s: key must have algorithm and secret\n",
			progname);
		exit(1);
	}
	secretstr = cfg_obj_asstring(secretobj);
	algorithm = cfg_obj_asstring(algorithmobj);

	if (strcasecmp(algorithm, "hmac-md5") != 0) {
		fprintf(stderr, "%s: unsupported algorithm: %s\n",
			progname, algorithm);
		exit(1);
	}

	secret.rstart = secretarray;
	secret.rend = secretarray + sizeof(secretarray);
	DO("decode base64 secret", isccc_base64_decode(secretstr, &secret));
	secret.rend = secret.rstart;
	secret.rstart = secretarray;

	/*
	 * Find the port to connect to.
	 */
	if (portset)
		;		/* Was set on command line, do nothing. */
	else {
		if (server != NULL)
			(void)cfg_map_get(server, "port", &defport);
		if (defport == NULL && options != NULL)
			cfg_map_get(options, "default-port", &defport);
	}
	if (defport != NULL) {
		remoteport = cfg_obj_asuint32(defport);
		if (remoteport > 65535) {
			fprintf(stderr, "%s: port out of range\n", progname);
			exit(1);
		}
	} else if (!portset)
		remoteport = NS_CONTROL_PORT;

	isccc_result_register();

	have_ipv4 = (isc_net_probeipv4() == ISC_R_SUCCESS);
	have_ipv6 = (isc_net_probeipv6() == ISC_R_SUCCESS);

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

	if (strcmp(command, "restart") == 0 || strcmp(command, "status") == 0)
		fatal("%s: '%s' is not implemented", progname, command);

	DO("post event", isc_app_onrun(mctx, task, rndc_start, NULL));

	isc_app_run();

	isc_mem_put(mctx, args, argslen);

	cfg_obj_destroy(pctx, &config);
	cfg_parser_destroy(&pctx);

	isccc_ccmsg_invalidate(&ccmsg);

	isc_socketmgr_destroy(&socketmgr);
	isc_task_detach(&task);
	isc_taskmgr_destroy(&taskmgr);
	isc_log_destroy(&log);
	isc_log_setcontext(NULL);

	if (show_final_mem)
		isc_mem_stats(mctx, stderr);

	isc_mem_destroy(&mctx);

	if (failed)
		return (1);

	return (0);
}
