/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#include <config.h>

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>

#include <isc/app.h>
#include <isc/error.h>
#include <isc/boolean.h>
#include <isc/commandline.h>
#include <isc/task.h>
#include <isc/timer.h>

#include <dns/dbtable.h>
#include <dns/tsig.h>
#include <dns/result.h>

#include <dst/result.h>

#define NS_MAIN 1

#include <named/globals.h>
#include <named/client.h>
#include <named/interfacemgr.h>
#include <named/server.h>

static isc_boolean_t			want_stats = ISC_FALSE;

static void
early_fatal(char *format, ...) {
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");

	exit(1);
}

static void
usage(void) {
	fprintf(stderr,
		"usage: named [[-c cachefile] ...] [[-z zonefile] ...]\n");
	fprintf(stderr,
		"             [-p port] [-s] [-N number of cpus]\n");
}

static void 
parse_command_line(int argc, char *argv[]) {
	char *argtext, *mastertext, *origintext; 
	int ch;
	ns_dbinfo_t *dbi;

	while ((ch = isc_commandline_parse(argc, argv, "c:N:p:sz:")) != -1) {
		switch (ch) {
		case 'c':
			/* XXXRTH temporary syntax */
			dbi = isc_mem_get(ns_g_mctx, sizeof *dbi);
			if (dbi == NULL)
				early_fatal("creating cache info failed");
			dbi->path = isc_mem_strdup(ns_g_mctx,
						   isc_commandline_argument);
			if (dbi->path == NULL)
				early_fatal("out of memory");
			dbi->origin = isc_mem_strdup(ns_g_mctx, ".");
			if (dbi->origin == NULL)
				early_fatal("out of memory");
			dbi->master = NULL;
			dbi->iscache = ISC_TRUE;
			dbi->isslave = ISC_FALSE;
			dbi->view = NULL;
			dbi->db = NULL;
			ISC_LINK_INIT(dbi, link);
			ISC_LIST_APPEND(ns_g_dbs, dbi, link);
			break;
		case 'N':
			ns_g_cpus = atoi(isc_commandline_argument);
			if (ns_g_cpus == 0)
				ns_g_cpus = 1;
			break;
		case 'p':
			ns_g_port = atoi(isc_commandline_argument);
			break;
		case 's':
			/* XXXRTH temporary syntax */
			want_stats = ISC_TRUE;
			break;
		case 'z':
			/* XXXRTH temporary syntax */
			dbi = isc_mem_get(ns_g_mctx, sizeof *dbi);
			if (dbi == NULL)
				early_fatal("creating zone info failed");
			argtext = isc_mem_strdup(ns_g_mctx,
						 isc_commandline_argument);
			if (argtext == NULL)
				early_fatal("out of memory");
			mastertext = strrchr(argtext, '@');
			if (mastertext == NULL) {
				dbi->master = NULL;
				dbi->isslave = ISC_FALSE;
			} else {
				*mastertext++ = '\0';
				dbi->master = isc_mem_strdup(ns_g_mctx,
							     mastertext);
				if (dbi->master == NULL)
					early_fatal("out of memory");
				
				RUNTIME_CHECK(dbi->master != NULL);
				dbi->isslave = ISC_TRUE;
			}
			
			origintext = strrchr(argtext, '/');
			if (origintext == NULL)
				origintext = argtext;
			else
				origintext++;	/* Skip '/'. */

			dbi->path = isc_mem_strdup(ns_g_mctx, argtext);
			if (dbi->path == NULL)
				early_fatal("out of memory");
			dbi->origin = isc_mem_strdup(ns_g_mctx, origintext);
			if (dbi->origin == NULL)
				early_fatal("out of memory");
			dbi->view = NULL;
			dbi->db = NULL;
			dbi->iscache = ISC_FALSE;
			isc_mem_free(ns_g_mctx, argtext);
			ISC_LINK_INIT(dbi, link);
			ISC_LIST_APPEND(ns_g_dbs, dbi, link);
			break;
		case '?':
			usage();
			early_fatal("unknown command line argument");
			break;
		default:
			early_fatal("parsing options returned %d", ch);
		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc > 1) {
		usage();
		early_fatal("extra command line arguments");
	}
}

static isc_result_t
create_managers() {
	isc_result_t result;

	result = isc_taskmgr_create(ns_g_mctx, ns_g_cpus, 0, &ns_g_taskmgr);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "ns_taskmgr_create() failed: %s\n",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	result = isc_timermgr_create(ns_g_mctx, &ns_g_timermgr);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "ns_timermgr_create() failed: %s\n",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	result = isc_socketmgr_create(ns_g_mctx, &ns_g_socketmgr);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_socketmgr_create() failed: %s\n",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	result = ns_clientmgr_create(ns_g_mctx, ns_g_taskmgr, ns_g_timermgr,
				     &ns_g_clientmgr);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "ns_clientmgr_create() failed: %s\n",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	result = ns_interfacemgr_create(ns_g_mctx, ns_g_taskmgr,
					ns_g_socketmgr, ns_g_clientmgr,
					&ns_g_interfacemgr);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "ns_interfacemgr_create() failed: %s\n",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	return (ISC_R_SUCCESS);
}

static void
destroy_managers(void) {
	/*
	 * The interface manager owns tasks, so we have to destroy it before
	 * we destroy the task manager.
	 */
	ns_interfacemgr_destroy(&ns_g_interfacemgr);
	/*
	 * isc_taskmgr_destroy() will  block until all tasks have exited,
	 */
	isc_taskmgr_destroy(&ns_g_taskmgr);
	isc_timermgr_destroy(&ns_g_timermgr);
	isc_socketmgr_destroy(&ns_g_socketmgr);
	ns_clientmgr_destroy(&ns_g_clientmgr);
}

static void
setup() {
	isc_result_t result;

	ISC_LIST_INIT(ns_g_viewlist);

	result = isc_rwlock_init(&ns_g_viewlock, 0, 0);
	if (result != ISC_R_SUCCESS)
		early_fatal("isc_rwlock_init() failed: %s",
			    isc_result_totext(result));

	result = create_managers();
	if (result != ISC_R_SUCCESS)
		early_fatal("create_managers() failed: %s",
			    isc_result_totext(result));

	result = ns_server_init();
	if (result != ISC_R_SUCCESS)
		early_fatal("ns_server_init() failed: %s",
			    isc_result_totext(result));

	result = dns_tsig_init(ns_g_mctx);
	if (result != ISC_R_SUCCESS)
		early_fatal("dns_tsig_init() failed: %s",
			    isc_result_totext(result));
}

static void
cleanup() {
	destroy_managers();
	dns_tsig_destroy();
#if 0
	isc_rwlock_destroy(&ns_g_viewlock);
#endif
}

int
main(int argc, char *argv[]) {
	isc_result_t result;

	result = isc_app_start();
	if (result != ISC_R_SUCCESS)
		early_fatal("isc_app_start() failed: %s",
			    isc_result_totext(result));

	result = isc_mem_create(0, 0, &ns_g_mctx);
	if (result != ISC_R_SUCCESS)
		early_fatal("isc_mem_create() failed: %s",
			    isc_result_totext(result));

	dns_result_register();
	dst_result_register();

	parse_command_line(argc, argv);

	setup();

	/*
	 * Start things running and then wait for a shutdown request.
	 */
	result = isc_app_run();
	if (result != ISC_R_SUCCESS)
		UNEXPECTED_ERROR(__FILE__, __LINE__, "isc_app_run(): %s",
				 isc_result_totext(result));

	cleanup();

	if (want_stats)
		isc_mem_stats(ns_g_mctx, stdout);
	isc_mem_destroy(&ns_g_mctx);

	isc_app_finish();

	return (0);
}
