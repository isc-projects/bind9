/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

#include <stdlib.h>

#include <isc/app.h>
#include <isc/commandline.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/dispatch.h>

#include <dst/result.h>

/*
 * Defining NS_MAIN provides storage declaratons (rather than extern)
 * for variables in named/globals.h.
 */
#define NS_MAIN 1		

#include <named/globals.h>	/* Explicit, though named/log.h includes it. */
#include <named/interfacemgr.h>
#include <named/log.h>
#include <named/omapi.h>
#include <named/os.h>
#include <named/server.h>
#include <named/main.h>

static isc_boolean_t	want_stats = ISC_FALSE;
static const char *	program_name = "named";

void
ns_main_earlyfatal(const char *format, ...) {
	va_list args;

	va_start(args, format);
	if (ns_g_lctx != NULL) {
		isc_log_vwrite(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			       NS_LOGMODULE_MAIN, ISC_LOG_CRITICAL,
			       format, args);
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			       NS_LOGMODULE_MAIN, ISC_LOG_CRITICAL,
			       "exiting (due to early fatal error)");
	} else {
		fprintf(stderr, "%s: ", program_name);
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
		fflush(stderr);
	}
	va_end(args);

	exit(1);
}

static void
assertion_failed(const char *file, int line, isc_assertiontype_t type,
		 const char *cond)
{
	/*
	 * Handle assertion failures.
	 */

	if (ns_g_lctx != NULL) {
		/*
		 * Reset the assetion callback in case it is the log
		 * routines causing the assertion.
		 */
		isc_assertion_setcallback(NULL);

		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_MAIN, ISC_LOG_CRITICAL,
			      "%s:%d: %s(%s) failed", file, line,
			      isc_assertion_typetotext(type), cond);
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			       NS_LOGMODULE_MAIN, ISC_LOG_CRITICAL,
			       "exiting (due assertion failure)");
	} else {
		fprintf(stderr, "%s:%d: %s(%s) failed\n",
			file, line, isc_assertion_typetotext(type), cond);
		fflush(stderr);
	}

	if (ns_g_coreok)
		abort();
	exit(1);
}

static void
library_fatal_error(const char *file, int line, const char *format,
		    va_list args)
{
	/*
	 * Handle isc_error_fatal() calls from our libraries.
	 */

	if (ns_g_lctx != NULL) {
		/*
		 * Reset the error callback in case it is the log
		 * routines causing the assertion.
		 */
		isc_error_setfatal(NULL);

		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_MAIN, ISC_LOG_CRITICAL,
			      "%s:%d: fatal error:", file, line);
		isc_log_vwrite(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			       NS_LOGMODULE_MAIN, ISC_LOG_CRITICAL,
			       format, args);
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_MAIN, ISC_LOG_CRITICAL,
			      "exiting (due to fatal error in library)");
	} else {
		fprintf(stderr, "%s:%d: fatal error: ", file, line);
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
		fflush(stderr);
	}

	if (ns_g_coreok)
		abort();
	exit(1);
}

static void
library_unexpected_error(const char *file, int line, const char *format,
			 va_list args)
{
	/*
	 * Handle isc_error_unexpected() calls from our libraries.
	 */

	if (ns_g_lctx != NULL) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_MAIN, ISC_LOG_ERROR,
			      "%s:%d: unexpected error:", file, line);
		isc_log_vwrite(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			       NS_LOGMODULE_MAIN, ISC_LOG_ERROR,
			       format, args);
	} else {
		fprintf(stderr, "%s:%d: fatal error: ", file, line);
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
		fflush(stderr);
	}
}

static void
usage(void) {
	fprintf(stderr,
		"usage: named [-c conffile] [-d debuglevel] "
		"[-f|-g] [-n number_of_cpus]\n"
		"             [-p port] [-s] [-t chrootdir] [-u username]\n");
}

static void 
parse_command_line(int argc, char *argv[]) {
	int ch;
	unsigned int port;

	isc_commandline_errprint = ISC_FALSE;
	while ((ch = isc_commandline_parse(argc, argv,
					   "c:d:fgn:N:p:st:u:x:")) !=
	       -1) {
		switch (ch) {
		case 'c':
			ns_g_conffile = isc_commandline_argument;
			break;
		case 'd':
			ns_g_debuglevel = atoi(isc_commandline_argument);
			break;
		case 'f':
			ns_g_foreground = ISC_TRUE;
			break;
		case 'g':
			ns_g_foreground = ISC_TRUE;
			ns_g_logstderr = ISC_TRUE;
			break;
		case 'N': /* Deprecated. */
		case 'n':
			ns_g_cpus = atoi(isc_commandline_argument);
			if (ns_g_cpus == 0)
				ns_g_cpus = 1;
			break;
		case 'p':
			port = atoi(isc_commandline_argument);
			if (port < 1 || port > 65535)
				ns_main_earlyfatal("port '%s' out of range",
						   isc_commandline_argument);
			ns_g_port = port;
			break;
		case 's':
			/* XXXRTH temporary syntax */
			want_stats = ISC_TRUE;
			break;
		case 't':
			/* XXXJAB should we make a copy? */
			ns_g_chrootdir = isc_commandline_argument;
			break;
		case 'u':
			ns_g_username = isc_commandline_argument;
			break;
		case 'x':
			/* XXXRTH temporary syntax */
			ns_g_cachefile = isc_commandline_argument;
			break;
		case '?':
			usage();
			ns_main_earlyfatal("unknown option '-%c'",
					   isc_commandline_option);
		default:
			ns_main_earlyfatal("parsing options returned %d", ch);
		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc > 0) {
		usage();
		ns_main_earlyfatal("extra command line arguments");
	}
}

static isc_result_t
create_managers(void) {
	isc_result_t result;

	result = isc_taskmgr_create(ns_g_mctx, ns_g_cpus, 0, &ns_g_taskmgr);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "ns_taskmgr_create() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	result = isc_timermgr_create(ns_g_mctx, &ns_g_timermgr);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "ns_timermgr_create() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	result = isc_socketmgr_create(ns_g_mctx, &ns_g_socketmgr);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_socketmgr_create() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	return (ISC_R_SUCCESS);
}

static void
destroy_managers(void) {
	if (ns_g_omapimgr != NULL)
		omapi_listener_shutdown(ns_g_omapimgr);
	else
		omapi_lib_destroy();

	/*
	 * isc_taskmgr_destroy() will  block until all tasks have exited,
	 */
	isc_taskmgr_destroy(&ns_g_taskmgr);
	isc_timermgr_destroy(&ns_g_timermgr);
	isc_socketmgr_destroy(&ns_g_socketmgr);
}

static void
setup(void) {
	isc_result_t result;

	ns_os_chroot(ns_g_chrootdir);

	/*
	 * For operating systems which have a capability mechanism, now
	 * is the time to switch to minimal privs and change our user id.
	 * On traditional UNIX systems, this call will be a no-op, and we
	 * will change the user ID after reading the config file the first
	 * time.  (We need to read the config file to know which possibly
	 * privileged ports to bind() to.)
	 */
	ns_os_minprivs(ns_g_username);

	result = ns_log_init(ISC_TF(ns_g_username != NULL));
	if (result != ISC_R_SUCCESS)
		ns_main_earlyfatal("ns_log_init() failed: %s",
				   isc_result_totext(result));

	/*
	 * Now is the time to daemonize (if we're not running in the
	 * foreground).  We waited until now because we wanted to get
	 * a valid logging context setup.  We cannot daemonize any later,
	 * because calling create_managers() will create threads, which
	 * would be lost after fork().
	 */
	if (!ns_g_foreground)
		ns_os_daemonize();

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE, "starting BIND %s", ns_g_version);

	result = create_managers();
	if (result != ISC_R_SUCCESS)
		ns_main_earlyfatal("create_managers() failed: %s",
				   isc_result_totext(result));

	ns_server_create(ns_g_mctx, &ns_g_server);

	result = ns_omapi_init();
	if (result != ISC_R_SUCCESS)
		ns_main_earlyfatal("omapi_lib_init() failed: %s",
				   isc_result_totext(result));

	result = ns_omapi_listen(&ns_g_omapimgr);
	if (result == ISC_R_SUCCESS)
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_MAIN, ISC_LOG_DEBUG(3),
			      "OMAPI started");
	else
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_MAIN, ISC_LOG_WARNING,
			      "OMAPI failed to start: %s",
			      isc_result_totext(result));
}

static void
cleanup(void) {
	destroy_managers();
	ns_server_destroy(&ns_g_server);
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE, "exiting");
	ns_log_shutdown();
}

int
main(int argc, char *argv[]) {
	isc_result_t result;

	program_name = argv[0];
	isc_assertion_setcallback(assertion_failed);
	isc_error_setfatal(library_fatal_error);
	isc_error_setunexpected(library_unexpected_error);

	ns_os_init();

	result = isc_app_start();
	if (result != ISC_R_SUCCESS)
		ns_main_earlyfatal("isc_app_start() failed: %s",
				   isc_result_totext(result));

	result = isc_mem_create(0, 0, &ns_g_mctx);
	if (result != ISC_R_SUCCESS)
		ns_main_earlyfatal("isc_mem_create() failed: %s",
				   isc_result_totext(result));

	dns_result_register();
	dst_result_register();

	parse_command_line(argc, argv);

	setup();

	/*
	 * Start things running and then wait for a shutdown request
	 * or reload.
	 */
	do {
		result = isc_app_run();
		
		if (result == ISC_R_RELOAD) {
			ns_server_reloadwanted(ns_g_server);
		} else if (result != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "isc_app_run(): %s",
					 isc_result_totext(result));
			/*
			 * Force exit.
			 */
			result = ISC_R_SUCCESS;
		}
	} while (result != ISC_R_SUCCESS);

	cleanup();

	if (want_stats)
		isc_mem_stats(ns_g_mctx, stdout);
	isc_mem_destroy(&ns_g_mctx);

	isc_app_finish();

	ns_os_shutdown();

	return (0);
}


