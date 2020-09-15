/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <config.h>

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <isc/app.h>
#include <isc/backtrace.h>
#include <isc/commandline.h>
#include <isc/dir.h>
#include <isc/entropy.h>
#include <isc/file.h>
#include <isc/hash.h>
#include <isc/httpd.h>
#include <isc/os.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/resource.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <isccc/result.h>

#include <dns/dispatch.h>
#include <dns/dyndb.h>
#include <dns/name.h>
#include <dns/result.h>
#include <dns/resolver.h>
#include <dns/view.h>

#include <dst/result.h>
#ifdef PKCS11CRYPTO
#include <pk11/result.h>
#endif

#include <dlz/dlz_dlopen_driver.h>

#ifdef HAVE_GPERFTOOLS_PROFILER
#include <gperftools/profiler.h>
#endif

#ifdef HAVE_GEOIP2
#include <maxminddb.h>
#endif

/*
 * Defining NS_MAIN provides storage declarations (rather than extern)
 * for variables in named/globals.h.
 */
#define NS_MAIN 1

#include <named/builtin.h>
#include <named/config.h>
#include <named/control.h>
#include <named/fuzz.h>
#include <named/globals.h>	/* Explicit, though named/log.h includes it. */
#include <named/interfacemgr.h>
#include <named/log.h>
#include <named/os.h>
#include <named/server.h>
#include <named/lwresd.h>
#include <named/main.h>
#include <named/seccomp.h>
#ifdef HAVE_LIBSCF
#include <named/ns_smf_globals.h>
#endif

#ifdef OPENSSL
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#endif
#ifdef HAVE_LIBXML2
#include <libxml/xmlversion.h>
#endif
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif
/*
 * Include header files for database drivers here.
 */
/* #include "xxdb.h" */

#ifdef CONTRIB_DLZ
/*
 * Include contributed DLZ drivers if appropriate.
 */
#include <dlz/dlz_drivers.h>
#endif

/*
 * The maximum number of stack frames to dump on assertion failure.
 */
#ifndef BACKTRACE_MAXFRAME
#define BACKTRACE_MAXFRAME 128
#endif

LIBISC_EXTERNAL_DATA extern int isc_dscp_check_value;
LIBDNS_EXTERNAL_DATA extern unsigned int dns_zone_mkey_hour;
LIBDNS_EXTERNAL_DATA extern unsigned int dns_zone_mkey_day;
LIBDNS_EXTERNAL_DATA extern unsigned int dns_zone_mkey_month;

static bool	want_stats = false;
static char		program_name[NAME_MAX] = "named";
static char		absolute_conffile[PATH_MAX];
static char		saved_command_line[512];
static char		version[512];
static unsigned int	maxsocks = 0;
static int		maxudp = 0;

void
ns_main_earlywarning(const char *format, ...) {
	va_list args;

	va_start(args, format);
	if (ns_g_lctx != NULL) {
		isc_log_vwrite(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			       NS_LOGMODULE_MAIN, ISC_LOG_WARNING,
			       format, args);
	} else {
		fprintf(stderr, "%s: ", program_name);
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
		fflush(stderr);
	}
	va_end(args);
}

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

ISC_PLATFORM_NORETURN_PRE static void
assertion_failed(const char *file, int line, isc_assertiontype_t type,
		 const char *cond) ISC_PLATFORM_NORETURN_POST;

static void
assertion_failed(const char *file, int line, isc_assertiontype_t type,
		 const char *cond)
{
	void *tracebuf[BACKTRACE_MAXFRAME];
	int i, nframes;
	isc_result_t result;
	const char *logsuffix = "";
	const char *fname;

	/*
	 * Handle assertion failures.
	 */

	if (ns_g_lctx != NULL) {
		/*
		 * Reset the assertion callback in case it is the log
		 * routines causing the assertion.
		 */
		isc_assertion_setcallback(NULL);

		result = isc_backtrace_gettrace(tracebuf, BACKTRACE_MAXFRAME,
						&nframes);
		if (result == ISC_R_SUCCESS && nframes > 0)
			logsuffix = ", back trace";
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_MAIN, ISC_LOG_CRITICAL,
			      "%s:%d: %s(%s) failed%s", file, line,
			      isc_assertion_typetotext(type), cond, logsuffix);
		if (result == ISC_R_SUCCESS) {
			for (i = 0; i < nframes; i++) {
				unsigned long offset;

				fname = NULL;
				result = isc_backtrace_getsymbol(tracebuf[i],
								 &fname,
								 &offset);
				if (result == ISC_R_SUCCESS) {
					isc_log_write(ns_g_lctx,
						      NS_LOGCATEGORY_GENERAL,
						      NS_LOGMODULE_MAIN,
						      ISC_LOG_CRITICAL,
						      "#%d %p in %s()+0x%lx", i,
						      tracebuf[i], fname,
						      offset);
				} else {
					isc_log_write(ns_g_lctx,
						      NS_LOGCATEGORY_GENERAL,
						      NS_LOGMODULE_MAIN,
						      ISC_LOG_CRITICAL,
						      "#%d %p in ??", i,
						      tracebuf[i]);
				}
			}
		}
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_MAIN, ISC_LOG_CRITICAL,
			      "exiting (due to assertion failure)");
	} else {
		fprintf(stderr, "%s:%d: %s(%s) failed\n",
			file, line, isc_assertion_typetotext(type), cond);
		fflush(stderr);
	}

	if (ns_g_coreok)
		abort();
	exit(1);
}

ISC_PLATFORM_NORETURN_PRE static void
library_fatal_error(const char *file, int line, const char *format,
		    va_list args)
ISC_FORMAT_PRINTF(3, 0) ISC_PLATFORM_NORETURN_POST;

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
			 va_list args) ISC_FORMAT_PRINTF(3, 0);

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
lwresd_usage(void) {
	fprintf(stderr,
		"usage: lwresd [-4|-6] [-c conffile | -C resolvconffile] "
		"[-d debuglevel] [-f|-g]\n"
		"              [-i pidfile] [-n number_of_cpus] "
		"[-p port] [-P listen-port]\n"
		"              [-s] [-S sockets] [-t chrootdir] [-u username] "
		"[-U listeners]\n"
		"              [-m {usage|trace|record|size|mctx}]\n"
		"usage: lwresd [-v|-V]\n");
}

static void
usage(void) {
	if (ns_g_lwresdonly) {
		lwresd_usage();
		return;
	}
	fprintf(stderr,
		"usage: named [-4|-6] [-c conffile] [-d debuglevel] "
		"[-E engine] [-f|-g]\n"
		"             [-n number_of_cpus] [-p port] [-s] "
		"[-S sockets] [-t chrootdir]\n"
		"             [-u username] [-U listeners] "
		"[-m {usage|trace|record|size|mctx}]\n"
		"usage: named [-v|-V]\n");
}

static void
save_command_line(int argc, char *argv[]) {
	int i;
	char *src;
	char *dst;
	char *eob;
	const char truncated[] = "...";
	bool quoted = false;

	dst = saved_command_line;
	eob = saved_command_line + sizeof(saved_command_line);

	for (i = 1; i < argc && dst < eob; i++) {
		*dst++ = ' ';

		src = argv[i];
		while (*src != '\0' && dst < eob) {
			/*
			 * This won't perfectly produce a shell-independent
			 * pastable command line in all circumstances, but
			 * comes close, and for practical purposes will
			 * nearly always be fine.
			 */
			if (quoted || isalnum(*src & 0xff) ||
			    *src == ',' || *src == '-' || *src == '_' ||
			    *src == '.' || *src == '/') {
				*dst++ = *src++;
				quoted = false;
			} else {
				*dst++ = '\\';
				quoted = true;
			}
		}
	}

	INSIST(sizeof(saved_command_line) >= sizeof(truncated));

	if (dst == eob)
		strcpy(eob - sizeof(truncated), truncated);
	else
		*dst = '\0';
}

static int
parse_int(char *arg, const char *desc) {
	char *endp;
	int tmp;
	long int ltmp;

	ltmp = strtol(arg, &endp, 10);
	tmp = (int) ltmp;
	if (*endp != '\0')
		ns_main_earlyfatal("%s '%s' must be numeric", desc, arg);
	if (tmp < 0 || tmp != ltmp)
		ns_main_earlyfatal("%s '%s' out of range", desc, arg);
	return (tmp);
}

static struct flag_def {
	const char *name;
	unsigned int value;
} mem_debug_flags[] = {
	{ "none", 0},
	{ "trace",  ISC_MEM_DEBUGTRACE },
	{ "record", ISC_MEM_DEBUGRECORD },
	{ "usage", ISC_MEM_DEBUGUSAGE },
	{ "size", ISC_MEM_DEBUGSIZE },
	{ "mctx", ISC_MEM_DEBUGCTX },
	{ NULL, 0 }
};

static void
set_flags(const char *arg, struct flag_def *defs, unsigned int *ret) {
	bool clear = false;

	for (;;) {
		const struct flag_def *def;
		const char *end = strchr(arg, ',');
		int arglen;
		if (end == NULL)
			end = arg + strlen(arg);
		arglen = (int)(end - arg);
		for (def = defs; def->name != NULL; def++) {
			if (arglen == (int)strlen(def->name) &&
			    memcmp(arg, def->name, arglen) == 0) {
				if (def->value == 0)
					clear = true;
				*ret |= def->value;
				goto found;
			}
		}
		ns_main_earlyfatal("unrecognized flag '%.*s'", arglen, arg);
	 found:
		if (clear || (*end == '\0'))
			break;
		arg = end + 1;
	}

	if (clear)
		*ret = 0;
}

static void
printversion(bool verbose) {
	char rndcconf[PATH_MAX], *dot = NULL;
	isc_mem_t *mctx = NULL;
	cfg_parser_t *parser = NULL;
	cfg_obj_t *config = NULL;
	const cfg_obj_t *defaults = NULL, *obj = NULL;

	printf("%s %s%s%s <id:%s>\n",
	       ns_g_product, ns_g_version,
	       (*ns_g_description != '\0') ? " " : "",
	       ns_g_description, ns_g_srcid);

	if (!verbose) {
		return;
	}
	printf("running on %s\n", ns_os_uname());
	printf("built by %s with %s\n", ns_g_builder, ns_g_configargs);
#ifdef __clang__
	printf("compiled by CLANG %s\n", __VERSION__);
#else
#if defined(__ICC) || defined(__INTEL_COMPILER)
	printf("compiled by ICC %s\n", __VERSION__);
#else
#ifdef __GNUC__
	printf("compiled by GCC %s\n", __VERSION__);
#endif
#endif
#endif
#ifdef _MSC_VER
	printf("compiled by MSVC %d\n", _MSC_VER);
#endif
#ifdef __SUNPRO_C
	printf("compiled by Solaris Studio %x\n", __SUNPRO_C);
#endif
#ifdef OPENSSL
	printf("compiled with OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
#if !defined(LIBRESSL_VERSION_NUMBER) && \
    OPENSSL_VERSION_NUMBER >= 0x10100000L /* 1.1.0 or higher */
	printf("linked to OpenSSL version: %s\n",
	       OpenSSL_version(OPENSSL_VERSION));
#else
	printf("linked to OpenSSL version: %s\n",
	       SSLeay_version(SSLEAY_VERSION));
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
#endif
#ifdef HAVE_LIBXML2
	printf("compiled with libxml2 version: %s\n", LIBXML_DOTTED_VERSION);
	printf("linked to libxml2 version: %s\n", xmlParserVersion);
#endif
#if defined(HAVE_JSON) && defined(JSON_C_VERSION)
	printf("compiled with libjson-c version: %s\n", JSON_C_VERSION);
	printf("linked to libjson-c version: %s\n", json_c_version());
#endif
#if defined(HAVE_ZLIB) && defined(ZLIB_VERSION)
	printf("compiled with zlib version: %s\n", ZLIB_VERSION);
	printf("linked to zlib version: %s\n", zlibVersion());
#endif
#if defined(HAVE_GEOIP2)
	/* Unfortunately, no version define on link time */
	printf("linked to maxminddb version: %s\n",
	       MMDB_lib_version());
#endif
#if defined(HAVE_DNSTAP)
	printf("compiled with protobuf-c version: %s\n",
	       PROTOBUF_C_VERSION);
	printf("linked to protobuf-c version: %s\n",
	       protobuf_c_version());
#endif
#ifdef ISC_PLATFORM_USETHREADS
	printf("threads support is enabled\n");
#else
	printf("threads support is disabled\n");
#endif

	/*
	 * The default rndc.conf and rndc.key paths are in the same
	 * directory, but named only has rndc.key defined internally.
	 * We construct the rndc.conf path from it. (We could use
	 * NAMED_SYSCONFDIR here but the result would look wrong on
	 * Windows.)
	 */
	strlcpy(rndcconf, ns_g_keyfile, sizeof(rndcconf));
	dot = strrchr(rndcconf, '.');
	if (dot != NULL) {
		size_t len = dot - rndcconf + 1;
		snprintf(dot + 1, PATH_MAX - len, "conf");
	}

#define RTC(x) RUNTIME_CHECK((x) == ISC_R_SUCCESS)
	RTC(isc_mem_create(0, 0, &mctx));
	RTC(cfg_parser_create(mctx, ns_g_lctx, &parser));
	RTC(ns_config_parsedefaults(parser, &config));
	RTC(cfg_map_get(config, "options", &defaults));

	/*
	 * Print default configuration paths.
	 */
	printf("\n");
	printf("default paths:\n");
	printf("  named configuration:  %s\n", ns_g_conffile);
	printf("  rndc configuration:   %s\n", rndcconf);
	RTC(cfg_map_get(defaults, "bindkeys-file", &obj));
	printf("  DNSSEC root key:      %s\n", cfg_obj_asstring(obj));
	printf("  nsupdate session key: %s\n", ns_g_defaultsessionkeyfile);
	printf("  named PID file:       %s\n", ns_g_defaultpidfile);
	printf("  named lock file:      %s\n", ns_g_defaultlockfile);
#if defined(HAVE_GEOIP2)
	obj = NULL;
	RTC(cfg_map_get(defaults, "geoip-directory", &obj));
	if (cfg_obj_isstring(obj)) {
		printf("  geoip-directory:      %s\n", cfg_obj_asstring(obj));
	}
#endif /* HAVE_GEOIP2 */
	cfg_obj_destroy(parser, &config);
	cfg_parser_destroy(&parser);
	isc_mem_detach(&mctx);
}

static void
parse_fuzz_arg(void) {
	if (!strncmp(isc_commandline_argument, "client:", 7)) {
		ns_g_fuzz_named_addr = isc_commandline_argument + 7;
		ns_g_fuzz_type = ns_fuzz_client;
	} else if (!strncmp(isc_commandline_argument, "tcp:", 4)) {
		ns_g_fuzz_named_addr = isc_commandline_argument + 4;
		ns_g_fuzz_type = ns_fuzz_tcpclient;
	} else if (!strncmp(isc_commandline_argument, "resolver:", 9)) {
		ns_g_fuzz_named_addr = isc_commandline_argument + 9;
		ns_g_fuzz_type = ns_fuzz_resolver;
	} else if (!strncmp(isc_commandline_argument, "http:", 5)) {
		ns_g_fuzz_named_addr = isc_commandline_argument + 5;
		ns_g_fuzz_type = ns_fuzz_http;
	} else if (!strncmp(isc_commandline_argument, "rndc:", 5)) {
		ns_g_fuzz_named_addr = isc_commandline_argument + 5;
		ns_g_fuzz_type = ns_fuzz_rndc;
	} else {
		ns_main_earlyfatal("unknown fuzzing type '%s'",
				   isc_commandline_argument);
	}
}

static void
parse_T_opt(char *option) {
	const char *p;
	/*
	 * force the server to behave (or misbehave) in
	 * specified ways for testing purposes.
	 *
	 * clienttest: make clients single shot with their
	 * 	       own memory context.
	 * delay=xxxx: delay client responses by xxxx ms to
	 *	       simulate remote servers.
	 * dscp=x:     check that dscp values are as
	 * 	       expected and assert otherwise.
	 */
	if (!strcmp(option, "clienttest")) {
		ns_g_clienttest = true;
	} else if (!strncmp(option, "delay=", 6)) {
		ns_g_delay = atoi(option + 6);
	} else if (!strcmp(option, "dropedns")) {
		ns_g_dropedns = true;
	} else if (!strncmp(option, "dscp=", 5)) {
		isc_dscp_check_value = atoi(option + 5);
	} else if (!strcmp(option, "ednsformerr")) {
		ns_g_ednsformerr = true;
	} else if (!strcmp(option, "ednsnotimp")) {
		ns_g_ednsnotimp = true;
	} else if (!strcmp(option, "ednsrefused")) {
		ns_g_ednsrefused = true;
	} else if (!strcmp(option, "fixedlocal")) {
		ns_g_fixedlocal = true;
	} else if (!strcmp(option, "keepstderr")) {
		ns_g_keepstderr = true;
	} else if (!strcmp(option, "noaa")) {
		ns_g_noaa = true;
	} else if (!strcmp(option, "noedns")) {
		ns_g_noedns = true;
	} else if (!strcmp(option, "nonearest")) {
		ns_g_nonearest = true;
	} else if (!strcmp(option, "nosoa")) {
		ns_g_nosoa = true;
	} else if (!strcmp(option, "nosyslog")) {
		ns_g_nosyslog = true;
	} else if (!strcmp(option, "notcp")) {
		ns_g_notcp = true;
	} else if (!strcmp(option, "maxudp512")) {
		maxudp = 512;
	} else if (!strcmp(option, "maxudp1460")) {
		maxudp = 1460;
	} else if (!strncmp(option, "maxudp=", 7)) {
		maxudp = atoi(option + 7);
		if (maxudp <= 0) {
			ns_main_earlyfatal("bad maxudp");
		}
	} else if (!strncmp(option, "mkeytimers=", 11)) {
		p = strtok(option + 11, "/");
		if (p == NULL) {
			ns_main_earlyfatal("bad mkeytimer");
		}

		dns_zone_mkey_hour = atoi(p);
		if (dns_zone_mkey_hour == 0) {
			ns_main_earlyfatal("bad mkeytimer");
		}

		p = strtok(NULL, "/");
		if (p == NULL) {
			dns_zone_mkey_day = (24 * dns_zone_mkey_hour);
			dns_zone_mkey_month = (30 * dns_zone_mkey_day);
			return;
		}

		dns_zone_mkey_day = atoi(p);
		if (dns_zone_mkey_day < dns_zone_mkey_hour)
			ns_main_earlyfatal("bad mkeytimer");

		p = strtok(NULL, "/");
		if (p == NULL) {
			dns_zone_mkey_month = (30 * dns_zone_mkey_day);
			return;
		}

		dns_zone_mkey_month = atoi(p);
		if (dns_zone_mkey_month < dns_zone_mkey_day) {
			ns_main_earlyfatal("bad mkeytimer");
		}
	} else if (!strcmp(option, "sigvalinsecs")) {
		ns_g_sigvalinsecs = true;
	} else if (!strncmp(option, "tat=", 4)) {
		ns_g_tat_interval = atoi(option + 4);
	} else {
		fprintf(stderr, "unknown -T flag '%s'\n", option);
	}
}

static void
parse_command_line(int argc, char *argv[]) {
	int ch;
	int port;
	const char *p;

	save_command_line(argc, argv);

	/*
	 * NS_MAIN_ARGS is defined in main.h, so that it can be used
	 * both by named and by ntservice hooks.
	 */
	isc_commandline_errprint = false;
	while ((ch = isc_commandline_parse(argc, argv, NS_MAIN_ARGS)) != -1) {
		switch (ch) {
		case '4':
			if (ns_g_disable4)
				ns_main_earlyfatal("cannot specify -4 and -6");
			if (isc_net_probeipv4() != ISC_R_SUCCESS)
				ns_main_earlyfatal("IPv4 not supported by OS");
			isc_net_disableipv6();
			ns_g_disable6 = true;
			break;
		case '6':
			if (ns_g_disable6)
				ns_main_earlyfatal("cannot specify -4 and -6");
			if (isc_net_probeipv6() != ISC_R_SUCCESS)
				ns_main_earlyfatal("IPv6 not supported by OS");
			isc_net_disableipv4();
			ns_g_disable4 = true;
			break;
		case 'A':
			parse_fuzz_arg();
			break;
		case 'c':
			ns_g_conffile = isc_commandline_argument;
			lwresd_g_conffile = isc_commandline_argument;
			if (lwresd_g_useresolvconf)
				ns_main_earlyfatal("cannot specify -c and -C");
			ns_g_conffileset = true;
			break;
		case 'C':
			lwresd_g_resolvconffile = isc_commandline_argument;
			if (ns_g_conffileset)
				ns_main_earlyfatal("cannot specify -c and -C");
			lwresd_g_useresolvconf = true;
			break;
		case 'd':
			ns_g_debuglevel = parse_int(isc_commandline_argument,
						    "debug level");
			break;
		case 'D':
			/* Descriptive comment for 'ps'. */
			break;
		case 'E':
			ns_g_engine = isc_commandline_argument;
			break;
		case 'f':
			ns_g_foreground = true;
			break;
		case 'g':
			ns_g_foreground = true;
			ns_g_logstderr = true;
			break;
		/* XXXBEW -i should be removed */
		case 'i':
			lwresd_g_defaultpidfile = isc_commandline_argument;
			break;
		case 'l':
			ns_g_lwresdonly = true;
			break;
		case 'L':
			ns_g_logfile = isc_commandline_argument;
			break;
		case 'M':
			if (strcmp(isc_commandline_argument, "external") == 0)
				isc_mem_defaultflags = 0;
			break;
		case 'm':
			set_flags(isc_commandline_argument, mem_debug_flags,
				  &isc_mem_debugging);
			break;
		case 'N': /* Deprecated. */
		case 'n':
			ns_g_cpus = parse_int(isc_commandline_argument,
					      "number of cpus");
			if (ns_g_cpus == 0)
				ns_g_cpus = 1;
			break;
		case 'p':
			port = parse_int(isc_commandline_argument, "port");
			if (port < 1 || port > 65535)
				ns_main_earlyfatal("port '%s' out of range",
						   isc_commandline_argument);
			ns_g_port = port;
			break;
		/* XXXBEW Should -P be removed? */
		case 'P':
			port = parse_int(isc_commandline_argument, "port");
			if (port < 1 || port > 65535)
				ns_main_earlyfatal("port '%s' out of range",
						   isc_commandline_argument);
			lwresd_g_listenport = port;
			break;
		case 's':
			/* XXXRTH temporary syntax */
			want_stats = true;
			break;
		case 'S':
			maxsocks = parse_int(isc_commandline_argument,
					     "max number of sockets");
			break;
		case 't':
			/* XXXJAB should we make a copy? */
			ns_g_chrootdir = isc_commandline_argument;
			break;
		case 'T':	/* NOT DOCUMENTED */
			parse_T_opt(isc_commandline_argument);
			break;
		case 'U':
			ns_g_udpdisp = parse_int(isc_commandline_argument,
						 "number of UDP listeners "
						 "per interface");
			break;
		case 'u':
			ns_g_username = isc_commandline_argument;
			break;
		case 'v':
			printversion(false);
			exit(0);
		case 'V':
			printversion(true);
			exit(0);
		case 'x':
			/* Obsolete. No longer in use. Ignore. */
			break;
		case 'X':
			ns_g_forcelock = true;
			if (strcasecmp(isc_commandline_argument, "none") != 0)
				ns_g_defaultlockfile = isc_commandline_argument;
			else
				ns_g_defaultlockfile = NULL;
			break;
		case 'F':
			/* Reserved for FIPS mode */
			/* FALLTHROUGH */
		case '?':
			usage();
			if (isc_commandline_option == '?')
				exit(0);
			p = strchr(NS_MAIN_ARGS, isc_commandline_option);
			if (p == NULL || *++p != ':')
				ns_main_earlyfatal("unknown option '-%c'",
						   isc_commandline_option);
			else
				ns_main_earlyfatal("option '-%c' requires "
						   "an argument",
						   isc_commandline_option);
			/* FALLTHROUGH */
		default:
			ns_main_earlyfatal("parsing options returned %d", ch);
		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;
	POST(argv);

	if (argc > 0) {
		usage();
		ns_main_earlyfatal("extra command line arguments");
	}
}

static isc_result_t
create_managers(void) {
	isc_result_t result;
	unsigned int socks;

	INSIST(ns_g_cpus_detected > 0);

#ifdef ISC_PLATFORM_USETHREADS
	if (ns_g_cpus == 0)
		ns_g_cpus = ns_g_cpus_detected;
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_INFO, "found %u CPU%s, using %u worker thread%s",
		      ns_g_cpus_detected, ns_g_cpus_detected == 1 ? "" : "s",
		      ns_g_cpus, ns_g_cpus == 1 ? "" : "s");
#else
	ns_g_cpus = 1;
#endif
#ifdef WIN32
	ns_g_udpdisp = 1;
#else
	if (ns_g_udpdisp == 0) {
		if (ns_g_cpus_detected == 1)
			ns_g_udpdisp = 1;
		else
			ns_g_udpdisp = ns_g_cpus_detected - 1;
	}
	if (ns_g_udpdisp > ns_g_cpus)
		ns_g_udpdisp = ns_g_cpus;
#endif
#ifdef ISC_PLATFORM_USETHREADS
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_INFO, "using %u UDP listener%s per interface",
		      ns_g_udpdisp, ns_g_udpdisp == 1 ? "" : "s");
#endif

	result = isc_taskmgr_create(ns_g_mctx, ns_g_cpus, 0, &ns_g_taskmgr);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_taskmgr_create() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	result = isc_timermgr_create(ns_g_mctx, &ns_g_timermgr);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_timermgr_create() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	result = isc_socketmgr_create2(ns_g_mctx, &ns_g_socketmgr, maxsocks);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_socketmgr_create() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}
	isc__socketmgr_maxudp(ns_g_socketmgr, maxudp);
	result = isc_socketmgr_getmaxsockets(ns_g_socketmgr, &socks);
	if (result == ISC_R_SUCCESS) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER,
			      ISC_LOG_INFO, "using up to %u sockets", socks);
	}

	result = isc_entropy_create(ns_g_mctx, &ns_g_entropy);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_entropy_create() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	result = isc_hash_create(ns_g_mctx, ns_g_entropy, DNS_NAME_MAXWIRE);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_hash_create() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	return (ISC_R_SUCCESS);
}

static void
destroy_managers(void) {
	ns_lwresd_shutdown();

	/*
	 * isc_taskmgr_destroy() will block until all tasks have exited,
	 */
	isc_taskmgr_destroy(&ns_g_taskmgr);
	isc_timermgr_destroy(&ns_g_timermgr);
	isc_socketmgr_destroy(&ns_g_socketmgr);

	/*
	 * isc_hash_destroy() cannot be called as long as a resolver may be
	 * running.  Calling this after isc_taskmgr_destroy() ensures the
	 * call is safe.
	 */
	isc_hash_destroy();
}

static void
dump_symboltable(void) {
	int i;
	isc_result_t result;
	const char *fname;
	const void *addr;

	if (isc__backtrace_nsymbols == 0)
		return;

	if (!isc_log_wouldlog(ns_g_lctx, ISC_LOG_DEBUG(99)))
		return;

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_DEBUG(99), "Symbol table:");

	for (i = 0, result = ISC_R_SUCCESS; result == ISC_R_SUCCESS; i++) {
		addr = NULL;
		fname = NULL;
		result = isc_backtrace_getsymbolfromindex(i, &addr, &fname);
		if (result == ISC_R_SUCCESS) {
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_MAIN, ISC_LOG_DEBUG(99),
				      "[%d] %p %s", i, addr, fname);
		}
	}
}

#ifdef HAVE_LIBSECCOMP
static void
setup_seccomp() {
	scmp_filter_ctx ctx;
	unsigned int i;
	int ret;

	/* Make sure the lists are in sync */
	INSIST((sizeof(scmp_syscalls) / sizeof(int)) ==
	       (sizeof(scmp_syscall_names) / sizeof(const char *)));

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_MAIN, ISC_LOG_WARNING,
			      "libseccomp activation failed");
		return;
	}

	for (i = 0 ; i < sizeof(scmp_syscalls)/sizeof(*(scmp_syscalls)); i++) {
		ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				       scmp_syscalls[i], 0);
		if (ret < 0)
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_MAIN, ISC_LOG_WARNING,
				      "libseccomp rule failed: %s",
				      scmp_syscall_names[i]);

		else
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_MAIN, ISC_LOG_DEBUG(9),
				      "added libseccomp rule: %s",
				      scmp_syscall_names[i]);
	}

	ret = seccomp_load(ctx);
	if (ret < 0) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_MAIN, ISC_LOG_WARNING,
			      "libseccomp unable to load filter");
	} else {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
			      "libseccomp sandboxing active");
	}

	/*
	 * Release filter in ctx. Filters already loaded are not
	 * affected.
	 */
	seccomp_release(ctx);
}
#endif /* HAVE_LIBSECCOMP */

static void
setup(void) {
	isc_result_t result;
	isc_resourcevalue_t old_openfiles;
#ifdef HAVE_LIBSCF
	char *instance = NULL;
#endif

	/*
	 * Get the user and group information before changing the root
	 * directory, so the administrator does not need to keep a copy
	 * of the user and group databases in the chroot'ed environment.
	 */
	ns_os_inituserinfo(ns_g_username);

	/*
	 * Initialize time conversion information
	 */
	ns_os_tzset();

	ns_os_opendevnull();

#ifdef HAVE_LIBSCF
	/* Check if named is under smf control, before chroot. */
	result = ns_smf_get_instance(&instance, 0, ns_g_mctx);
	/* We don't care about instance, just check if we got one. */
	if (result == ISC_R_SUCCESS)
		ns_smf_got_instance = 1;
	else
		ns_smf_got_instance = 0;
	if (instance != NULL)
		isc_mem_free(ns_g_mctx, instance);
#endif /* HAVE_LIBSCF */

#ifdef PATH_RANDOMDEV
	/*
	 * Initialize system's random device as fallback entropy source
	 * if running chroot'ed.
	 */
	if (ns_g_chrootdir != NULL) {
		result = isc_entropy_create(ns_g_mctx, &ns_g_fallbackentropy);
		if (result != ISC_R_SUCCESS)
			ns_main_earlyfatal("isc_entropy_create() failed: %s",
					   isc_result_totext(result));

		result = isc_entropy_createfilesource(ns_g_fallbackentropy,
						      PATH_RANDOMDEV);
		if (result != ISC_R_SUCCESS) {
			ns_main_earlywarning("could not open pre-chroot "
					     "entropy source %s: %s",
					     PATH_RANDOMDEV,
					     isc_result_totext(result));
			isc_entropy_detach(&ns_g_fallbackentropy);
		}
	}
#endif

#ifdef ISC_PLATFORM_USETHREADS
	/*
	 * Check for the number of cpu's before ns_os_chroot().
	 */
	ns_g_cpus_detected = isc_os_ncpus();
#endif

	ns_os_chroot(ns_g_chrootdir);

	/*
	 * For operating systems which have a capability mechanism, now
	 * is the time to switch to minimal privs and change our user id.
	 * On traditional UNIX systems, this call will be a no-op, and we
	 * will change the user ID after reading the config file the first
	 * time.  (We need to read the config file to know which possibly
	 * privileged ports to bind() to.)
	 */
	ns_os_minprivs();

	result = ns_log_init((ns_g_username != NULL));
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

	/*
	 * We call isc_app_start() here as some versions of FreeBSD's fork()
	 * destroys all the signal handling it sets up.
	 */
	result = isc_app_start();
	if (result != ISC_R_SUCCESS)
		ns_main_earlyfatal("isc_app_start() failed: %s",
				   isc_result_totext(result));

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE, "starting %s %s%s%s <id:%s>",
		      ns_g_product, ns_g_version,
		      *ns_g_description ? " " : "", ns_g_description,
		      ns_g_srcid);

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE, "running on %s", ns_os_uname());

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE, "built with %s", ns_g_configargs);

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE, "running as: %s%s",
		      program_name, saved_command_line);
#ifdef __clang__
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "compiled by CLANG %s", __VERSION__);
#else
#if defined(__ICC) || defined(__INTEL_COMPILER)
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "compiled by ICC %s", __VERSION__);
#else
#ifdef __GNUC__
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "compiled by GCC %s", __VERSION__);
#endif
#endif
#endif
#ifdef _MSC_VER
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "compiled by MSVC %d", _MSC_VER);
#endif
#ifdef __SUNPRO_C
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "compiled by Solaris Studio %x", __SUNPRO_C);
#endif
#ifdef OPENSSL
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "compiled with OpenSSL version: %s",
		      OPENSSL_VERSION_TEXT);
#if !defined(LIBRESSL_VERSION_NUMBER) && \
    OPENSSL_VERSION_NUMBER >= 0x10100000L /* 1.1.0 or higher */
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "linked to OpenSSL version: %s",
		      OpenSSL_version(OPENSSL_VERSION));
#else
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "linked to OpenSSL version: %s",
		      SSLeay_version(SSLEAY_VERSION));
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
#endif
#ifdef HAVE_LIBXML2
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "compiled with libxml2 version: %s",
		      LIBXML_DOTTED_VERSION);
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "linked to libxml2 version: %s", xmlParserVersion);
#endif
#if defined(HAVE_JSON) && defined(JSON_C_VERSION)
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "compiled with libjson-c version: %s", JSON_C_VERSION);
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "linked to libjson-c version: %s", json_c_version());
#endif
#if defined(HAVE_ZLIB) && defined(ZLIB_VERSION)
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "compiled with zlib version: %s", ZLIB_VERSION);
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "linked to zlib version: %s", zlibVersion());
#endif
#ifdef ISC_PLATFORM_USETHREADS
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "threads support is enabled");
#else
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "threads support is disabled");
#endif

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE,
		      "----------------------------------------------------");
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE,
		      "BIND 9 is maintained by Internet Systems Consortium,");
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE,
		      "Inc. (ISC), a non-profit 501(c)(3) public-benefit ");
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE,
		      "corporation.  Support and training for BIND 9 are ");
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE,
		      "available at https://www.isc.org/support");
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE,
		      "----------------------------------------------------");

	dump_symboltable();

	/*
	 * Get the initial resource limits.
	 */
	(void)isc_resource_getlimit(isc_resource_stacksize,
				    &ns_g_initstacksize);
	(void)isc_resource_getlimit(isc_resource_datasize,
				    &ns_g_initdatasize);
	(void)isc_resource_getlimit(isc_resource_coresize,
				    &ns_g_initcoresize);
	(void)isc_resource_getlimit(isc_resource_openfiles,
				    &ns_g_initopenfiles);

	/*
	 * System resources cannot effectively be tuned on some systems.
	 * Raise the limit in such cases for safety.
	 */
	old_openfiles = ns_g_initopenfiles;
	ns_os_adjustnofile();
	(void)isc_resource_getlimit(isc_resource_openfiles,
				    &ns_g_initopenfiles);
	if (old_openfiles != ns_g_initopenfiles) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_MAIN, ISC_LOG_NOTICE,
			      "adjusted limit on open files from "
			      "%" PRIu64 " to "
			      "%" PRIu64,
			      old_openfiles, ns_g_initopenfiles);
	}

	/*
	 * If the named configuration filename is relative, prepend the current
	 * directory's name before possibly changing to another directory.
	 */
	if (! isc_file_isabsolute(ns_g_conffile)) {
		result = isc_file_absolutepath(ns_g_conffile,
					       absolute_conffile,
					       sizeof(absolute_conffile));
		if (result != ISC_R_SUCCESS)
			ns_main_earlyfatal("could not construct absolute path "
					   "of configuration file: %s",
					   isc_result_totext(result));
		ns_g_conffile = absolute_conffile;
	}

	/*
	 * Record the server's startup time.
	 */
	result = isc_time_now(&ns_g_boottime);
	if (result != ISC_R_SUCCESS)
		ns_main_earlyfatal("isc_time_now() failed: %s",
				   isc_result_totext(result));

	result = create_managers();
	if (result != ISC_R_SUCCESS)
		ns_main_earlyfatal("create_managers() failed: %s",
				   isc_result_totext(result));

	ns_builtin_init();

	/*
	 * Add calls to register sdb drivers here.
	 */
	/* xxdb_init(); */

#ifdef ISC_DLZ_DLOPEN
	/*
	 * Register the DLZ "dlopen" driver.
	 */
	result = dlz_dlopen_init(ns_g_mctx);
	if (result != ISC_R_SUCCESS)
		ns_main_earlyfatal("dlz_dlopen_init() failed: %s",
				   isc_result_totext(result));
#endif

#if CONTRIB_DLZ
	/*
	 * Register any other contributed DLZ drivers.
	 */
	result = dlz_drivers_init();
	if (result != ISC_R_SUCCESS)
		ns_main_earlyfatal("dlz_drivers_init() failed: %s",
				   isc_result_totext(result));
#endif

	ns_server_create(ns_g_mctx, &ns_g_server);

#ifdef HAVE_LIBSECCOMP
	setup_seccomp();
#endif /* HAVE_LIBSECCOMP */
}

static void
cleanup(void) {
	destroy_managers();

	if (ns_g_mapped != NULL)
		dns_acl_detach(&ns_g_mapped);

	ns_server_destroy(&ns_g_server);

	isc_entropy_detach(&ns_g_entropy);
	if (ns_g_fallbackentropy != NULL)
		isc_entropy_detach(&ns_g_fallbackentropy);

	ns_builtin_deinit();

	/*
	 * Add calls to unregister sdb drivers here.
	 */
	/* xxdb_clear(); */

#ifdef CONTRIB_DLZ
	/*
	 * Unregister contributed DLZ drivers.
	 */
	dlz_drivers_clear();
#endif
#ifdef ISC_DLZ_DLOPEN
	/*
	 * Unregister "dlopen" DLZ driver.
	 */
	dlz_dlopen_clear();
#endif

	dns_name_destroy();

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_MAIN,
		      ISC_LOG_NOTICE, "exiting");
	ns_log_shutdown();
}

static char *memstats = NULL;

void
ns_main_setmemstats(const char *filename) {
	/*
	 * Caller has to ensure locking.
	 */

	if (memstats != NULL) {
		free(memstats);
		memstats = NULL;
	}

	if (filename == NULL)
		return;

	memstats = strdup(filename);
}

#ifdef HAVE_LIBSCF
/*
 * Get FMRI for the named process.
 */
isc_result_t
ns_smf_get_instance(char **ins_name, int debug, isc_mem_t *mctx) {
	scf_handle_t *h = NULL;
	int namelen;
	char *instance;

	REQUIRE(ins_name != NULL && *ins_name == NULL);

	if ((h = scf_handle_create(SCF_VERSION)) == NULL) {
		if (debug)
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "scf_handle_create() failed: %s",
					 scf_strerror(scf_error()));
		return (ISC_R_FAILURE);
	}

	if (scf_handle_bind(h) == -1) {
		if (debug)
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "scf_handle_bind() failed: %s",
					 scf_strerror(scf_error()));
		scf_handle_destroy(h);
		return (ISC_R_FAILURE);
	}

	if ((namelen = scf_myname(h, NULL, 0)) == -1) {
		if (debug)
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "scf_myname() failed: %s",
					 scf_strerror(scf_error()));
		scf_handle_destroy(h);
		return (ISC_R_FAILURE);
	}

	if ((instance = isc_mem_allocate(mctx, namelen + 1)) == NULL) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "ns_smf_get_instance memory "
				 "allocation failed: %s",
				 isc_result_totext(ISC_R_NOMEMORY));
		scf_handle_destroy(h);
		return (ISC_R_FAILURE);
	}

	if (scf_myname(h, instance, namelen + 1) == -1) {
		if (debug)
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "scf_myname() failed: %s",
					 scf_strerror(scf_error()));
		scf_handle_destroy(h);
		isc_mem_free(mctx, instance);
		return (ISC_R_FAILURE);
	}

	scf_handle_destroy(h);
	*ins_name = instance;
	return (ISC_R_SUCCESS);
}
#endif /* HAVE_LIBSCF */

/* main entry point, possibly hooked */

int
main(int argc, char *argv[]) {
	isc_result_t result;
#ifdef HAVE_LIBSCF
	char *instance = NULL;
#endif

#ifdef HAVE_GPERFTOOLS_PROFILER
	(void) ProfilerStart(NULL);
#endif

#ifdef WIN32
	/*
	 * Prevent unbuffered I/O from crippling named performance on Windows
	 * when it is logging to stderr (e.g. in system tests).  Use full
	 * buffering (_IOFBF) as line buffering (_IOLBF) is unavailable on
	 * Windows and fflush() is called anyway after each log message gets
	 * written to the default stderr logging channels created by libisc.
	*/
	setvbuf(stderr, NULL, _IOFBF, BUFSIZ);
#endif

#ifdef HAVE_LIBXML2
	xmlInitThreads();
#endif /* HAVE_LIBXML2 */

	/*
	 * Record version in core image.
	 * strings named.core | grep "named version:"
	 */
	strlcat(version,
#if defined(NO_VERSION_DATE) || !defined(__DATE__)
		"named version: BIND " VERSION " <" SRCID ">",
#else
		"named version: BIND " VERSION " <" SRCID "> (" __DATE__ ")",
#endif
		sizeof(version));
	result = isc_file_progname(*argv, program_name, sizeof(program_name));
	if (result != ISC_R_SUCCESS)
		ns_main_earlyfatal("program name too long");

	if (strcmp(program_name, "lwresd") == 0)
		ns_g_lwresdonly = true;

	isc_assertion_setcallback(assertion_failed);
	isc_error_setfatal(library_fatal_error);
	isc_error_setunexpected(library_unexpected_error);

	ns_os_init(program_name);

	dns_result_register();
	dst_result_register();
	isccc_result_register();
#ifdef PKCS11CRYPTO
	pk11_result_register();
#endif

	parse_command_line(argc, argv);

#ifdef ENABLE_AFL
	if (ns_g_fuzz_type != ns_fuzz_none) {
		named_fuzz_setup();
	}

	if (ns_g_fuzz_type == ns_fuzz_resolver) {
		dns_resolver_setfuzzing();
	} else if (ns_g_fuzz_type == ns_fuzz_http) {
		isc_httpd_setfinishhook(named_fuzz_notify);
	}
#endif
	/*
	 * Warn about common configuration error.
	 */
	if (ns_g_chrootdir != NULL) {
		int len = strlen(ns_g_chrootdir);
		if (strncmp(ns_g_chrootdir, ns_g_conffile, len) == 0 &&
		    (ns_g_conffile[len] == '/' || ns_g_conffile[len] == '\\'))
			ns_main_earlywarning("config filename (-c %s) contains "
					     "chroot path (-t %s)",
					     ns_g_conffile, ns_g_chrootdir);
	}

	result = isc_mem_create(0, 0, &ns_g_mctx);
	if (result != ISC_R_SUCCESS)
		ns_main_earlyfatal("isc_mem_create() failed: %s",
				   isc_result_totext(result));
	isc_mem_setname(ns_g_mctx, "main", NULL);

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

#ifdef HAVE_LIBSCF
	if (ns_smf_want_disable == 1) {
		result = ns_smf_get_instance(&instance, 1, ns_g_mctx);
		if (result == ISC_R_SUCCESS && instance != NULL) {
			if (smf_disable_instance(instance, 0) != 0)
				UNEXPECTED_ERROR(__FILE__, __LINE__,
						 "smf_disable_instance() "
						 "failed for %s : %s",
						 instance,
						 scf_strerror(scf_error()));
		}
		if (instance != NULL)
			isc_mem_free(ns_g_mctx, instance);
	}
#endif /* HAVE_LIBSCF */

	cleanup();

	if (want_stats) {
		isc_mem_stats(ns_g_mctx, stdout);
		isc_mutex_stats(stdout);
	}

	if (ns_g_memstatistics && memstats != NULL) {
		FILE *fp = NULL;
		result = isc_stdio_open(memstats, "w", &fp);
		if (result == ISC_R_SUCCESS) {
			isc_mem_stats(ns_g_mctx, fp);
			isc_mutex_stats(fp);
			(void) isc_stdio_close(fp);
		}
	}
	isc_mem_destroy(&ns_g_mctx);
	isc_mem_checkdestroyed(stderr);

	ns_main_setmemstats(NULL);

	isc_app_finish();

	ns_os_closedevnull();

	ns_os_shutdown();

#ifdef HAVE_LIBXML2
	xmlCleanupThreads();
#endif /* HAVE_LIBXML2 */

#ifdef HAVE_GPERFTOOLS_PROFILER
	ProfilerStop();
#endif

	return (0);
}
