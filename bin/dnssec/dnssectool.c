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

#include <config.h>

#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/entropy.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/log.h>
#include <dns/name.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/secalg.h>

#include "dnssectool.h"

extern int verbose;
extern const char *program;

static isc_entropysource_t *filesource = NULL;

void
fatal(const char *format, ...) {
	va_list args;

	fprintf(stderr, "%s: ", program);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(1);
}

void
check_result(isc_result_t result, const char *message) {
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "%s: %s: %s\n", program, message,
			isc_result_totext(result));
		exit(1);
	}
}

void
vbprintf(int level, const char *fmt, ...) {
	va_list ap;
	if (level > verbose)
		return;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", program);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

char *
nametostr(dns_name_t *name) {
	isc_buffer_t b;
	isc_region_t r;
	isc_result_t result;
	static char data[1025];

	isc_buffer_init(&b, data, sizeof(data));
	result = dns_name_totext(name, ISC_FALSE, &b);
	check_result(result, "dns_name_totext()");
	isc_buffer_usedregion(&b, &r);
	r.base[r.length] = 0;
	return (char *) r.base;
}

char *
typetostr(const dns_rdatatype_t type) {
	isc_buffer_t b;
	isc_region_t r;
	isc_result_t result;
	static char data[20];

	isc_buffer_init(&b, data, sizeof(data));
	result = dns_rdatatype_totext(type, &b);
	check_result(result, "dns_rdatatype_totext()");
	isc_buffer_usedregion(&b, &r);
	r.base[r.length] = 0;
	return (char *) r.base;
}

char *
algtostr(const dns_secalg_t alg) {
	isc_buffer_t b;
	isc_region_t r;
	isc_result_t result;
	static char data[10];

	isc_buffer_init(&b, data, sizeof(data));
	result = dns_secalg_totext(alg, &b);
	check_result(result, "dns_secalg_totext()");
	isc_buffer_usedregion(&b, &r);
	r.base[r.length] = 0;
	return ((char *)r.base);
}

void
setup_logging(int verbose, isc_mem_t *mctx, isc_log_t **logp) {
	isc_result_t result;
	isc_logdestination_t destination;
	isc_logconfig_t *logconfig;
	isc_log_t *log = 0;
	int level;

	switch (verbose) {
        case 0:
                /*
		 * We want to see warnings about things like out-of-zone
		 * data in the master file even when not verbose.
		 */
		level = ISC_LOG_WARNING;
		break;
	case 1:
		level = ISC_LOG_INFO;
		break;
	default:
		level = ISC_LOG_DEBUG(verbose - 2 + 1);
		break;
	}
	
	RUNTIME_CHECK(isc_log_create(mctx, &log, &logconfig) == ISC_R_SUCCESS);
	isc_log_setcontext(log);
	dns_log_init(log);
	dns_log_setcontext(log);

	RUNTIME_CHECK(isc_log_settag(logconfig, program) == ISC_R_SUCCESS);

	/*
	 * Set up a channel similar to default_stderr except:
	 *  - the logging level is passed in
	 *  - the program name and logging level are printed
	 *  - no time stamp is printed
	 */
	destination.file.stream = stderr;
	destination.file.name = NULL;
	destination.file.versions = ISC_LOG_ROLLNEVER;
	destination.file.maximum_size = 0;
	result = isc_log_createchannel(logconfig, "stderr",
				       ISC_LOG_TOFILEDESC,
				       level,
				       &destination,
				       ISC_LOG_PRINTTAG|ISC_LOG_PRINTLEVEL);
	check_result(result, "isc_log_createchannel()");
	
	RUNTIME_CHECK(isc_log_usechannel(logconfig, "stderr",
					 NULL, NULL) == ISC_R_SUCCESS);

	*logp = log;
}

void
setup_entropy(isc_mem_t *mctx, const char *randomfile, isc_entropy_t **ectx) {
	isc_result_t result;
	result = isc_entropy_create(mctx, ectx);
	if (result != ISC_R_SUCCESS)
		fatal("could not create entropy object");
	if (randomfile != NULL) {
		result = isc_entropy_createfilesource(*ectx, randomfile, 0,
						      &filesource);
		if (result == ISC_R_SUCCESS)
			return;
	}
	result = isc_entropy_createfilesource(*ectx, "/dev/random", 0,
					      &filesource);
	if (result != ISC_R_SUCCESS)
		fatal("No randomfile specified, and /dev/random not present.");
	return;
}

void
cleanup_entropy(isc_entropy_t **ectx) {
	if (filesource != NULL)
		isc_entropy_destroysource(&filesource);
	isc_entropy_detach(ectx);
}
