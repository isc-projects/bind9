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

/* $Id: dnssectool.c,v 1.12 2000/06/22 21:49:05 tale Exp $ */

#include <config.h>

#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/entropy.h>
#include <isc/keyboard.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/log.h>
#include <dns/name.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/secalg.h>

#include "dnssectool.h"

extern int verbose;
extern const char *program;

static isc_entropysource_t *source = NULL;
static isc_keyboard_t kbd;
static isc_boolean_t wantkeyboard = ISC_FALSE;

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

static isc_result_t
kbdstart(isc_entropysource_t *source, void *arg, isc_boolean_t blocking) {
	isc_keyboard_t *kbd = (isc_keyboard_t *)arg;
	static isc_boolean_t first = ISC_TRUE;

	UNUSED(source);

	if (!blocking)
		return (ISC_R_NOENTROPY);
	if (first) {
		if (!wantkeyboard) {
			fprintf(stderr, "You must use the keyboard to create "
				"entropy, since your system is lacking\n");
			fprintf(stderr, "/dev/random\n\n");
		}
		first = ISC_FALSE;
	}
	fprintf(stderr, "start typing:\n");
	return (isc_keyboard_open(kbd));
}

static void
kbdstop(isc_entropysource_t *source, void *arg) {
	isc_keyboard_t *kbd = (isc_keyboard_t *)arg;

	UNUSED(source);

	fprintf(stderr, "stop typing.\r\n");
	(void)isc_keyboard_close(kbd, 3);
}

static isc_result_t
kbdget(isc_entropysource_t *source, void *arg, isc_boolean_t blocking) {
	isc_keyboard_t *kbd = (isc_keyboard_t *)arg;
	isc_result_t result;
	isc_time_t t;
	isc_uint32_t sample;
	isc_uint32_t extra;
	unsigned char c;

	if (!blocking)
		return (ISC_R_NOENTROPY);

	result = isc_keyboard_getchar(kbd, &c);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = isc_time_now(&t);
	if (result != ISC_R_SUCCESS)
		return (result);

        sample = isc_time_nanoseconds(&t);
	extra = c;

	result = isc_entropy_addcallbacksample(source, sample, extra);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "\r\n");
		return (result);
	}

	fprintf(stderr, ".");
	fflush(stderr);

	return (result);
}

void
setup_entropy(isc_mem_t *mctx, const char *randomfile, isc_entropy_t **ectx) {
	isc_result_t result;

	result = isc_entropy_create(mctx, ectx);
	if (result != ISC_R_SUCCESS)
		fatal("could not create entropy object");
	if (randomfile != NULL && strcasecmp(randomfile, "keyboard") != 0) {
		result = isc_entropy_createfilesource(*ectx, randomfile);
		if (result != ISC_R_SUCCESS)
			fatal("could not open randomdev %s: %s", randomfile,
			      isc_result_totext(result));
	}
	else {
		if (randomfile == NULL) {
			result = isc_entropy_createfilesource(*ectx,
							      "/dev/random");
			if (result == ISC_R_SUCCESS)
				return;
		}
		else
			wantkeyboard = ISC_TRUE;
		result = isc_entropy_createcallbacksource(*ectx, kbdstart,
							  kbdget, kbdstop,
							  &kbd, &source);
		if (result != ISC_R_SUCCESS)
			fatal("failed to open keyboard: %s\n",
			      isc_result_totext(result));
	}
}

void
cleanup_entropy(isc_entropy_t **ectx) {
	if (source != NULL)
		isc_entropy_destroysource(&source);
	isc_entropy_detach(ectx);
}
