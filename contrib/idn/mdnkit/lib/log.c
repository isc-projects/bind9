#ifndef lint
static char *rcsid = "$Id: log.c,v 1.1 2002/01/02 02:46:43 marka Exp $";
#endif

/*
 * Copyright (c) 2000 Japan Network Information Center.  All rights reserved.
 *  
 * By using this file, you agree to the terms and conditions set forth bellow.
 * 
 * 			LICENSE TERMS AND CONDITIONS 
 * 
 * The following License Terms and Conditions apply, unless a different
 * license is obtained from Japan Network Information Center ("JPNIC"),
 * a Japanese association, Kokusai-Kougyou-Kanda Bldg 6F, 2-3-4 Uchi-Kanda,
 * Chiyoda-ku, Tokyo 101-0047, Japan.
 * 
 * 1. Use, Modification and Redistribution (including distribution of any
 *    modified or derived work) in source and/or binary forms is permitted
 *    under this License Terms and Conditions.
 * 
 * 2. Redistribution of source code must retain the copyright notices as they
 *    appear in each source code file, this License Terms and Conditions.
 * 
 * 3. Redistribution in binary form must reproduce the Copyright Notice,
 *    this License Terms and Conditions, in the documentation and/or other
 *    materials provided with the distribution.  For the purposes of binary
 *    distribution the "Copyright Notice" refers to the following language:
 *    "Copyright (c) Japan Network Information Center.  All rights reserved."
 * 
 * 4. Neither the name of JPNIC may be used to endorse or promote products
 *    derived from this Software without specific prior written approval of
 *    JPNIC.
 * 
 * 5. Disclaimer/Limitation of Liability: THIS SOFTWARE IS PROVIDED BY JPNIC
 *    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *    PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL JPNIC BE LIABLE
 *    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *    OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *    ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * 6. Indemnification by Licensee
 *    Any person or entities using and/or redistributing this Software under
 *    this License Terms and Conditions shall defend indemnify and hold
 *    harmless JPNIC from and against any and all judgements damages,
 *    expenses, settlement liabilities, cost and other liabilities of any
 *    kind as a result of use and redistribution of this Software or any
 *    claim, suite, action, litigation or proceeding by any third party
 *    arising out of or relates to this License Terms and Conditions.
 * 
 * 7. Governing Law, Jurisdiction and Venue
 *    This License Terms and Conditions shall be governed by and and
 *    construed in accordance with the law of Japan. Any person or entities
 *    using and/or redistributing this Software under this License Terms and
 *    Conditions hereby agrees and consent to the personal and exclusive
 *    jurisdiction and venue of Tokyo District Court of Japan.
 */

#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <mdn/log.h>

#define LOGLEVEL_ENV	"MDN_LOG_LEVEL"

#ifdef DEBUG
#define DEFAULT_LOG_LEVEL	mdn_log_level_info
#else
#define DEFAULT_LOG_LEVEL	mdn_log_level_error
#endif

static int		log_level = -1;
static mdn_log_proc_t	log_proc;

static void	initialize(void);
static void	log(int level, const char *fmt, va_list args);
static void	log_to_stderr(int level, const char *buf);

void
mdn_log_fatal(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	log(mdn_log_level_fatal, fmt, args);
	va_end(args);
	exit(1);
}

void
mdn_log_error(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	log(mdn_log_level_error, fmt, args);
	va_end(args);
}

void
mdn_log_warning(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	log(mdn_log_level_warning, fmt, args);
	va_end(args);
}

void
mdn_log_info(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	log(mdn_log_level_info, fmt, args);
	va_end(args);
}

void
mdn_log_trace(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	log(mdn_log_level_trace, fmt, args);
	va_end(args);
}

void
mdn_log_dump(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	log(mdn_log_level_dump, fmt, args);
	va_end(args);
}

void
mdn_log_setlevel(int level) {
	if (level >= 0)
		log_level = level;
}

int
mdn_log_getlevel(void) {
	if (log_level < 0)
		initialize();
	return log_level;
}

void
mdn_log_setproc(mdn_log_proc_t proc) {
	if (proc == NULL)
		log_proc = log_to_stderr;
	else
		log_proc = proc;
}

static void
initialize(void) {
	char *s;

	if (log_level < 0) {
		if ((s = getenv(LOGLEVEL_ENV)) != NULL) {
			int level = atoi(s);
			if (level >= 0)
				log_level = level;
		}
		if (log_level < 0)
			log_level = DEFAULT_LOG_LEVEL;
	}

	if (log_proc == NULL)
		log_proc = log_to_stderr;
}

static void
log(int level, const char *fmt, va_list args) {
	char buf[1024];

	initialize();

	if (log_level < level)
		return;

#if HAVE_VSNPRINTF
	(void)vsnprintf(buf, sizeof(buf), fmt, args);
#else
	/* Let's hope 1024 is enough.. */
	(void)vsprintf(buf, fmt, args);
#endif
	(*log_proc)(level, buf);
}

static void
log_to_stderr(int level, const char *buf) {
	char *title;
	char tmp[20];

	switch (level) {
	case mdn_log_level_fatal:
		title = "FATAL";
		break;
	case mdn_log_level_error:
		title = "ERROR";
		break;
	case mdn_log_level_warning:
		title = "WARNING";
		break;
	case mdn_log_level_info:
		title = "INFO";
		break;
	case mdn_log_level_trace:
		title = "TRACE";
		break;
	case mdn_log_level_dump:
		title = "DUMP";
		break;
	default:
		(void)sprintf(tmp, "LEVEL%d", level);
		title = tmp;
		break;
	}
	fprintf(stderr, "%u: [%s] %s", (unsigned int)getpid(), title, buf);
}
