/*
 * logging.c - logging support
 */

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

#ifndef lint
static char *rcsid = "$Id: logging.c,v 1.1.2.1 2002/02/08 12:14:49 marka Exp $";
#endif

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYSLOG
#include <syslog.h>
#endif

#include <mdn/log.h>
#include <mdn/version.h>

#include "mdnsproxy.h"

#define DEFAULT_LOGFILE	"mdnsproxy.log"

#ifdef DEBUG
#define DEFAULT_LOG_LEVEL LOGLEVEL_TRACE
#else
#define DEFAULT_LOG_LEVEL LOGLEVEL_WARN
#endif

#ifndef LOGDIR
#define LOGDIR	"/var/mdnsproxy"
#endif

/*
 * Logging Control Variables
 */

static  char    logFname[256] = { 0 } ;
static  FILE    *logFptr = NULL       ;
static  int	logMode = LOGMODE_FILE;
static	int	logFacility;
static	int	logLevel = DEFAULT_LOG_LEVEL ;
static  int	timeToTurnOver = 0 ;

/*
 * log_default_path -- get default log file pathname
 */

static void	log_default_path(void)
{
#ifdef UNIX
    sprintf(logFname, "%s/%s", LOGDIR, DEFAULT_LOGFILE) ;
#endif
#if defined(WIN32) || defined(OS2)
    {
	char *env;
	if ((env = getenv("TEMP")) == NULL)
	    env = getenv("TMP");
	if (env != NULL &&
	    strlen(env) + strlen(DEFAULT_LOGFILE) + 1 < sizeof(logFname)) {
	    (void)strcpy(logFname, env);
	    (void)strcat(logFname, "\\");
	    (void)strcat(logFname, DEFAULT_LOGFILE);
	}
    }
#endif
}    const char *name;


/*
 * log_setlevel - set log level
 */
void	log_setlevel(int level)
{
    logLevel = level;
}

/*
 * log_strtolevel - string to log level
 */
int	log_strtolevel(char *s)
{
    if ('0' <= s[0] && s[0] <= '9') {
	return atoi(s) ;
    } else if (!strcmp(s, "none")) {
	return LOGLEVEL_NONE;
    } else if (!strcmp(s, "fatal")) {
	return LOGLEVEL_FATAL;
    } else if (!strcmp(s, "warn") || !strcmp(s, "warning")) {
	return LOGLEVEL_WARN;
    } else if (!strcmp(s, "trace")) {
	return LOGLEVEL_TRACE;
    } else {
	return -1;
    }
}

typedef struct {
    const char *name;
    int value;
} syslog_facility_t;

static const syslog_facility_t facility_table[] = {
#ifdef LOG_AUTH
    {"auth",		LOG_AUTH},
#endif
#ifdef LOG_AUTHPRIV
    {"authpriv",	LOG_AUTHPRIV},
#endif
#ifdef LOG_CRON
    {"cron",		LOG_CRON},
#endif
#ifdef LOG_DAEMON
    {"daemon",		LOG_DAEMON},
#endif
#ifdef LOG_FTP
    {"ftp",		LOG_FTP},
#endif
#ifdef LOG_KERN
    {"kern",		LOG_KERN},
#endif
#ifdef LOG_LOCAL0
    {"local0",		LOG_LOCAL0},
#endif
#ifdef LOG_LOCAL1
    {"local1",		LOG_LOCAL1},
#endif
#ifdef LOG_LOCAL2
    {"local2",		LOG_LOCAL2},
#endif
#ifdef LOG_LOCAL3
    {"local3",		LOG_LOCAL3},
#endif
#ifdef LOG_LOCAL4
    {"local4",		LOG_LOCAL4},
#endif
#ifdef LOG_LOCAL5
    {"local5",		LOG_LOCAL5},
#endif
#ifdef LOG_LOCAL6
    {"local6",		LOG_LOCAL6},
#endif
#ifdef LOG_LOCAL7
    {"local7",		LOG_LOCAL7},
#endif
#ifdef LOG_LPR
    {"lpr",		LOG_LPR},
#endif
#ifdef LOG_MAIL
    {"mail",		LOG_MAIL},
#endif
#ifdef LOG_NEWS
    {"news",		LOG_NEWS},
#endif
#ifdef LOG_SYSLOG
    {"syslog",		LOG_SYSLOG},
#endif
#ifdef LOG_USER
    {"user",		LOG_USER},
#endif
#ifdef LOG_UUCP
    {"uucp",		LOG_UUCP},
#endif
    {NULL,		0}
};

/*
 * log_strtofacility - string to log facility
 */
static int	log_strtofacility(char *name, int *value)
{
    const syslog_facility_t *p;

    for (p = facility_table; p->name != NULL; p++) {
	if (strcmp(name, p->name) == 0) {
	    *value = p->value;
	    return 1;
	}
    }

    return 0;
}

/*
 * log_terminate - terminate logging
 */

void    log_terminate(void)
{
    if (logMode == LOGMODE_FILE && logFptr != NULL) {
	fclose(logFptr) ;
	logFptr = NULL  ;
    }
}

/*
 * log_turnover_request - request turning over log
 *	this function is intended for calling from singnal handler.
 */

void	log_turnover_request(void)
{
    timeToTurnOver = 1;
}

/*
 * log_turnover - turn over log if requested
 */

void	log_turnover(void)
{
    if (timeToTurnOver && logMode == LOGMODE_FILE) {
	timeToTurnOver = 0;
	log_trace_printf("--- log file turned over\n");
	log_terminate() ;
	logFptr = fopen(logFname, "a") ;
    }
}

/*
 * libmdn_logproc - log hander for libmdn
 *	output message to a regular log file.
 */
static void
libmdn_logproc(int level, const char *message)
{
    char    buff[512] ;
    char    *newline;
    time_t  t;

    if (logMode == LOGMODE_SYSLOG) {
#ifdef HAVE_SYSLOG
	switch (level) {
	case mdn_log_level_fatal:
	    syslog(LOG_ERR, "[FATAL] %s", message);
	    break;
	case mdn_log_level_error:
	    syslog(LOG_ERR, "[ERROR] %s", message);
	    break;
	case mdn_log_level_warning:
	    syslog(LOG_WARNING, "[WARNING] %s", message);
	    break;
	case mdn_log_level_info:
	    syslog(LOG_INFO, "[INFO] %s", message);
	    break;
	case mdn_log_level_trace:
	    syslog(LOG_DEBUG, "[TRACE] %s", message);
	    break;
	case mdn_log_level_dump:
	    syslog(LOG_DEBUG, "[DUMP] %s", message);
	    break;
	default:
	    syslog(LOG_NOTICE, "[LEVEL%d] %s", level, message);
	    break;
	}
#endif /* HAVE_SYSLOG */

    } else if (logMode == LOGMODE_STDERR) {
	fputs(message, logFptr) ;
	fflush(logFptr) ;

    } else if (logFptr != NULL) {
	t = time(NULL);
	strcpy(buff, ctime(&t));
	newline = strchr(buff, '\n');
	if (newline != NULL)
	    *newline = '\0';

	fputs(buff, logFptr);
	fprintf(logFptr, " [%d]: ", (int)getpid());
	fputs(message, logFptr) ;
	fflush(logFptr) ;
    }
}

/*
 * libmdn_string_to_loglevel - convert log level name to value.
 */

static int
libmdn_string_to_loglevel(char *s)
{
    if ('0' <= s[0] && s[0] <= '9')
	return atoi(s);
    else if (!strcmp(s, "fatal"))
	return mdn_log_level_fatal;
    else if (!strcmp(s, "error"))
	return mdn_log_level_error;
    else if (!strcmp(s, "warning"))
	return mdn_log_level_warning;
    else if (!strcmp(s, "info"))
	return mdn_log_level_info;
    else if (!strcmp(s, "trace"))
	return mdn_log_level_trace;
    else if (!strcmp(s, "dump"))
	return mdn_log_level_dump;
    else
	return -1;
}

/*
 * log_vprintf - as name describes
 */

static void	log_vprintf(int level, char *fmt, va_list arg_ptr)
{
    char    buff[512] ;
    char    *newline;
    time_t  t;
    
    if (logLevel < level) {
	return;
    }

    /*
     * format message
     */
     
    if (logMode == LOGMODE_SYSLOG) {
	vsprintf(buff, fmt, arg_ptr) ;

#ifdef HAVE_SYSLOG
	switch (level) {
	case LOGLEVEL_FATAL:
	    syslog(LOG_ERR, buff);
	    break;
	case LOGLEVEL_WARN:
	    syslog(LOG_WARNING, buff);
	    break;
	case LOGLEVEL_TRACE:
	    syslog(LOG_DEBUG, buff);
	    break;
	}
#endif /* HAVE_SYSLOG */

    } else if (logMode == LOGMODE_STDERR) {
	vfprintf(logFptr, fmt, arg_ptr) ;
	fflush(logFptr) ;

    } else if (logFptr != NULL) {
	t = time(NULL);
	strcpy(buff, ctime(&t));
	newline = strchr(buff, '\n');
	if (newline != NULL)
	    *newline = '\0';

	fputs(buff, logFptr);
	fprintf(logFptr, " [%d]: ", (int)getpid());
	vfprintf(logFptr, fmt, arg_ptr);
	fflush(logFptr) ;
    }

#ifdef  WIN32               /* For NT, having trouble with      */
    fclose(logFptr) ;       /* reading open'd logging file      */
    logFptr = NULL  ;       /* so, close and re-open it         */
#endif
}

/*
 * log_fatal_printf, log_warn_printf, log_trace_printf - write out
 *	fatal/warning/trace log to the log file
 */

void    log_fatal_printf(char *fmt, ...)
{
    va_list arg_ptr   ;
    
    va_start(arg_ptr, fmt) ;
    log_vprintf(LOGLEVEL_FATAL, fmt, arg_ptr) ;
    va_end(arg_ptr) ;
}

void    log_warn_printf(char *fmt, ...)
{
    va_list arg_ptr   ;
    
    va_start(arg_ptr, fmt) ;
    log_vprintf(LOGLEVEL_WARN, fmt, arg_ptr) ;
    va_end(arg_ptr) ;
}

void    log_trace_printf(char *fmt, ...)
{
    va_list arg_ptr   ;
    
    va_start(arg_ptr, fmt) ;
    log_vprintf(LOGLEVEL_TRACE, fmt, arg_ptr) ;
    va_end(arg_ptr) ;
}

/*
 * log_configure - configure logging (must be called after 'config_load')
 */

BOOL    log_configure(int ac, char *av[])
{
    int     i, nArgs   ;
    char    **aArgs    ;
    char    *fn = NULL ;
    int     lineNo;

    log_default_path();

#ifdef HAVE_SYSLOG
    logFacility = LOG_DAEMON;
#endif

    for (i = 1 ; i < ac ; i++) {
        if (strcmp(av[i], CMDOPT_LOGFILE) == 0) {
	    fn = av[i+=1] ;
	}
    }
    if (fn != NULL) {
	if (strlen(fn) + 1 > sizeof(logFname)) {
		fprintf(stderr,
		    "log_configure - too long log file name \"%.100s...\"\n",
		     fn);
	    return FALSE;
	}
        strcpy(logFname, fn) ;

    } else if (config_query_value(KW_LOG_FILE, &nArgs, &aArgs, &lineNo)) {
	if (nArgs != 2) {
	    fprintf(stderr,
		"log_configure - wrong # of args for \"%s\", line %d\n", 
		KW_LOG_FILE, lineNo);
	    return FALSE;
	}
        strcpy(logFname, aArgs[1]) ;
    }

    if (config_query_value(KW_LOG_LEVEL, &nArgs, &aArgs, &lineNo) == TRUE) {
	int level ;

	if (nArgs != 2) {
	    fprintf(stderr,
		"log_configure - wrong # of args for \"%s\", line %d\n",
		KW_LOG_LEVEL, lineNo);
	    return FALSE;
	}
	if ((level = log_strtolevel(aArgs[1])) < 0) {
	    fprintf(stderr,
		"log_configure - invalid log level \"%.100s\", line %d\n",
		aArgs[1], lineNo);
	    return FALSE;
	}
	log_setlevel(level);
    }

    if (config_query_value(KW_MDN_LOG_LEVEL, &nArgs, &aArgs, &lineNo)) {
	int level;

	if (nArgs != 2) {
	    fprintf(stderr,
		"wrong # of args for \"%s\", line %d\n", KW_MDN_LOG_LEVEL,
		lineNo);
	    return FALSE;
	}
	if ((level = libmdn_string_to_loglevel(aArgs[1])) < 0) {
	    fprintf(stderr,
		"unknown mdn log level \"%.100s\", line %d\n", aArgs[1],
		lineNo);
	    return FALSE;
	}
	mdn_log_setlevel(level);
    }

#ifdef HAVE_SYSLOG
    if (config_query_value(KW_SYSLOG_FACILITY, &nArgs, &aArgs, &lineNo)
	== TRUE) {
	if (nArgs != 2) {
	    fprintf(stderr,
		"log_configure - wrong # of args for \"%s\", line %d\n",
		KW_LOG_LEVEL, lineNo);
	    return FALSE;
	} else if (!log_strtofacility(aArgs[1], &logFacility)) {
	    fprintf(stderr,
		"log_configure - unknown syslog facility \"%.100s\", "
		"line %d\n", aArgs[1], lineNo);
	    return FALSE;
	}
    }
#endif /* HAVE_SYSLOG */

    if (*logFname == '\0') {
	fprintf(stderr, "log_configure - no logging file specified\n");
        return FALSE;
    }

    if (strcmp(logFname, "syslog") == 0) {
#ifdef HAVE_SYSLOG
	logMode = LOGMODE_SYSLOG;
	logFptr = NULL;
	openlog("mdnsproxy", LOG_NDELAY | LOG_PID, logFacility);
	syslog(LOG_NOTICE, "** mdnsproxy version %s", mdn_version_getstring());
#else /* not HAVE_SYSLOG */
	fprintf(stderr, "log_configure - syslog is unavailable\n");
	return FALSE;
#endif /* not HAVE_SYSLOG */
    } else if (strcmp(logFname, "stderr") == 0) {
	logMode = LOGMODE_STDERR;
	logFptr = stderr;
    } else {
	logMode = LOGMODE_FILE;
	logFptr = fopen(logFname, "a") ;
	if (logFptr == NULL) {
	    fprintf(stderr,
		"log_configure - cannot open, the log file\"%.100s\"\n",
		logFname);
	    return FALSE;
	}
	fprintf(stderr, "** mdnsproxy version %s\n", mdn_version_getstring());
    }

    mdn_log_setproc(libmdn_logproc);

    return TRUE;
}
