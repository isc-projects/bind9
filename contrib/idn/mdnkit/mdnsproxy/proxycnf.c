/*
 * proxycnf.c - mDNS Proxy, configuration
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
static char *rcsid = "$Id: proxycnf.c,v 1.1.2.1 2002/02/08 12:14:57 marka Exp $";
#endif

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef  WIN32
#include <windows.h>
#include <winsock.h>
#else   /* for normal systems */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "mdnsproxy.h"       /* Common definitions for mDNS proxy    */

/*
 * Note that logging macros (FATAL, WARN and TRACE) cannot be used
 * until logging file is configured, i.e. log_configure() is called.
 * Be careful.
 */

/*
 * default config file (path & basename), depend on MACHINE
 */

#ifndef CONFIG_PATH
#warning "no \"CONFIG_PATH\", use "\"./\" as default" 
#define CONFIG_PATH "./"
#endif
#ifndef CONFIG_FILE
#warning "no \"CONFIG_FILE\", use "mdnsproxy.ini" as default" 
#define CONFIG_FILE "mdnsproxy.ini"
#endif
#ifndef CONFIG_HOME
#warning "no \"CONFIG_HOME\", use "\"./\" as default" 
#define CONFIG_HOME "./"
#endif

static  u_char  *confFile = CONFIG_FILE ;

static  u_char  *confPath[] = {
#if defined(DEBUG) && !defined(UNIX)
    "./",
    CONFIG_HOME,
#endif
    CONFIG_PATH,
    NULL
} ;

static u_char *confCommands[] = {
    KW_LISTEN,
    KW_FORWARD,
    KW_CLIENT_ENCODING,
    KW_MDN_CONF_FILE,
    KW_LOG_FILE,
    KW_LOG_LEVEL,
    KW_MDN_LOG_LEVEL,
    KW_SYSLOG_FACILITY,
    KW_USER_ID,
    KW_GROUP_ID,
    KW_ROOT_DIRECTORY,
    KW_ALLOW_ACCESS,
    KW_LOG_ON_DENIED,
    NULL
};

static u_char *confObsoleteCommands[] = {
    KW_CLIENT_TRANSLATION,
    KW_ALTERNATE_ENCODING,
    KW_NORMALIZE,
    KW_SERVER_TRANSLATION,
    KW_ENCODING_ALIAS_FILE,
    NULL
};

static  u_char  *expandName(u_char *name, u_char *buff)
{
#ifndef UNIX
    int     inEnv = FALSE ;
    u_char  *bp, *ep ;
    u_char  env[512] ;

    for (bp = buff, ep = env ; *name != '\0' ; name++) {
        if (inEnv == FALSE) {
	    if (*name == '$') {
	        inEnv = TRUE ;
		ep = env ;
	    } else {
	        *bp++ = *name ;
		*bp = '\0' ;
	    }
	} else {
	    if (*name == '(') {
                /* skip this */
            } else if (*name != ')') {
	        *ep++ = *name ;
		*ep = '\0' ;
	    } else if ((ep = getenv(env)) == NULL) {
	        return NULL ;
	    } else {
	        while (*ep != '\0') {
		    *bp++ = *ep++ ;
		}
		*bp = '\0' ;
		inEnv = FALSE ;
	    }
	}
    }
#else /* UNIX */
    strcpy(buff, name);
#endif /* UNIX */

    return buff ;
}

static  FILE    *openConfig(u_char *fname)
{
    int     i ;
    FILE    *fp = NULL ;
    u_char  path[512] ;
    u_char  name[512] ;
    
    /*
     * if coinfiguration file specified, open it
     */
     
    if (fname != NULL) {
        if (expandName(fname, name) == NULL) {
	    return NULL ;
	}
        if ((fp = fopen(name, "r")) == NULL) {
	    return NULL ;
	}
	return fp ;
    }
    
    /*
     * otherwise, look for configuration file in search path
     */

    for (i = 0 ; confPath[i] != NULL ; i++) {

        if (expandName(confPath[i], path) == NULL) {
	    continue ;
	}

	sprintf(name, "%s%s", path, confFile) ;
	
	if ((fp = fopen(name, "r")) != NULL) {
	    return fp ;
	}
    }
    return NULL ;
}

/*
 * configuration data in file consists of
 *
 *      key value ...
 *
 *  lines.  This module hold them as following list.
 */

typedef struct  _CONF   *CNFPTR ;

typedef struct _CONF {
    int     lineNo   ;
    CNFPTR  prev     ;
    CNFPTR  next     ;
    u_char  *key     ;  /* really, buffer for key & val     */
    int     nVal     ;
    u_char  *aVal[1] ;  /* really, follows 'nVal' entries   */
} CNFREC ;

static  CNFREC  confList = { 0 } ;

static  void    disposeData(void)
{
    CNFPTR  p ;
    
    if (confList.prev == NULL || confList.next == NULL) {
        return ;
    }
    while ((p = confList.next) != &confList) {
        confList.next = p->next ;
	free(p->key) ;
	free(p) ;
    }
}

static  u_char  *getString(u_char *p, CNFPTR pCnf)
{
    /*
     * mark start of value string
     */
     
    pCnf->aVal[pCnf->nVal++] = p ;

    /*
     * look for end of string, any space
     */

    for ( ; *p != '\0' ; p++) {
        if (isspace(*p)) {
	    break ;
	}
    }
    if (*p != '\0') {
        *p++ = '\0' ;
    }
    return p ;
}

static  u_char  *getQuoted(u_char *p, CNFPTR pCnf)
{
    if (*p != '"') {        /* Oh, something wrong !! */
        return p ;
    }
    p++ ;                   /* skip leading '"' */

    /*
     * mark start of value string
     */

    pCnf->aVal[pCnf->nVal++] = p ;

    /*
     * look for terminating '"', may be escaped with '\'
     */

    while (*p != '\0' && *p != '\n' && *p != '\r') {
        if (*p == '"') {
	    break ;
	} else if (*p == '\\') {    /* quoted pair */
	    p += 2 ;
	} else {
	    p += 1 ;
	}
    }
    if (*p != '\0') {
        *p++ = '\0' ;
    }
    return p ;
}

static	BOOL	findCommand(u_char *name)
{
    u_char **cmd;

    for (cmd = (u_char **)confCommands; *cmd != NULL; cmd++) {
	if (strcmp(*cmd, name) == 0)
	    return TRUE;
    }

    return FALSE;
}

static	BOOL	findObsoleteCommand(u_char *name)
{
    u_char **cmd;

    for (cmd = (u_char **)confObsoleteCommands; *cmd != NULL; cmd++) {
	if (strcmp(*cmd, name) == 0)
	    return TRUE;
    }

    return FALSE;
}

static  BOOL    appendData(u_char *line, int lineNo)
{
    int     len ;
    u_char  *pStr, *p  ;
    CNFPTR  pCnf, pNew ;
    CNFPTR  prev, next ;
    
    /*
     * list is not initialized, initialize it
     */
     
    if (confList.prev == NULL || confList.next == NULL) {
        confList.prev = &confList ;
	confList.next = &confList ;
    }

    /*
     * prepare buffers 
     */
    
    len = strlen(line) ;
    
    pCnf = (CNFPTR) malloc(sizeof(CNFREC) + sizeof(u_char *) * len) ;
    pStr = malloc(len + 2) ;
    
    if (pStr == NULL || pCnf == NULL) {
        fprintf(stderr, "appendData - cannot allocate memory\n") ;
	if (pStr != NULL) free(pStr) ;
	if (pCnf != NULL) free(pCnf) ;
	return FALSE ;
    }
    
    memset(pCnf, 0, sizeof(CNFREC)) ;

    for (p = pStr ; *line != '\0' ;  ) {
        if (*line == '\n' || *line == '\r') {
	    break ;
	}
	*p++ = *line++ ;
    }
    *p = '\0' ;

    /*
     * parse line (save results into pCnf)
     *
     *      term may be string or quoted-string
     */

    for (p = pStr ; *p != '\0' ;  ) {
        if (isspace(*p)) {
	    p += 1 ;
	} else if (*p == '#') {
	    break ;
	} else if (*p == '"') {
	    p = getQuoted(p, pCnf) ;
	} else {
	    p = getString(p, pCnf) ;
	}
    }

    /*
     * if no term found, skip the line
     */

    if (pCnf->nVal == 0) {
	free(pStr) ;
	free(pCnf) ;
	return TRUE ;
    }

    if (findObsoleteCommand(pStr)) {
        fprintf(stderr, "appendData - obsolete command \"%.100s\", line %d\n",
	    pStr, lineNo) ;
	return FALSE;
    }
    if (!findCommand(pStr)) {
        fprintf(stderr, "appendData - unknown command \"%.100s\", line %d\n",
	    pStr, lineNo) ;
	return FALSE;
    }

    /*
     * create resulting CNF record
     */

    pNew = (CNFPTR) malloc(sizeof(CNFREC) + sizeof(u_char *) * pCnf->nVal) ;
    
    if (pNew == NULL) {
        fprintf(stderr, "appendData - cannot allocate memory\n") ;
	free(pStr) ;
	free(pCnf) ;
	return FALSE ;
    }

    memset(pNew, 0, sizeof(CNFREC)) ;
    
    pNew->lineNo = lineNo;
    pNew->key = pStr ;
    pNew->nVal = pCnf->nVal ;
    memcpy(pNew->aVal, pCnf->aVal, sizeof(u_char *) * pCnf->nVal) ;
    
    free(pCnf) ;

    /*
     * link to list
     */

    prev = confList.prev ;
    next = prev->next    ;
    pNew->prev = confList.prev ;
    pNew->next = &confList     ;
    prev->next = pNew ;
    next->prev = pNew ;

    return TRUE ;
}

/*
 * config_load - load mDNS Proxy configuration data
 */

BOOL    config_load(int ac, char *av[])
{
    int     i     ;
    u_char  *conf ;
    FILE    *fp   ;
    u_char  line[512] ;
    int	    lineNo ;
    
    /*
     * check if alternate config file specified
     */

    for (i = 1, conf = CONFIG_PATH "/" CONFIG_FILE ; i < ac ; i++) {
        if (strcmp(av[i], "-config") == 0) {
	    if ((i + 1) < ac) {
	        conf = av[i+=1] ;
	    }
        }
    }

    /*
     * open configuration file
     */
     
    if ((fp = openConfig(conf)) == NULL) {
        fprintf(stderr, "config_load - cannot open the configuration file, "
	    "%s, \"%.100s\"\n", strerror(errno), conf) ;
	return FALSE ;
    }

    /*
     * read and parse configuration data (per line)
     */
    lineNo = 0;
    while (fgets(line, 512, fp) != NULL) {
	lineNo++;
        if (appendData(line, lineNo) != TRUE) {
	    fprintf(stderr, "config_load - error in \"%s\"\n", conf) ;
	    fclose(fp) ;
	    return FALSE ;
	}
    }
    
    fclose(fp) ;
    return TRUE ;
}

/*
 * config_dump - dump contents of mDNS Proxy configuration data
 */

static  BOOL    haveSpace(u_char *str)
{
    for ( ; *str != '\0' ; str++) {
        if (isspace(*str)) {
	    return TRUE ;
	}
    }
    return FALSE ;
}

void    config_dump(FILE *ofp)
{
    CNFPTR  p ;
    int     i ;
    
    if (confList.next == NULL || confList.prev == NULL) {
        return ;
    }
    for (p = confList.next ; p != &confList ; p = p->next) {
        if (haveSpace(p->key)) {
	    fprintf(ofp, "<%s>", p->key) ;
	} else {
	    fprintf(ofp, "<%s>", p->key) ;
	}
        for (i = 0  ; i < p->nVal ; i++) {
	    if (haveSpace(p->aVal[i])) {
	        fprintf(ofp, " \"%s\"", p->aVal[i]) ;
	    } else {
	        fprintf(ofp, " %s", p->aVal[i]) ;
	    }
        }
	fprintf(ofp, "\n") ;
    }
}

/*
 * config_free - dispose mDNS configuration data
 */

void    config_free(void)
{
    disposeData() ;
}

/*
 * config_query_value - query configuration data
 *
 *      this is generic interface to access configuration data
 *      but note, this function cannot work with multiple
 *      configuration data, such as client-translation
 */

BOOL    config_query_value(char *key, int *count, char ***array, int *lineNo)
{
    CNFPTR  p ;
    
    for (p = confList.next ; p != &confList ; p = p->next) {
        if (strcmp(p->key, key) != 0) {
	    continue ;
	}
	*count = p->nVal ;
	*array = (char **) p->aVal ;
	*lineNo = p->lineNo;
	return TRUE ;
    }
    return FALSE ;
}

/*
 * config_query_listen, config_query_forward
 *
 *      queries sockaddr (really sockaddr_in) of proxy to listen, 
 *      and DNS server to which proxy forwards the requests.  
 *      These function set
 *
 *          addr->sin_family    <- AF_INET
 *          addr->sin_addr      <- specified/default
 *          addr->sin_port      <- specified/default
 *
 *      for 'listen' address, both sin_addr/sin_port have default values,
 *      but for 'forward' address, there is no default for 'sin_addr',
 *      and result error on such case.
 *
 *  NOTE: for DNS proxy, both listen/forward address should be
 *        specified with xx.xx.xx.xx notation, never be host name
 */

#define DEFAULT_ADDR    INADDR_ANY
#define DEFAULT_PORT    53

static  CNFPTR  queryData(u_char *key)
{
    CNFPTR  p ;
    
    for (p = confList.next ; p != &confList ; p = p->next) {
        if (strcmp(p->key, key) == 0) {
            return p ;
	}
    }
    return NULL ;
}

/*
 * Parse `host:port'.  Either `host' or `port' can be omitted.
 */
static  BOOL    getHostPort(u_char *arg, struct sockaddr_in *iaddr, int lineNo)
{
    unsigned int octets[4];
    unsigned short port;
    int digit_count;
    int octet_count;
    const char *p = arg;

    octets[0] = (DEFAULT_ADDR >> 24) & 0xff;
    octets[1] = (DEFAULT_ADDR >> 16) & 0xff;
    octets[2] = (DEFAULT_ADDR >> 8)  & 0xff;
    octets[3] = (DEFAULT_ADDR)       & 0xff;
    port = DEFAULT_PORT;

    /*
     * Parse an dot noted IP address.
     */
    if ('0' <= *p && *p <= '9') {
	octet_count = 0; 
	while (octet_count < 4) {
	    octets[octet_count] = 0;
	    if (*p == '0' && '0' <= *(p + 1) && *(p + 1) <= '9') {
		WARN("getHostPort - invalid address \"%.100s\", line %d\n",
		    arg, lineNo);
		return FALSE;
	    }
	    for (digit_count = 0; '0' <= *p && *p <= '9'; p++, digit_count++)
		octets[octet_count] = octets[octet_count] * 10 + (*p - '0');
	    if (digit_count == 0 || digit_count > 3 ||
		octets[octet_count] > 255) {
		WARN("getHostPort - invalid address \"%.100s\" line %d\n",
		    arg, lineNo);
		return FALSE;
	    }
	    octet_count++;

	    if (octet_count != 4) {
		if (*p != '.') {
		    WARN("getHostPort - malformed address \"%.100s\", "
			"line %d\n", arg, lineNo);
		    return FALSE;
		}
		p++;
	    }
	}
    }

    /*
     * Parse an optional port number preceded by `:'.
     */
    if (*p == ':') {
	port = 0;
	p++;
	if (*p == '0' && '0' <= *(p + 1) && *(p + 1) <= '9') {
	    WARN("getHostPort - invalid port number \"%.100s\", line %d\n",
		arg, lineNo);
	    return FALSE;
	}
	for (digit_count = 0; '0' <= *p && *p <= '9'; p++, digit_count++)
	    port = port * 10 + (*p - '0');
	if (digit_count == 0 && *p == '\0') {
	    port = DEFAULT_PORT;
	} else if (digit_count == 0 || digit_count > 5 || port == 0 ||
	    port > 65535) {
	    WARN("getHostPort - invalid port number \"%.100s\", line %d\n",
		arg, lineNo);
	    return FALSE;
	}
    }

    if (*p != '\0') {
	WARN("getHostPort - invalid address \"%.100s\", line %d\n",
	    arg, lineNo);
	return FALSE;
    }

    /*
     * Put the result into `address' and `port'.
     */
    iaddr->sin_addr.s_addr = htonl((octets[0] << 24) + (octets[1] << 16)
	+ (octets[2] << 8) + octets[3]);
    iaddr->sin_port = htons(port);

    return TRUE;
}

/*
 * Parse `host:port'.  `port' can be omitted.
 */
static  BOOL    getHostPort2(u_char *arg, struct sockaddr_in *iaddr, 
			     int lineNo)
{
    if (*arg == ':') {
	WARN("getHostPort2 - missing host name \"%.100s\", line %d\n",
	    arg, lineNo);
	return FALSE;
    }

    return getHostPort(arg, iaddr, lineNo);
}

BOOL    config_query_listen(struct sockaddr *addr)
{
    CNFPTR  pListen ;
    struct sockaddr_in  *iaddr ;

    memset(addr, 0, sizeof(struct sockaddr)) ;
    iaddr = (struct sockaddr_in *) addr      ;
    
    if ((pListen = queryData(KW_LISTEN)) == NULL) {
        iaddr->sin_addr.s_addr = htonl(DEFAULT_ADDR) ;
	iaddr->sin_port        = htons(DEFAULT_PORT) ;
	return TRUE ;
    }
    if (pListen->nVal != 2) {
        WARN("config_query_listen - wrong # of args for \"%s\", line %d\n",
	    KW_LISTEN, pListen->lineNo) ;
	return FALSE ;
    }

    if (!getHostPort(pListen->aVal[1], iaddr, pListen->lineNo)) {
	return FALSE;
    }

    iaddr->sin_family = AF_INET ;
    
    return TRUE ;
}

BOOL    config_query_forward(struct sockaddr *addr)
{
    CNFPTR  pForward ;
    struct sockaddr_in  *iaddr ;
    
    memset(addr, 0, sizeof(struct sockaddr)) ;
    iaddr = (struct sockaddr_in *) addr      ;
    iaddr->sin_family = AF_INET ;

    if ((pForward = queryData(KW_FORWARD)) == NULL) {
        WARN("config_query_forward - \"%s\" not found in the configuration "
	    "file\n", KW_FORWARD) ;
	return FALSE ;
    }
    if (pForward->nVal != 2 && pForward->nVal != 3) {
        WARN("config_query_forward - wrong # of args for \"%s\", line %d\n",
	    KW_FORWARD, pForward->lineNo) ;
	return FALSE ;
    }

    if (!getHostPort2(pForward->aVal[1], iaddr, pForward->lineNo)) {
	return FALSE ;
    }

    iaddr->sin_family = AF_INET ;

    return TRUE ;	
}

/*
 * config_query_restrict - query 'source-restrict' flag
 */

BOOL    config_query_restrict(BOOL *src_restrict)
{
    CNFPTR  pForward ;
    
    if ((pForward = queryData(KW_FORWARD)) == NULL) {
        *src_restrict = FALSE ;
    } else if (pForward->nVal < 3) {
        *src_restrict = FALSE ;
    } else if (strcmp(pForward->aVal[2], "bind4compat") != 0) {
        *src_restrict = FALSE ;
    } else {
        *src_restrict = TRUE ;
    }
    return TRUE ;
}

/*
 * config_query_log_on_denied - query 'log-on-denied' flag
 */

BOOL    config_query_log_on_denied(BOOL *flag)
{
    CNFPTR  pForward ;
    
    if ((pForward = queryData("log-on-denied")) == NULL) {
        *flag = FALSE ;
	return TRUE ;
    }
    if (pForward->nVal != 2)
	return FALSE ;

    if (strcmp(pForward->aVal[1], "yes") == 0)
        *flag = TRUE ;
    else if (strcmp(pForward->aVal[1], "no") == 0)
        *flag = FALSE ;
    else
	return FALSE ;

    return TRUE;
}

/*
 * config_query_open, config_query_more, config_query_close
 *
 *      this is generic interface to access configuration data
 *      for multiple entires for same key value.
 */

config_ctx_t    config_query_open(char *key, int *count, char ***array,
				  int *lineNo)
{
    CNFPTR  p ;
    
    for (p = confList.next ; p != &confList ; p = p->next) {
        if (strcmp(p->key, key) != 0) {
	    continue ;
	}
	*count = p->nVal ;
	*array = (char **) p->aVal ;
	*lineNo = p->lineNo;
	return (config_ctx_t) p ;
    }
    return NULL ;
}

config_ctx_t    config_query_more(config_ctx_t ctx, int *count, char ***array,
				  int *lineNo)
{
    CNFPTR  p = (CNFPTR) ctx ;
    CNFPTR  np ;
    
    for (np = p->next ; np != &confList ; np = np->next) {
        if (strcmp(np->key, p->key) != 0) {
	    continue ;
	}
	*count = np->nVal ;
	*array = (char **) np->aVal ;
	*lineNo = np->lineNo;
	return (config_ctx_t) np ;
    }
    return NULL ;
}

void            config_query_close(config_ctx_t ctx)
{
    /* nothing to do */
}

#ifdef  TEST
/*
 * test driver for 'config' module
 */

static  void    dumpaddr(u_char *str, struct sockaddr *addr)
{
    u_char  *p ;
    struct sockaddr_in  *iaddr = (struct sockaddr_in *) addr ;
    
    printf("%s ", str) ;
    
    p = (u_char *) &iaddr->sin_addr ;
    printf("address %d.%d.%d.%d", 
        (p[0] & 0xff), (p[1] & 0xff), (p[2] & 0xff), (p[3] & 0xff)) ;

    p = (u_char *) &iaddr->sin_port ;
    printf(" port %d", ((p[0] & 0xff) * 256 + (p[1] & 0xff))) ;

    printf("\n") ;
}

static  void    dumpvalue(char *key, int count, char **array)
{
    int     i ;
    
    for (i = 0 ; i < count ; i++) {
        printf("%s ", array[i]) ;
    }
    printf("\n") ; fflush(stdout) ;
}

int     main(int ac, char *av[])
{
    int                 stat ;
    struct sockaddr     addr ;
    int     count   ;
    char    **array ;
    config_ctx_t    ctx ;
    int			lineNo;

    if ((stat = config_load(ac, av)) != TRUE) {
        printf("config_load failed %d\n", stat) ;
	return 1 ;
    }
    config_dump(stdout) ;

    if (config_query_value(KW_LISTEN, &count, &array, &lineNo) == TRUE) {
        dumpvalue("listen", count, array) ;
    }
    if (config_query_value(KW_FORWARD, &count, &array, &lineNo) == TRUE) {
        dumpvalue("forward", count, array) ;
    }
    
    ctx = config_query_open("client-translation", &count, &array, &lineNo) ;
    while (ctx != NULL) {
        dumpvalue("client-translation", count, array) ;
        ctx = config_query_more(ctx, &count, &array, &lineNo) ;
    }
    config_query_close(ctx) ;

    if (config_query_listen(&addr) != TRUE) {
        printf("no \"listen\" data\n") ;
    } else {
        dumpaddr("listen", &addr) ;
    }

    if (config_query_forward(&addr) != TRUE) {
        printf("no \"forward\" data\n") ;
    } else {
        dumpaddr("forward", &addr) ;
    }
    
    config_free() ;
    return 0 ;
}
#endif  /* TEST */
