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
 * a Japanese association, Fuundo Bldg., 1-2 Kanda Ogawamachi, Chiyoda-ku,
 * Tokyo, Japan.
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
static char *rcsid = "$Id: proxycnf.c,v 1.16 2000/11/17 05:46:23 ishisone Exp $";
#endif

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef  WIN32
#include <windows.h>
#include <winsock.h>
#else   /* for normal systems */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "dnsproxy.h"       /* Common definitions for mDNS proxy    */
#include "proxycnf.h"       /* Machine/Env specific configuration   */

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
#warning "no \"CONFIG_FILE\", use "dnsproxy.ini" as default" 
#define CONFIG_FILE "dnsproxy.ini"
#endif
#ifndef CONFIG_HOME
#warning "no \"CONFIG_HOME\", use "\"./\" as default" 
#define CONFIG_HOME "./"
#endif

static  u_char  *confFile = CONFIG_FILE ;

static  u_char  *confPath[] = {
#ifdef  DEBUG
    "./",
    CONFIG_HOME,
#endif
    CONFIG_PATH,
    NULL
} ;

static  u_char  *expandName(u_char *name, u_char *buff)
{
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

static  BOOL    appendData(u_char *line)
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
        fprintf(stderr, "configure - cannot allocate parsing buffer\n") ;
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

    /*
     * create resulting CNF record
     */

    pNew = (CNFPTR) malloc(sizeof(CNFREC) + sizeof(u_char *) * pCnf->nVal) ;
    
    if (pNew == NULL) {
        fprintf(stderr, "configure - cannot allocate parsed record\n") ;
	free(pStr) ;
	free(pCnf) ;
	return FALSE ;
    }

    memset(pNew, 0, sizeof(CNFREC)) ;
    
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
    
    /*
     * check if alternate config file specified
     */

    for (i = 1, conf = NULL ; i < ac ; i++) {
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
        fprintf(stderr, "config - cannot locate config file\n") ;
	return FALSE ;
    }

    /*
     * read and parse configuration data (per line)
     */

    while (fgets(line, 512, fp) != NULL) {
        if (appendData(line) != TRUE) {
	    fprintf(stderr, "config - cannot load data %s\n", line) ;
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

BOOL    config_query_value(char *key, int *count, char ***array)
{
    CNFPTR  p ;
    
    for (p = confList.next ; p != &confList ; p = p->next) {
        if (strcmp(p->key, key) != 0) {
	    continue ;
	}
	*count = p->nVal ;
	*array = (char **) p->aVal ;
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

static  void    getHostPort(u_char *arg, u_char *host, u_char *port)
{
    for (*host = '\0' ; *arg != '\0' ; arg++) {
        if (*arg == ':') {
	    arg += 1 ;
	    break ;
	}
	*host++ = *arg ;
	*host = '\0'   ;
    }
    for (*port = '\0' ; *arg != '\0' ; arg++) {
        *port++ = *arg ;
	*port = '\0' ;
    }
}

BOOL    config_query_listen(struct sockaddr *addr)
{
    CNFPTR  pListen ;
    u_char  host[64], port[64] ;
    struct sockaddr_in  *iaddr ;

    memset(addr, 0, sizeof(struct sockaddr)) ;
    iaddr = (struct sockaddr_in *) addr      ;
    
    iaddr->sin_family = AF_INET ;
    
    if ((pListen = queryData("listen")) == NULL) {
        iaddr->sin_addr.s_addr = htonl(DEFAULT_ADDR) ;
	iaddr->sin_port        = htons(DEFAULT_PORT) ;
	return TRUE ;
    }
    if (pListen->nVal < 2) {
        iaddr->sin_addr.s_addr = htonl(DEFAULT_ADDR) ;
	iaddr->sin_port        = htons(DEFAULT_PORT) ;
	return TRUE ;
    }

    getHostPort(pListen->aVal[1], host, port) ;
    
    if (isdigit(*host)) {
        iaddr->sin_addr.s_addr = inet_addr(host) ;
    } else {
        iaddr->sin_addr.s_addr = htonl(DEFAULT_ADDR) ;
    }
    if (isdigit(*port)) {
        iaddr->sin_port = htons(atoi(port)) ;
    } else {
        iaddr->sin_port = htons(DEFAULT_PORT) ;
    }
    return TRUE ;
}

BOOL    config_query_forward(struct sockaddr *addr)
{
    CNFPTR  pForward ;
    u_char  host[64], port[64] ;
    struct sockaddr_in  *iaddr ;
    
    memset(addr, 0, sizeof(struct sockaddr)) ;
    iaddr = (struct sockaddr_in *) addr      ;

    if ((pForward = queryData("forward")) == NULL) {
        WARN("config - no \"forward\" record\n") ;
	return FALSE ;
    }
    if (pForward->nVal < 2) {
        WARN("config - no \"forward\" value\n") ;
	return FALSE ;
    }

    getHostPort(pForward->aVal[1], host, port) ;

    if (isdigit(*host)) {
        iaddr->sin_addr.s_addr = inet_addr(host) ;
    } else {
        WARN("config - no \"forward\" address\n") ;
        return FALSE ;
    }
    if (isdigit(*port)) {
        iaddr->sin_port = htons(atoi(port)) ;
    } else {
        iaddr->sin_port = htons(DEFAULT_PORT) ;
    }
    iaddr->sin_family = AF_INET ;

    return TRUE ;	
}

/*
 * config_query_restrict - query 'source-restrict' flag
 */

BOOL    config_query_restrict(BOOL *restrict)
{
    CNFPTR  pForward ;
    
    if ((pForward = queryData("forward")) == NULL) {
        *restrict = FALSE ;
    } else if (pForward->nVal < 3) {
        *restrict = FALSE ;
    } else if (strcmp(pForward->aVal[2], "bind4compat") != 0) {
        *restrict = FALSE ;
    } else {
        *restrict = TRUE ;
    }
    return TRUE ;
}

/*
 * config_query_open, config_query_more, config_query_close
 *
 *      this is generic interface to access configuration data
 *      for multiple entires for same key value.
 */

config_ctx_t    config_query_open(char *key, int *count, char ***array)
{
    CNFPTR  p ;
    
    for (p = confList.next ; p != &confList ; p = p->next) {
        if (strcmp(p->key, key) != 0) {
	    continue ;
	}
	*count = p->nVal ;
	*array = (char **) p->aVal ;
	return (config_ctx_t) p ;
    }
    return NULL ;
}

config_ctx_t    config_query_more(config_ctx_t ctx, int *count, char ***array)
{
    CNFPTR  p = (CNFPTR) ctx ;
    CNFPTR  np ;
    
    for (np = p->next ; np != &confList ; np = np->next) {
        if (strcmp(np->key, p->key) != 0) {
	    continue ;
	}
	*count = np->nVal ;
	*array = (char **) np->aVal ;
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
    
    if ((stat = config_load(ac, av)) != TRUE) {
        printf("config_load failed %d\n", stat) ;
	return 1 ;
    }
    config_dump(stdout) ;

    if (config_query_value("listen", &count, &array) == TRUE) {
        dumpvalue("listen", count, array) ;
    }
    if (config_query_value("forward", &count, &array) == TRUE) {
        dumpvalue("forward", count, array) ;
    }
    if (config_query_value("normalize", &count, &array) == TRUE) {
        dumpvalue("normalize", count, array) ;
    }
    if (config_query_value("server-translation", &count, &array) == TRUE) {
        dumpvalue("server-translation", count, array) ;
    }
    
    ctx = config_query_open("client-translation", &count, &array) ;
    while (ctx != NULL) {
        dumpvalue("client-translation", count, array) ;
        ctx = config_query_more(ctx, &count, &array) ;
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
