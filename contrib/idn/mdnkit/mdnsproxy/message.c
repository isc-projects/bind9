/*
 * message.c - mDNS Proxy, message handling
 *
 *      message will passed with callback 'notify_message'.
 *      this module parse received message and forward request,
 *      or reply to originator
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
static char *rcsid = "$Id: message.c,v 1.1.2.1 2002/02/08 12:14:55 marka Exp $";
#endif

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef  WIN32
#include <windows.h>
#include <winsock.h>
#else   /* for normal systems */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "mdnsproxy.h"

/*
 * address handling utilities
 *
 *      addrEq      check same addresses
 *      addrFmt     format address, port & protocol
 *
 *  these functions are same with those in 'server.c'.
 *  may be put in another 'utility' module.
 */

static  BOOL    addrEq(struct sockaddr *a1, struct sockaddr *a2)
{
    struct sockaddr_in  *ip1 = (struct sockaddr_in *) a1 ;
    struct sockaddr_in  *ip2 = (struct sockaddr_in *) a2 ;
    
    if (ip1->sin_addr.s_addr != ip2->sin_addr.s_addr) {
        return FALSE ;
    }
    if (ip1->sin_port != ip2->sin_port) {
        return FALSE ;
    }
    return TRUE ;
}

static  u_char  fmtbuff[64] ;

static  u_char  *addrFmt(struct sockaddr *addr, int proto)
{
    struct sockaddr_in  *iaddr = (struct sockaddr_in *) addr ;
    u_char  *ap ;
    u_char  *pp ;

    ap = (u_char *) &iaddr->sin_addr ;
    pp = (u_char *) &iaddr->sin_port ;
    
    sprintf(fmtbuff, "%s:%d.%d.%d.%d:%d",
        (proto == SOCK_STREAM ? "TCP" : "UDP"),
        (ap[0] & 0xff), (ap[1] & 0xff), (ap[2] & 0xff), (ap[3] & 0xff),
	((pp[0] & 0xff) * 256 + (pp[1] & 0xff)) ) ;

    return fmtbuff ;
}

/*
 * Managing Message ID
 */
 
static  u_short msgidLast = 0xffff ;
static  u_short msgidMap[4096] = { 0 } ;

#define ID_INDEX(x) (((x) & 0xfff0) >> 4)
#define ID_MASK(x)  (1 << ((x) & 0x000f))

#define ID_CHECK(x)  (msgidMap[ID_INDEX((x))] & ID_MASK((x)))
#define ID_USEIT(x)  (msgidMap[ID_INDEX((x))] |= ID_MASK((x)))
#define ID_CLEAR(x)  (msgidMap[ID_INDEX((x))] &= ~ID_MASK((x)))

static  BOOL    idAlloc(u_short *id)
{
    u_short newid ;
    
    for (newid = (msgidLast + 1) & 0xffff ;
	 newid != msgidLast ;
	 newid = (newid + 1) & 0xffff) {
        if (ID_CHECK(newid) == 0) {
	    ID_USEIT(newid) ;
	    msgidLast = newid ;
	    *id = newid ;
	    return TRUE ;
	}
    }
    WARN("idAlloc - no more ID\n") ;
    return FALSE ;
}

static  void    idFree(u_short id)
{
    if (ID_CHECK(id) == 0) {
        WARN("idAlloc - %04x is not in use\n", id) ;
	return ;
    }
    ID_CLEAR(id) ;
}

/*
 * Message Managements
 *
 *      Request from client is identified with its ID word.  It is unique
 *      on one client, but proxy accepts requests from multiple clients,
 *      proxy cannot distinguish request with ID only, and cannot forward
 *      request with such ID word.
 *
 *      So, proxy will identify requests with combination of address, port,
 *      (which identified client) and ID word.  Then forwarding request,
 *      proxy allocate unique ID, and change request's ID with new one.
 *
 *      Response from DNS server will identified with newly allocated ID.
 *      For responding such response to originator, replace response's
 *      ID with original one, and send response to marked address/port.
 */
 
typedef struct  _MSG    *MSGPTR ;

typedef struct  _MSG {
    MSGPTR                  prev  ;
    MSGPTR                  next  ;
    time_t                  last  ;
    struct sockaddr         from  ;
    int                     proto ;
    u_short                 orgId ;  
    u_short                 newId ;
    translation_context_t   trctx ;
} MSGREC ;

static  MSGREC  listMsg = { 0 } ;

/*
 * searchReq - search request in message list, search on original ID
 */

static  MSGPTR  searchReq(u_short id, int proto, struct sockaddr *addr)
{
    MSGPTR  p ;
    
    if (listMsg.prev == NULL || listMsg.next == NULL) {
        listMsg.prev = &listMsg ;
	listMsg.next = &listMsg ;
    }
    for (p = listMsg.next ; p != &listMsg ; p = p->next) {
        if (p->orgId != id || p->proto != proto) {
	    continue ;
	}
	if (addrEq(&p->from, addr) != TRUE) {
	    continue ;
	}
	p->last = time(NULL) ;
	return p ;
    }
    return NULL ;
}

/*
 * searchOrg - search original request matching to new ID
 */

static  MSGPTR  searchOrg(u_short id, int proto)
{
    MSGPTR  p ;
    
    if (listMsg.prev == NULL || listMsg.next == NULL) {
        listMsg.prev = &listMsg ;
	listMsg.next = &listMsg ;
    }
    for (p = listMsg.next ; p != &listMsg ; p = p->next) {
        if (p->newId != id || p->proto != proto) {
	    continue ;
	}
	p->last = time(NULL) ;
	return p ;
    }
    return NULL ;
}

/*
 * createReq - create new message record for new request
 *
 *      it also allocate new ID for this request, used for
 *      forwarding this request
 */

static  MSGPTR  createReq(u_short id, int proto, struct sockaddr *addr)
{
    u_short newid ;
    MSGPTR  pMsg, prev, next ;
    
    if (listMsg.prev == NULL || listMsg.next == NULL) {
        listMsg.prev = &listMsg ;
	listMsg.next = &listMsg ;
    }

    if (idAlloc(&newid) != TRUE) {
        WARN("createReq - no more ID\n") ;
	return NULL ;
    }
    if ((pMsg = (MSGPTR) malloc(sizeof(MSGREC))) == NULL) {
        WARN("createReq - cannot allocate message record\n") ;
	idFree(newid) ;
	return NULL ;
    }

    memset(pMsg, 0, sizeof(MSGREC)) ;
    
    memcpy(&pMsg->from, addr, sizeof(struct sockaddr)) ;
    pMsg->proto = proto ;
    pMsg->orgId = id    ;
    pMsg->newId = newid ;
    pMsg->last = time(NULL) ;

    pMsg->trctx.client   = &pMsg->from ;
    pMsg->trctx.protocol = pMsg->proto ;
    pMsg->trctx.old_id   = pMsg->orgId ;
    pMsg->trctx.new_id   = pMsg->newId ;
    
    prev = listMsg.prev ;
    next = prev->next   ;    
    
    prev->next = pMsg ;
    next->prev = pMsg ;
    pMsg->prev = prev ;
    pMsg->next = next ;
    
    return pMsg ;
}

/*
 * disposeReq - dispose message record
 */

static  void    disposeReq(MSGPTR pMsg)
{
    MSGPTR  p ;
    
    if (listMsg.prev == NULL || listMsg.next == NULL) {
        listMsg.prev = &listMsg ;
	listMsg.next = &listMsg ;
    }

    for (p = listMsg.next ; p != &listMsg ; p = p->next) {
        if (p == pMsg) {
	    break ;
	}
    }
    if (p == pMsg) {        /* safe to unlink it */
        pMsg->prev->next = pMsg->next ;
	pMsg->next->prev = pMsg->prev ;
    }
    idFree(pMsg->newId) ;
    free(pMsg) ;
}

/*
 * messageForward - forward the request
 */

static  void    errorOnRequest(MSGPTR pMsg, u_char *msg, int len, size_t err)
{
    u_short     errmsg[6] ;
    u_short     flags     ;
    u_short     *ps       ;
    
    TRACE("errorOnRequest %d\n", err) ;
    
    ps = (u_short *) msg ;
    flags = ntohs(ps[1]) ;
    flags = ((flags & 0x7fff) | 0x8000) ;           /* QR to response   */
    flags = ((flags & 0xfff8) | (err & 0x0007)) ;   /* set RCODE        */
    
    memset(errmsg, 0, sizeof(errmsg)) ;
    errmsg[0] = htons(pMsg->orgId) ;
    errmsg[1] = htons(flags)       ;
    
    server_response(&pMsg->from, pMsg->proto, (u_char *) errmsg, sizeof(errmsg)) ;
}

static  void    messageForward(MSGPTR pMsg, u_char *msg, int len)
{
    u_short *p ;
    u_char  buff[1024] ;
    u_char  *bbase ;
    size_t  bleng  ;
    size_t  cleng = 0 ;     /* avoid un-expected length on xlate error  */
    size_t  cstat = 0 ;     /* avoid un-expected status on xlate error  */
    
    TRACE("messageForward - %04x -> %04x\n", pMsg->orgId, pMsg->newId) ;
    
    /*
     * prepare conversion buffer
     */

    if (len < sizeof(buff) / 2) {
        bbase = buff ;
	bleng = sizeof(buff) ;
    } else {
        bbase = malloc(len * 2) ;
	bleng = len * 2 ;
    }
    if (bbase == NULL) {
        WARN("messageForward - cannot prepare conversion buffer\n") ;
	return ;
    }
    
    /*
     * translate message (domain names)
     */

    TRACE("messageForward - translate request\n") ;
    
    cstat = translate_request(&pMsg->trctx, msg, len, bbase, bleng, &cleng) ;
    
    TRACE("messageForward - translated status %d length %d\n", cstat, cleng) ;

    if (cstat != 0) {       /* error on conversion */
        WARN("messageForward - translation error %d\n", cstat) ;
        errorOnRequest(pMsg, msg, len, cstat) ;
	return ;
    }
    if (pMsg->proto == SOCK_DGRAM && cleng > 512) {
        WARN("messageForward - translation overflow %d\n", cleng) ;
	errorOnRequest(pMsg, msg, len, 2) ;
	return ;
    }
    
    /*
     * forward the request
     */
     
    p = (u_short *) bbase ;
    p[0] = htons(pMsg->newId) ;
    
    server_forward(NULL, pMsg->proto, bbase, cleng) ;
    
    /*
     * cleanup buffer
     */

    if (bbase != buff) {
        free(bbase) ;
    }
}

/*
 * messageResponse - response to originating client
 */

static  void    errorOnResponse(MSGPTR pMsg, u_char *msg, int len, size_t err)
{
    u_short     errmsg[6] ;
    u_short     flags     ;
    u_short     *ps       ;
    
    TRACE("errorOnResponse %d\n", err) ;
    
    ps = (u_short *) msg ;
    flags = ntohs(ps[1]) ;
    flags = ((flags & 0x7fff) | 0x8000) ;           /* QR to response   */
    flags = ((flags & 0xfff8) | (err & 0x0007)) ;   /* set RCODE        */
    
    memset(errmsg, 0, sizeof(errmsg)) ;
    errmsg[0] = htons(pMsg->orgId) ;
    errmsg[1] = htons(flags)       ;
    
    server_response(&pMsg->from, pMsg->proto, (u_char *) errmsg, sizeof(errmsg)) ;
}

static  void    messageResponse(MSGPTR pMsg, u_char *msg, int len)
{
    u_short *p ;
    u_char  buff[1024] ;
    u_char  *bbase ;
    size_t  bleng  ;
    size_t  cleng  ;
    size_t  cstat  ;
    
    TRACE("messageResponse - %04x <- %04x\n", pMsg->orgId, pMsg->newId) ;

    /*
     * prepare conversion buffer
     */

    if (len < sizeof(buff) / 2) {
        bbase = buff ;
	bleng = sizeof(buff) ;
    } else {
        bbase = malloc(len * 2) ;
	bleng = len * 2 ;
    }
    if (bbase == NULL) {
        WARN("messageResponse - cannot prepare conversion buffer\n") ;
	return ;
    }
    
    /*
     * translate message (domain names)
     */

    TRACE("messageResponse - translate response\n") ;

    cstat = translate_reply(&pMsg->trctx, msg, len, bbase, bleng, &cleng) ;
    
    TRACE("messageResponse - translated status %d length %d\n", cstat, cleng) ;

    if (cstat != 0) {       /* error on conversion */
        WARN("messageResponse - translation error %d\n", cstat) ;
        errorOnResponse(pMsg, msg, len, cstat) ;
	return ;
    }
    if (pMsg->proto == SOCK_DGRAM && cleng > 512) {
        WARN("messageResponse - translation overflow %d\n", cleng) ;
        errorOnResponse(pMsg, msg, len, 2) ;
	return ;
    }
    
    /*
     * reply back to requester
     */
     
    p = (u_short *) bbase ;
    p[0] = htons(pMsg->orgId) ;
    
    server_response(&pMsg->from, pMsg->proto, bbase, cleng) ;

    /*
     * cleanup buffer
     */

    if (bbase != buff) {
        free(bbase) ;
    }
}

/*
 * notify_message - callback from server loop
 */

void    notify_message(struct sockaddr *from, int proto, u_char *msg, int len)
{
    u_short     *p = (u_short *) msg ;
    u_short     msgid, flags ;
    MSGPTR      pMsg ;
#ifdef  DEBUG
    char    logbuf[256] ;
#endif
    
    msgid = ntohs(p[0]) ;
    flags = ntohs(p[1]) ;
    
#ifdef DEBUG
    if ((flags & 0x8000) == 0) {
        sprintf(logbuf, "Request  %04x (%04x) from %s, %d bytes", 
                            msgid, flags, addrFmt(from, proto), len) ;
    } else {
        sprintf(logbuf, "Response %04x (%04x) from %s %d bytes", 
	                    msgid, flags, addrFmt(from, proto), len) ;
    }
    TRACE("%s\n", logbuf) ;

    strcpy(logbuf, "    ") ;

    switch ((flags & 0x7800) >> 11) {
        case 0  : strcat(logbuf, "QUERY  ") ; break ;
	case 1  : strcat(logbuf, "IQUERY ") ; break ;
	case 2  : strcat(logbuf, "STATUS ") ; break ;
	default : strcat(logbuf, "UNKNOWN") ; break ;
    }
    if ((flags & 0x0400) != 0) {
        strcat(logbuf, ",AA") ;
    }
    if ((flags & 0x0200) != 0) {
        strcat(logbuf, ",TC") ;
    }
    if ((flags & 0x0100) != 0) {
        strcat(logbuf, ",RD") ;
    }
    if ((flags & 0x0080) != 0) {
        strcat(logbuf, ",RA") ;
    }
    switch (flags & 0x00f) {
        case 0  : strcat(logbuf, ",No Error       ") ; break ;
	case 1  : strcat(logbuf, ",Format Error   ") ; break ;
	case 2  : strcat(logbuf, ",Server Failure ") ; break ;
	case 3  : strcat(logbuf, ",Name Error     ") ; break ;
	case 4  : strcat(logbuf, ",Not Implemented") ; break ;
	case 5  : strcat(logbuf, ",Refused        ") ; break ;
	default : strcat(logbuf, ",Unknown Error  ") ; break ;
    }
    TRACE("%s\n", logbuf) ;
#endif

    if ((flags & 0x8000) == 0) {        /* request from client  */

        if ((pMsg = searchReq(msgid, proto, from)) == NULL) {
	    pMsg = createReq(msgid, proto, from) ;
	}
	if (pMsg == NULL) {
	    WARN("notify_message - cannot create message record\n") ;
	    return ;
	}
	messageForward(pMsg, msg, len) ;
	
    } else {                            /* response from server */

        if ((pMsg = searchOrg(msgid, proto)) == NULL) {
	    WARN("notify_message - no corresponding request\n") ;
	    return ;
	}
	messageResponse(pMsg, msg, len) ;
	disposeReq(pMsg);
    }
}

/*
 * notify_timer - timer callback
 */

static  time_t      timeLastCheck = 0 ;
static  time_t      timeInterval = 60 ;
static  time_t      timeTimeout = (60 * 10) ;

void    notify_timer(void)
{
    time_t  t = time(NULL) ;
    MSGPTR  p, np ;
#ifdef DEBUG
    int ndiscarded = 0;
#endif
    
    if (listMsg.prev == NULL || listMsg.next == NULL) {
        listMsg.prev = &listMsg ;
	listMsg.next = &listMsg ;
    }

    if ((t - timeLastCheck) < timeInterval) {
        return ;
    }
    for (p = listMsg.next ; p != &listMsg ; p = np) {
        np = p->next ;
	if ((t - p->last) > timeTimeout) {
            disposeReq(p) ;
#ifdef DEBUG
	    ndiscarded++;
#endif
	}
    }
#ifdef DEBUG
    TRACE("notify_timer: %d discarded\n", ndiscarded);
#endif
    timeLastCheck = t;
}
