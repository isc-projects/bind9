/*
 * server.c - mDNS Proxy, proxy server core
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
static char *rcsid = "$Id: server.c,v 1.1.2.1 2002/02/08 12:15:00 marka Exp $";
#endif

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef  HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef  WIN32
#include <windows.h>
#include <winsock.h>
#else   /* for normal systems */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <netinet/in.h>
#include <errno.h>
#endif

#include "mdnsproxy.h"

#ifdef  WIN32
#define close(s)    closesocket(s)
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

#ifndef max
#define max(x, y)   ((x) > (y) ? (x) : (y))
#endif

/*
 * Status of receiving data or accept a TCP connection.
 */
#define SUCCESS  0         /* succeeded        */ 
#define FAILURE  1         /* failed           */
#define DENIED   2         /* denied           */

/*
 * send buffer for TCP
 *      hold sending data when sending socket blocked
 */

typedef struct _SNDBUF {
    struct _SNDBUF      *prev ;
    struct _SNDBUF      *next ;
    int                 leng  ;     /* data length in the buffer    */
    int                 sent  ;     /* data have been sent          */
    int                 size  ;     /* size of this bufefr          */
    u_char              buff[1] ;   /* 'size' array follows         */
} SNDREC, *SNDPTR ;

/*
 * recv buffer for TCP
 *      hold incomplete message
 */

typedef struct _RCVBUF {
    int     stat  ;         /* what data receiving now      */
    int     leng  ;         /* length of the message        */
    int     recv  ;         /* message have been received   */
    int     size  ;         /* size of this buffer          */
    u_char  *buff ;         /* points 'size' array of char  */
} RCVREC, *RCVPTR ;

#define RCV_STAT_LEN1   0   /* waiting 1st byte of length   */
#define RCV_STAT_LEN2   1   /* waiting 2nd byte of length   */
#define RCV_STAT_DATA   2   /* waiting message data         */

/*
 * transport control block
 *      is used to handle pending recv/send data of the socket
 */

typedef struct _NETREC {
    struct _NETREC      *prev ;
    struct _NETREC      *next ;
    int                 sock  ;     /* socket to do network I/O */
    int                 proto ;     /* TCP or UDP               */
    int                 type  ;     /* see below                */
    struct sockaddr     peer  ;     /* peer of this transoport  */
    SNDREC              send  ;     /* pending send data (TPC)  */
    RCVREC              recv  ;     /* pending recv message     */
} NETREC, *NETPTR ;

#define NET_LISTEN  1       /* is proxy's listening socket  */
#define NET_CLIENT  2       /* is connection from client    */
#define NET_SERVER  3       /* is transport to server       */

static  NETREC  listNet = { 0 } ;   /* list of transports   */

/*
 * allocate/dispose buffer for SND/RCV buffer managements
 *      simply mapped to malloc/free, but may be
 *      re-maped to spceific function if speed required
 */

#define xalloc(x)   malloc((x))
#define xfree(p)    free((p))

/*
 * Whether to log denied access from client.
 */
static int	logOnDenied = 0;

/*
 * transientError - utility for handling "soft" errors
 */

static BOOL	transientError(int eno)
{
    if (
#ifdef EAGAIN
	eno == EAGAIN ||
#endif
#ifdef EWOULDBLOCK
	eno == EWOULDBLOCK ||
#endif
#ifdef EINTR
	eno == EINTR ||
#endif
	eno == 0)
	return TRUE ;
    else
	return FALSE ;
}

/*
 * addrEq, addrFmt - utilities for handling address
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
 * netCreate, netDispose - create/dispose transport control block
 */
 
#define SZRCVBUF    1024

static  NETPTR  netCreate(int sock, struct sockaddr *peer, int proto, int type)
{
    NETPTR  pNet, prev, next ;
    u_char  *pBuf ;
    
    if (listNet.prev == NULL || listNet.next == NULL) {
        WARN("netCreate - transport list is not initialized\n") ;
	listNet.prev = &listNet ;
	listNet.next = &listNet ;
    }
    
    pNet = (NETPTR)   xalloc(sizeof(NETREC)) ;
    pBuf = (u_char *) xalloc(SZRCVBUF) ;
    
    if (pNet == NULL || pBuf == NULL) {
        WARN("netCreate - cannot allocate buffer\n") ;
	if (pNet != NULL) xfree(pNet) ;
	if (pBuf != NULL) xfree(pBuf) ;
	return NULL ;
    }
    memset(pNet, 0, sizeof(NETREC)) ;

    pNet->sock  = sock  ;
    pNet->proto = proto ;
    pNet->type  = type  ;
    
    if (peer != NULL) {
        memcpy(&pNet->peer, peer, sizeof(struct sockaddr)) ;
    }

    pNet->send.prev = &pNet->send   ;
    pNet->send.next = &pNet->send   ;
    pNet->recv.stat = RCV_STAT_LEN1 ;
    pNet->recv.leng = 0             ;
    pNet->recv.recv = 0             ;
    pNet->recv.size = SZRCVBUF      ;
    pNet->recv.buff = pBuf         ;
    
    prev = listNet.prev ;
    next = prev->next   ;

    prev->next = pNet ;
    next->prev = pNet ;
    pNet->prev = prev ;
    pNet->next = next ;

    return pNet ;
}

static  void    netDispose(NETPTR pNet)
{
    NETPTR  p    ;
    SNDPTR  pSnd ;
    
    if (listNet.prev == NULL || listNet.next == NULL) {
        WARN("netDispose - transport list is not initialized\n") ;
	listNet.prev = &listNet ;
	listNet.next = &listNet ;
    }

    /*
     * unlink from transport list
     */
     
    for (p = listNet.next ; p != &listNet ; p = p->next) {
        if (p == pNet) {
	    break ;
	}
    }
    if (p == pNet) {        /* safe to unlink it */
        pNet->prev->next = pNet->next ;
	pNet->next->prev = pNet->prev ;
    }

    /*
     * dispose control block resources
     */
     
    if (pNet->send.prev == NULL || pNet->send.next == NULL) {
        WARN("netDispose - un-initialized SNDREC\n") ;
        pNet->send.prev = &pNet->send ;
        pNet->send.next = &pNet->send ;
    }
    while ((pSnd = pNet->send.next) != &pNet->send) {
	pSnd->prev->next = pSnd->next ;
	pSnd->next->prev = pSnd->prev ;
	xfree(pSnd) ;
    }
    if (pNet->recv.buff != NULL) {
        xfree(pNet->recv.buff) ;
    }
    close(pNet->sock) ;
    xfree(pNet) ;
}

/*
 * netExpand - expand receive buffer
 */

static  BOOL    netExpand(NETPTR p)
{
    int     len ;
    u_char  *np ;
    
    if (p->recv.size > p->recv.leng) {
        return TRUE ;
    }
    
    len = 1024 * ((p->recv.leng + 1023) / 1024) ;
    
    TRACE("netExpand %d -> %d\n", p->recv.size, len) ;

    if ((np = xalloc(len)) == NULL) {
        WARN("netExpand - cannot allocate memory\n") ;
        return FALSE ;
    }
    if (p->recv.recv > 0) {
        memcpy(np, p->recv.buff, p->recv.recv) ;
    }
    xfree(p->recv.buff) ;
    p->recv.buff = np   ;
    p->recv.size = len  ;
    
    return TRUE ;
}

/*
 * tcpSend, tcpQueue, tcpFlush - send message over stream socket
 *
 *      tcpSend  - send message over TCP socket
 *      tcpQueue - en-queue message if stream blocked
 *      tcpFlush - flush pending messages
 */
 
static  int     tcpSend(int sock, u_char *msg, int len)
{
    int     n, cnt = 0 ;
    
    while (len > 0) {
        if ((n = send(sock, msg, len, 0)) > 0) {
	    msg += n ;
	    len -= n ;
	    cnt += n ;
	    continue ;
	}
	if (!transientError(errno)) {
	    WARN("tcpSend - send error %d\n", errno) ;
	    return -1 ;
	}
	break ;
    }
    return cnt ;
}

static  BOOL    tcpQueue(NETPTR p, u_char *msg, int len)
{
    SNDPTR  sp, prev, next ;

    if ((sp = (SNDPTR) xalloc(sizeof(SNDREC) + len)) == NULL) {
        WARN("tcpQueue - cannot allocate buffer\n") ;
	return FALSE ;
    }

    sp->sent = 0   ;
    sp->leng = len ;
    sp->size = len ;
    memcpy(sp->buff, msg, len) ;
    
    prev = p->send.prev ;
    next = prev->next   ;
    prev->next = sp ;
    next->prev = sp ;
    sp->next = next ;
    sp->prev = prev ;

    return TRUE ;
}

static  BOOL    tcpFlush(NETPTR p)
{
    SNDPTR  sp ;
    int     n, len ;
    
    if (p->proto != SOCK_STREAM) {
        WARN("tcpFlush - flushing on non-stream socket\n") ;
	return FALSE ;
    }
    if (p->send.prev == NULL || p->send.prev == NULL) {
        WARN("tcpFlush - send buffer is not initialized\n") ;
        p->send.prev = &p->send ;
        p->send.next = &p->send ;
    }

    while ((sp = p->send.next) != &p->send) {

        /*
	 * try to send data
	 */

        if ((len = sp->leng - sp->sent) > 0) {
	    if ((n = tcpSend(p->sock, &sp->buff[sp->sent], len)) < 0) {
	        WARN("tcpFlush - send error %d\n", errno) ;
		return FALSE ;
	    }
            if (n == 0) {
	        TRACE("tcpFlush - blocked\n") ;
	        return TRUE ;
	    }
	    sp->sent += n ;
	}
	
        /*
	 * if no more data in send buffer, unlink and free
	 */

        if ((len = sp->leng - sp->sent) <= 0) {
	    sp->prev->next = sp->next ;
	    sp->next->prev = sp->prev ;
	    xfree(sp) ;
        }
    }
    return TRUE ;
}

/*
 * Server Control Variables
 */

static  BOOL    servActive = FALSE ;

static  NETPTR  listenTcp = NULL ;  /* proxy's listening socket */
static  NETPTR  listenUdp = NULL ;  /* proxy's listening socket */

static  struct sockaddr serverDefaultAddr  = { 0 } ;
static  BOOL            serverRestrictPort = FALSE ;

/*
 * server_done - finalize server
 *
 *  is also used when 'server_init' failed in initialization sequence
 *
 *  using module level utilities
 *      
 *      netDispose      dispose transport control block
 */

void    server_done(void)
{
    NETPTR  p ;
    
    if (listNet.prev == NULL || listNet.next == NULL) {
        listNet.prev = &listNet ;
	listNet.next = &listNet ;
    }
    while ((p = listNet.next) != &listNet) {
        netDispose(p) ;
    }
}

/*
 * server_init - initialize server
 *
 *  using sub-functions
 *
 *      initTcp     create socket to listening TCP connection
 *      initUdp     create socket to listening UDP message
 *
 *  and also using module level utilities
 *      
 *      netCreate       create transport control block
 *
 *  also use 'server_done' to cleanup resources
 */

static  NETPTR  initTcp(void)
{
    NETPTR  p ;
    int     sock ;
    int     one  = 1 ;
    struct  sockaddr addr ;
    
    if (config_query_listen(&addr) != TRUE) {
        WARN("initTcp - no listen address\n") ;
	return NULL ;
    }

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        WARN("initTcp - cannot create TCP socket\n") ;
	return NULL ;
    }
    
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ;
    
    if (bind(sock, &addr, sizeof(addr)) < 0) {
        WARN("initTcp - cannot bind TCP socket\n") ;
	close(sock) ;
	return NULL ;
    }
    if (listen(sock, 5) < 0) {
        WARN("initTcp - cannot listen on TCP socket\n") ;
	close(sock) ;
	return NULL ;
    }
    if ((p = netCreate(sock, &addr, SOCK_STREAM, NET_LISTEN)) == NULL) {
        WARN("initTcp - cannot create control block\n") ;
	close(sock) ;
	return NULL ;
    }
    return p ;
}

static  NETPTR  initUdp(void)
{
    NETPTR  p ;
    int     sock ;
    int     one  = 1 ;
    struct  sockaddr addr ;
    
    if (config_query_listen(&addr) != TRUE) {
        WARN("initUdp - no listen address\n") ;
	return NULL ;
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        WARN("initUdp - cannot create UDP socket\n") ;
	return NULL ;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ;

    if (bind(sock, &addr, sizeof(addr)) < 0) {
        WARN("initUdp - cannot bind UDP socket\n") ;
	close(sock) ;
	return NULL ;
    }
    if ((p = netCreate(sock, &addr, SOCK_DGRAM, NET_LISTEN)) == NULL) {
        WARN("initUdp - cannot create control block\n") ;
	close(sock) ;
	return NULL ;
    }
    return p ;
}

/*
 * server_init - initialize proxy server
 */
 
BOOL    server_init(int ac, char *av[])
{
    /*
     * initialize transport list
     */
     
    listNet.prev = &listNet ;
    listNet.next = &listNet ;

    /*
     * setup transports
     */
     
    listenTcp = initTcp() ;
    listenUdp = initUdp() ;

    if (listenTcp == NULL || listenUdp == NULL) {
        WARN("server_init - cannot create proxy's listening port\n") ;
	server_done() ;
	return FALSE ;
    }
    
    if (config_query_forward(&serverDefaultAddr) != TRUE) {
        WARN("server_init - no DNS server address\n") ;
	server_done() ;
	return FALSE ;
    }
    if (config_query_restrict(&serverRestrictPort) != TRUE) {
        WARN("server_init - cannot query 'serverRestrictPort' flag\n") ;
	server_done() ;
	return FALSE ;
    }
    if (config_query_log_on_denied(&logOnDenied) != TRUE) {
        WARN("syntax error at log-on-denied line\n") ;
	server_done() ;
	return FALSE ;
    }
    
    /*
     * initialize translator
     */
     
    if (translate_initialize() != TRUE) {
	WARN("server_init - translation configuration failed\n") ;
	server_done() ;
	return FALSE ;
    }

    /*
     * initialize ACL.
     */
     
    if (acl_initialize() != TRUE) {
	WARN("server_init - access list configuration failed\n") ;
	server_done() ;
	return FALSE ;
    }

    /*
     * now server is ready, turn on active flags now
     */

    servActive = TRUE ;
    
    return TRUE ;
}

/*
 * server_stop - request to stop server
 *
 *      simply turn off 'servActive' control flag.
 *      then 'server_loop' terminate 
 */

void    server_stop(void)
{
    servActive = FALSE ;
}

/*
 * server_loop - proxy server's message loop
 *
 *  using sub-funcstions
 *
 *      setRdFds        listup sockets to check read  ready
 *      setWtFds        listup sockets to check write ready
 *      sockAccept      accept connection from client
 *      sockRecvTcp     receive message over TCP
 *      sockRecvUdp     receive message over UDP
 *      sockDispatch    dispatch on ready sockets
 *      sockValidate    validate sockets
 *      timerDispatch   entry of timer processing
 *
 *  and also using module level utilities
 *
 *      netCreate       create  transport control block
 *      netDispose      dispose transport control block
 *      tcpFlush        send pending message
 *      addrFmt         formatting address (& proto)
 */

/*
 * setRdFds, setWtFds - listup socket to check if ready
 */
 
static  int     setRdFds(fd_set *rfds)
{
    int     maxfd = 0 ;
    NETPTR  p ;
    
    /*
     * listup sockets to check read ready
     */
    
    if (listNet.prev == NULL || listNet.next == NULL) {
        WARN("setRdFds - listNet is not initialized\n") ;
	listNet.prev = &listNet ;
	listNet.next = &listNet ;
    }
    for (p = listNet.next ; p != &listNet ; p = p->next) {
        FD_SET(p->sock, rfds) ;
	maxfd = max(maxfd, p->sock) ;
    }
    return maxfd ;
}

static  int     setWtFds(fd_set *wfds)
{
    int     maxfd = 0 ;
    NETPTR  p ;
    
    /*
     * listup sockets to check read ready
     */
    
    if (listNet.prev == NULL || listNet.next == NULL) {
        WARN("setRdFds - listNet is not initialized\n") ;
	listNet.prev = &listNet ;
	listNet.next = &listNet ;
    }
    for (p = listNet.next ; p != &listNet ; p = p->next) {
        if (p->send.prev == NULL || p->send.next == NULL) {
	    WARN("setWtFds - send buffer is not initialized\n") ;
	    p->send.prev = &p->send ;
	    p->send.next = &p->send ;
	}
        if (p->send.next != &p->send) {
            FD_SET(p->sock, wfds) ;
	    maxfd = max(maxfd, p->sock) ;
	}
    }
    return maxfd ;
}

/*
 * sockAccept - accept connection from client
 */
 
static  int    sockAccept(NETPTR p)
{
    NETPTR  np ;
    int     ns, addrlen ;
    struct sockaddr     addr ;
    struct sockaddr     peer ;
    
    memset(&addr, 0, sizeof(addr)) ;
    memset(&peer, 0, sizeof(peer)) ;
    
    addrlen = sizeof(addr) ;

    if ((ns = accept(p->sock, &addr, &addrlen)) < 0) {
        WARN("sockAccept - cannot accept connection %d\n", errno) ;
	return FAILURE ;
    }
    
    addrlen = sizeof(peer) ;
    getpeername(ns, &peer, &addrlen) ;

    if (!acl_test(&peer)) {
	if (logOnDenied) {
	    WARN("sockAccept - deny access from %s\n",
		addrFmt(&peer, SOCK_STREAM));
	}
	shutdown(ns, 2) ;
	close(ns) ;
	return DENIED ;
    }
    
    if ((np = netCreate(ns, &peer, SOCK_STREAM, NET_CLIENT)) == NULL) {
        WARN("sockAccept - cannot create control block\n") ;
	close(ns) ;
	return FAILURE ;
    }

    TRACE("sockAccept - accept connection from %s on socket %d\n", addrFmt(&peer, SOCK_STREAM), ns) ;

    return SUCCESS ;
}

/*
 * sockRecvTcp, sockRecvUdp - receive message
 *
 *  when message complete, call 'notify_message' to
 *  notify message arrival.
 */
 
static  int    sockRecvTcp(NETPTR p)
{
    int     n, len ;
    u_char  buff[2] ;
    u_char  *bp ;
    
    /*
     * validate transport
     */

    if (p == NULL || p->proto != SOCK_STREAM) {
        WARN("sockRecvTcp - bad parameter\n") ;
	return FAILURE ;
    }
    if (p->recv.buff == NULL || p->recv.size == 0) {
        WARN("sockRecvTcp - no receiver buffer\n") ;
	return FAILURE ;
    }

    /*
     * when receiving message over TCP, constuct state machine with
     * RCVBUF's status.
     */

    if (p->recv.stat == RCV_STAT_LEN1) {
        if ((n = recv(p->sock, buff, 2, 0)) <= 0) {
	    if (errno == EWOULDBLOCK) {
	        return SUCCESS ;
	    }
	    WARN("sockRecvTcp - recv error %d on socket %d, STAT_LEN1\n", errno, p->sock) ;
	    return FAILURE ;
	}
	if (n == 1) {
	    p->recv.leng = ((int) (buff[0] & 0xff)) * 256 ;
	    p->recv.stat = RCV_STAT_LEN2 ;
	    return SUCCESS  ;   /* blocked, try later */
	}
	p->recv.leng = ((int) (buff[0] & 0xff)) * 256 + ((int) (buff[1] & 0xff)) ;
	p->recv.stat = RCV_STAT_DATA ;
	/* then fall through */
    }

    if (p->recv.stat == RCV_STAT_LEN2) {
        if ((n = recv(p->sock, buff, 1, 0)) <= 0) {
	    if (errno == EWOULDBLOCK) {
	        return SUCCESS ;
	    }
	    WARN("sockRecvTcp - recv error %d on socket %d, STAT_LEN2\n", errno, p->sock) ;
	    return FAILURE ;
	}
	p->recv.leng += ((int) (buff[0] & 0xff)) ;
	p->recv.stat = RCV_STAT_DATA ;
	/* then fall through */
    }

    if (p->recv.stat == RCV_STAT_DATA) {
        if (p->recv.size < p->recv.leng) {
            if (netExpand(p) != TRUE) {
	        WARN("sockRecvTcp - cannot expand recv buffer\n") ;
		return FAILURE ;
	    }
        }

	bp  = &p->recv.buff[p->recv.recv] ;
	len = p->recv.leng - p->recv.recv ;

	if ((n = recv(p->sock, bp, len, 0)) <= 0) {
	    if (errno == EWOULDBLOCK) {
	        return SUCCESS ;
	    }
	    WARN("sockRecvTcp - recv error %d on socket %d, "
		"STAT_DATA %d (%d/%d)\n", 
		errno, p->sock, len, p->recv.recv, p->recv.leng) ;
	    return FAILURE ;
	}
	if ((p->recv.recv += n) < p->recv.leng) {
	    return SUCCESS ;       /* still in-complete */
	}
	
	/*
	 * message complete, notify it
	 */
	 
	notify_message(&p->peer, SOCK_STREAM, p->recv.buff, p->recv.leng) ;

        /*
	 * reset recv buffer
	 */
	 
	p->recv.stat = RCV_STAT_LEN1 ;
	p->recv.leng = 0 ;
	p->recv.recv = 0 ;

	return SUCCESS ;
    }
    WARN("sockRecvTcp - something wrong\n") ;
    return FAILURE ;
}

static  int    sockRecvUdp(NETPTR p)
{
    int             n, fromlen ;
    struct sockaddr fromaddr   ;
    
    /*
     * validate transport
     */

    if (p == NULL || p->proto != SOCK_DGRAM) {
        WARN("sockRecvUdp - bad parameter\n") ;
	return FAILURE ;
    }
    if (p->recv.buff == NULL || p->recv.size == 0) {
        WARN("sockRecvUdp - no receiver buffer\n") ;
	return FAILURE ;
    }

    /*
     * receive over UDP
     */
     
    fromlen = sizeof(fromaddr) ;
    
    n = recvfrom(p->sock, p->recv.buff, p->recv.size, 0, &fromaddr, &fromlen) ;

    if (n == 0) {
	WARN("sockRecvUdp - no data\n") ;
	return SUCCESS ;
    } else if (n < 0) {
	if (transientError(errno))
	    return SUCCESS ;
	switch (errno) {
#ifdef ECONNREFUSED
	case ECONNREFUSED:
#endif
#ifdef ENETUNREACH
	case ENETUNREACH:
#endif
#ifdef EHOSTUNREACH
	case EHOSTUNREACH:
#endif
	    WARN("sockRecvUdp - recv error %d (ignored)\n", errno) ;
	    return SUCCESS ;
	default:
	    WARN("sockRecvUdp - recv error %d\n", errno) ;
	    return FAILURE ;
	}
    }

    if (!addrEq(&fromaddr, &serverDefaultAddr) && !acl_test(&fromaddr)) {
	if (logOnDenied) {
	    WARN("sockRecvUdp - deny access from %s\n", 
		addrFmt(&fromaddr, SOCK_DGRAM));
	}
	return DENIED ;
    }
                
    /*
     * notify message arrival
     */

    notify_message(&fromaddr, SOCK_DGRAM, p->recv.buff, n) ;

    return SUCCESS ;
}

/*
 * sockDispatch - process on ready sockets
 */
 
static  void    sockDispatch(int nfds, fd_set *rfds, fd_set *wfds)
{
    NETPTR  p, np ;
    int     stat ;
    
    /*
     * process on ready sockets
     */
     
    if (listNet.prev == NULL || listNet.next == NULL) {
        WARN("sockDispatch - listNet is not initialized\n") ;
        listNet.prev = &listNet ;
        listNet.next = &listNet ;
    }
    for (p = listNet.next ; p != &listNet ; p = np) {

        np = p->next ;
	stat = SUCCESS ;  /* assume no problem */
        
        /*
	 * if receiving socket ready, then
	 *
	 *      LISTEN TCP      accept connection
	 *      LISTEN UDP      receive message
	 *      CLIENT          receive message
	 *      SERVER          receive message
	 */
	 
	if (FD_ISSET(p->sock, rfds)) {
	    if (p->type != NET_LISTEN) {
	        if (p->proto == SOCK_STREAM) {
		    stat = sockRecvTcp(p) ;
		} else {
		    stat = sockRecvUdp(p) ;
		}
            } else if (p->proto == SOCK_DGRAM) {
	        stat = sockRecvUdp(p) ;
	    } else {        /* connect request on listening TCP socket */
	        stat = sockAccept(p) ;
	    }
	}

        /*
	 * if send socket ready, then send pending message
	 *
	 *      don't check transport type, protocol, but
	 *      this happens only for TCP socket to CLIENT/SERVER
	 */
	 
	if (stat == SUCCESS && FD_ISSET(p->sock, wfds)) {
	    tcpFlush(p) ;
	}
	
	/*
	 * if something wrong on socket, dispose it
	 */

        if (stat == FAILURE) {
            if (p->type == NET_LISTEN || p->proto == SOCK_DGRAM) {
    	        WARN("sockDispatch - error on listening socket\n") ;
	        server_stop() ;
	    } else {
	        WARN("sockDispatch - error on socket %d\n", p->sock) ;
	    }
	    netDispose(p) ;
        }	
    }
}

/*
 * sockValidate - validate socket when select error
 */
 
static  void    sockValidate(int nfds, fd_set *rfds, fd_set *wfds)
{
    NETPTR  p, np ;
    fd_set  fds ;
    struct timeval  tm ;

    TRACE("sockValidate\n") ;

    FD_ZERO(&fds) ;
    tm.tv_sec  = 0 ;
    tm.tv_usec = 0 ;
    
    if (listNet.prev == NULL || listNet.next == NULL) {
        WARN("sockValidate - listNet is not initialized\n") ;
        listNet.prev = &listNet ;
        listNet.next = &listNet ;
    }

    for (p = listNet.next ; p != &listNet ; p = np) {

        np = p->next ;
        
        /*
	 * check if socket is still available
	 */

        FD_SET(p->sock, &fds) ;

        if (!FD_ISSET(p->sock, rfds) && !FD_ISSET(p->sock, wfds)) {
	    FD_CLR(p->sock, &fds) ;
	    continue ;
	}
	if (select(p->sock + 1, &fds, NULL, NULL, &tm) >= 0) {
	    FD_CLR(p->sock, &fds) ;
	    continue ;
	}
        FD_CLR(p->sock, &fds) ;

        /*
	 * something wrong on socket
	 */
	 
        if (p->type == NET_LISTEN) {
	    WARN("sockValidate - closed listening socket\n") ;
	    server_stop() ;
	} else {
	    WARN("sockValidate - closed socket %d\n", p->sock) ;
	}
	netDispose(p) ;
    }
}

/*
 * timerDispatch - entry of timer processing
 */
 
static  time_t  timeLast = 0 ;      /* last time of timer process   */
static  time_t  timeWait = 10 ;     /* wait till next timer process */

static  void    timerDispatch(void)
{
    time_t  t = time(NULL) ;
    
    /*
     * do timer process every 'timeWait' interval
     */

    if ((t - timeLast) < timeWait) {
        return ;
    }

    /*
     * call timer processes here
     */
    
    notify_timer() ;
    
    /*
     * update timer
     */
     
    timeLast = t ;
}

/*
 * server_loop - proxy's main, select loop
 */
 
void    server_loop(void)
{
    struct timeval  tm ;
    fd_set  rfds, wfds ;
    int     maxrfd, maxwfd ;
    int     n, nfds ;

    while (servActive) {

        FD_ZERO(&rfds) ;
	FD_ZERO(&wfds) ;
	
	maxrfd = setRdFds(&rfds) ;
	maxwfd = setWtFds(&wfds) ;
	nfds = max(maxrfd, maxwfd) + 1 ;
	
	tm.tv_sec  = 10 ;
	tm.tv_usec = 0 ;
	
	if (maxwfd == 0) {
	    n = select(nfds, &rfds, NULL, NULL, &tm) ;
	} else {
	    n = select(nfds, &rfds, &wfds, NULL, &tm) ;
	}

	if (n > 0) {
	    sockDispatch(nfds, &rfds, &wfds) ;
	} else if (n < 0) {
	    if (!transientError(errno)) {
		sockValidate(nfds, &rfds, &wfds) ;
	    }
	}
        timerDispatch() ;
#ifdef  DEBUG
        fflush(stdout) ;
	fflush(stderr) ;
#endif
	log_turnover();
    }
}

/*
 * Server's entries for send message (forward or response)
 *
 *      server_forward      forward request to DNS server
 *      server_response     send back response to client
 *
 * using sub-functions,
 *
 *      openTcp      open TCP connection to the upstream server
 *      openUdp      open UDP transport  to the upstream server
 *      getServer    get transport to the upstream server
 *      getClient    get transport to responding client 
 *      sendTcp      send message via TCP
 *      sendUdp      send message via UDP
 *
 * and also using module level utilities,
 *      
 *      netCreate   create transport control block
 *      tcpSend     send message over TCP socket
 *      tcpQueue    enqueue if TCP blocked
 *      addrEq      check if addresses are same
 *      addrFmt     formatting address (& proto)
 */

/*
 * openTcp, openUdp - create TCP/UDP transport to DNS server
 */
 
static  NETPTR  openTcp(struct sockaddr *to)
{
    int     sock ;
    NETPTR  p    ;
    
    TRACE("openTcp - creating transport to %s\n", addrFmt(to, SOCK_STREAM)) ;
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        WARN("openTcp - cannote create socket %d\n", errno) ;
	return NULL ;
    }
    if (connect(sock, to, sizeof(struct sockaddr)) < 0) {
        WARN("openTcp - cannot connect to server %d\n", errno) ;
        close(sock) ;
	return NULL ;
    }
    if ((p = netCreate(sock, to, SOCK_STREAM, NET_SERVER)) == NULL) {
        WARN("openTcp - cannot create control block\n") ;
	close(sock) ;
	return NULL ;
    }
    return p ;
}

static  NETPTR  openUdp(struct sockaddr *to)
{
    int     sock ;
    NETPTR  p    ;
    struct sockaddr_in  saddr ;     /* source port */
    
    TRACE("openUdp - creating transport to %s\n", addrFmt(to, SOCK_DGRAM)) ;
    
    memset(&saddr, 0, sizeof(saddr)) ;
    saddr.sin_family = AF_INET                ;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY) ;
    saddr.sin_port = htons(0)                 ;
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        WARN("openUdp - cannote create socket %d\n", errno) ;
	return NULL ;
    }
    if (bind(sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
        WARN("openUdp - cannot bind source port\n") ;
	close(sock) ;
	return NULL ;
    }
    if (connect(sock, to, sizeof(struct sockaddr)) < 0) {
        WARN("openUdp - cannot connect to server\n") ;
	close(sock) ;
	return NULL ;
    }
    if ((p = netCreate(sock, to, SOCK_DGRAM, NET_SERVER)) == NULL) {
        WARN("openUdp - cannot create control block\n") ;
	close(sock) ;
	return NULL ;
    }
    return p ;
}

/*
 * getServer - search/create transport to the DNS server
 */
 
static  NETPTR  getServer(struct sockaddr *to, int proto)
{
    NETPTR  p ;

    /*
     * if proxy should use DNS port to communicate DNS server,
     * use proxy's listen port to forward request to the server
     */
    
    if (proto == SOCK_DGRAM && serverRestrictPort) {
        return listenUdp ;
    }
    
    /*
     * search transport to specified DNS server
     */

    if (listNet.prev == NULL || listNet.next == NULL) {
        WARN("getServer - listNet is not initialized\n") ;
	listNet.prev = &listNet ;
	listNet.next = &listNet ;
    }
    for (p = listNet.next ; p != &listNet ; p = p->next) {
        if (p->proto != proto || p->type != NET_SERVER) {
	    continue ;
	}
	if (addrEq(&p->peer, to)) {
	    return p ;
	}
    }
    
    /*
     * if not exist, create new one
     */

    if (proto == SOCK_STREAM) {
        p = openTcp(to) ;
    } else {
        p = openUdp(to) ;
    }
    return p ;
}

/*
 * getClient - search transport to the client
 */
 
static  NETPTR  getClient(struct sockaddr *to, int proto)
{
    NETPTR  p ;

    /*
     * for response using UDP, use proxy's UDP socket
     */

    if (proto == SOCK_DGRAM) {
        return listenUdp ;
    }

    /*
     * otherwise (TCP), use existing transport to the client
     */
     
    if (listNet.prev == NULL || listNet.next == NULL) {
        WARN("getClient - listNet is not initialized\n") ;
	listNet.prev = &listNet ;
	listNet.next = &listNet ;
    }
    for (p = listNet.next ; p != &listNet ; p = p->next) {
        if (p->proto != proto || p->type != NET_CLIENT) {
	    continue ;
	}
	if (addrEq(&p->peer, to)) {
	    return p ;
	}
    }
    return NULL ;
}

/*
 * sendTcp, sendUdp - send message over TCP/UDP
 */
 
static  void    sendTcp(NETPTR p, u_char *msg, int len)
{
    int     n ;
    u_char  buff[1024] ;
    u_char  *bp ;
    
    /*
     * insert 2 bytes message length field before the message
     */
     
    if (len < (1024 - 2)) {
        bp = buff ;
    } else {
        bp = malloc(len + 2) ;
    }
    if (bp == NULL) {
        WARN("sendTcp - cannot alocate send buffer\n") ;
	return ;
    }
    bp[0] = len / 256 ;
    bp[1] = len % 256 ;
    memcpy(&bp[2], msg, len) ;
    len += 2 ;
    
    /*
     * if there is pending data, enqueue sending message
     */

    if (p->send.prev == NULL || p->send.next == NULL) {
        WARN("sendTcp - send buffer is not initialized\n") ;
	p->send.prev = &p->send ;
	p->send.next = &p->send ;
    }
    if (p->send.next != &p->send) {
        tcpQueue(p, bp, len) ;
	if (bp != buff) free(bp) ;
	return ;
    }
    
    /*
     * then, try to send message
     */

    if ((n = tcpSend(p->sock, bp, len)) < 0) {
        WARN("sendTcp - cannot send message\n") ;
	if (bp != buff) free(bp) ;
	return ;
    }
    if (n != len) {
        tcpQueue(p, (bp + n), (len - n)) ;
    }
    if (bp != buff) free(bp) ;
}

static  void    sendUdp(NETPTR p, u_char *msg, int len, struct sockaddr *to)
{
    int     n ;
    
    if (p->type == NET_SERVER) {    /* target is binded */
        n = send(p->sock, msg, len, 0) ;
    } else {                        /* need to specify target */
        n = sendto(p->sock, msg, len, 0, to, sizeof(struct sockaddr)) ;
    }
    if (n < 0) {
	if (!transientError(errno)) {
	    WARN("sendUdp - cannot send message %d\n", errno) ;
	}
	return ;
    }
    if (n != len) {
        WARN("sendUdp - cannot send entire message %d/%d\n", n, len) ;
	return ;
    }
}

/*
 * server_forward - forward request to the DNS server
 */
 
void    server_forward(struct sockaddr *to, int proto, u_char *msg, int len)
{
    NETPTR  p ;
    
    if (to == NULL) {
        to = &serverDefaultAddr ;
    }
    if ((p = getServer(to, proto)) == NULL) {
        WARN("server_forward - no transport to server %s\n",
	    addrFmt(to, proto)) ;
	return ;
    }
    if (proto == SOCK_STREAM) {
        sendTcp(p, msg, len) ;
    } else {
        sendUdp(p, msg, len, to) ;
    }
}

/*
 * server_response - response to client
 */
 
void    server_response(struct sockaddr *to, int proto, u_char *msg, int len)
{
    NETPTR  p ;
    
    if ((p = getClient(to, proto)) == NULL) {
        WARN("server_response - no transport to client %s\n",
	    addrFmt(to, proto)) ;
        return ;
    }
    if (proto == SOCK_STREAM) {
        sendTcp(p, msg, len) ;
    } else {
        sendUdp(p, msg, len, to) ;
    }
}
