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

#ifndef DIG_H
#define DIG_H

#define SDIG_BUFFER_SIZE 2048
#include <isc/lang.h>
#include <isc/socket.h>
#include <isc/buffer.h>
#include <isc/bufferlist.h>
#include <isc/sockaddr.h>
#include <isc/boolean.h>
#include <isc/mem.h>
#include <isc/list.h>
#include <isc/print.h>

#define MXSERV 4
#define MXNAME 256
#define MXRD 32
#define BUFSIZE 512
#define COMMSIZE 65536
#define RESOLVCONF "/etc/resolv.conf"

ISC_LANG_BEGINDECLS

typedef struct dig_lookup dig_lookup_t;
typedef struct dig_query dig_query_t;
typedef struct dig_server dig_server_t;

struct dig_lookup {
	isc_boolean_t pending, /* Pending a successful answer */
		waiting_connect,
		doing_xfr,
		ns_search_only,
		use_my_server_list,
		identify;
	char textname[MXNAME]; /* Name we're going to be looking up */
	char rttext[MXRD]; /* rdata type text */
	char rctext[MXRD]; /* rdata class text */
	char namespace[BUFSIZE];
	isc_buffer_t namebuf;
	isc_buffer_t sendbuf;
	char sendspace[COMMSIZE];
	dns_name_t *name;
	isc_timer_t *timer;
	isc_interval_t interval;
	dns_message_t *sendmsg;
	ISC_LINK(dig_lookup_t) link;
	ISC_LIST(dig_query_t) q;
	ISC_LIST(dig_server_t) my_server_list;
	dig_query_t *xfr_q;
};

struct dig_query {
	dig_lookup_t *lookup;
	isc_boolean_t working,
		waiting_connect,
		first_pass,
		first_soa_rcvd;
	char *servname;
	isc_bufferlist_t sendlist,
		recvlist,
		lengthlist;
	isc_buffer_t recvbuf,
		lengthbuf,
		slbuf;
	char recvspace[COMMSIZE],
		lengthspace[4],
		slspace[4];
	isc_socket_t *sock;
	ISC_LINK(dig_query_t) link;
	isc_sockaddr_t sockaddr;
};

struct dig_server {
	char servername[MXNAME];
	ISC_LINK(dig_server_t) link;
};

/* Routines in dighost.c */
void
fatal(char *format, ...) ;
void
debug(char *format, ...) ;
inline void
check_result(isc_result_t result, char *msg);
isc_boolean_t
isclass(char *text) ;
isc_boolean_t
istype(char *text) ;
void
setup_lookup(dig_lookup_t *lookup);
void
do_lookup_udp (dig_lookup_t *lookup);
void
do_lookup_tcp (dig_lookup_t *lookup);

/* Routines needed in dig.c and host.c */
void
parse_args(isc_boolean_t is_batchfile, int argc, char **argv) ;
isc_result_t
printmessage(dig_query_t *query, dns_message_t *msg, isc_boolean_t headers) ;
void
check_next_lookup (dig_lookup_t *lookup);


ISC_LANG_ENDDECLS

#endif
