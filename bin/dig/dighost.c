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

#define TWIDDLE (random()%4+1)

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int h_errno;

#include <isc/types.h>
#include <isc/app.h>
#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/net.h>
#include <isc/netdb.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/time.h>
#include <isc/buffer.h>
#include <isc/list.h>
#include <isc/util.h>

#include <dns/types.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/result.h>

#include <dig/dig.h>

ISC_LIST(dig_lookup_t) lookup_list;
ISC_LIST(dig_server_t) server_list;

isc_boolean_t tcp_mode = ISC_FALSE, recurse = ISC_TRUE, have_ipv6 = ISC_FALSE,
	free_now = ISC_FALSE;
#ifdef TWIDDLE
isc_boolean_t twiddle = ISC_FALSE;
#endif
in_port_t port;
unsigned int timeout;
isc_mem_t *mctx = NULL;
isc_taskmgr_t *taskmgr = NULL;
isc_task_t *task = NULL;
isc_timermgr_t *timermgr = NULL;
isc_socketmgr_t *socketmgr = NULL;
dns_messageid_t id;
dns_name_t rootorg;
char *rootspace[BUFSIZE];
isc_buffer_t rootbuf;
int sendcount = 0;

extern isc_boolean_t short_form;

static void
free_lists(void);

static void
hex_dump(isc_buffer_t *b) {
	unsigned int len;
	isc_region_t r;

	isc_buffer_remainingregion(b, &r);

	printf("Printing a buffer with length %d\n", r.length);
	for (len = 0 ; len < r.length ; len++) {
		printf("%02x ", r.base[len]);
		if (len != 0 && len % 16 == 0)
			printf("\n");
	}
	if (len % 16 != 0)
		printf("\n");
}


void
fatal(char *format, ...) {
	va_list args;

	va_start(args, format);	
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	free_lists();
	isc_app_finish();
	if (mctx != NULL)
		isc_mem_destroy(&mctx);

	exit(1);
}

#ifdef DEBUG
void
debug(char *format, ...) {
	va_list args;

	va_start(args, format);	
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
}
#else
void
debug(char *format, ...) {
	va_list args;
	UNUSED(args);
	UNUSED(format);
}
#endif

inline void
check_result(isc_result_t result, char *msg) {
	if (result != ISC_R_SUCCESS)
		fatal("%s: %s", msg, isc_result_totext(result));
}

isc_boolean_t
isclass(char *text) {
	/* Tests if a field is a class, without needing isc libs
	   initialized.  This list will have to be manually kept in 
	   sync with what the libs support. */
	const char *classlist[] = {"in", "hs", "any"};
	const int numclasses = 3;
	int i;

	for (i = 0; i < numclasses; i++)
		if (strcasecmp(text, classlist[i]) == 0)
			return ISC_TRUE;

	return ISC_FALSE;
}

isc_boolean_t
istype(char *text) {
	/* Tests if a field is a type, without needing isc libs
	   initialized.  This list will have to be manually kept in 
	   sync with what the libs support. */
	const char *typelist[] = {"a", "ns", "md", "mf", "cname",
				  "soa", "mb", "mg", "mr", "null",
				  "wks", "ptr", "hinfo", "minfo",
				  "mx", "txt", "rp", "afsdb",
				  "x25", "isdn", "rt", "nsap",
				  "nsap_ptr", "sig", "key", "px",
				  "gpos", "aaaa", "loc", "nxt",
				  "srv", "naptr", "kx", "cert",
				  "a6", "dname", "opt", "unspec",
				  "tkey", "tsig", "axfr"};
	const int numtypes = 41;
	int i;

	for (i = 0; i < numtypes; i++) {
		if (strcasecmp(text, typelist[i]) == 0)
			return ISC_TRUE;
	}
	return ISC_FALSE;
}


#ifdef TWIDDLE
void
twiddlebuf(isc_buffer_t buf) {
	isc_region_t r;
	int len, pos, bit;
	unsigned char bitfield;
	int i, tw;

	hex_dump(&buf);
	tw=TWIDDLE;
	printf ("Twiddling %d bits: ",tw);
	for (i=0;i<tw;i++) {
		isc_buffer_usedregion (&buf, &r);
		len = r.length;
		pos=(int)random();
		pos = pos%len;
		bit = (int)random()%8;
		bitfield = 1 << bit;
		printf ("%d@%03x ",bit, pos);
		r.base[pos] ^= bitfield;
	}
	puts ("");
	hex_dump(&buf);
}
#endif

static void
setup_system(void) {
	char rcinput[MXNAME];
	FILE *fp;
	char *ptr;
	dig_server_t *srv;

	id = getpid() << 8;

	debug ("setup_system()");
	if (server_list.head == NULL) {
		fp = fopen (RESOLVCONF, "r");
		if (fp != NULL) {
			while (fgets(rcinput, MXNAME, fp) != 0) {
				ptr = strtok (rcinput, " \t");
				if (ptr != NULL &&
				    strcasecmp(ptr, "nameserver") == 0) {
					ptr = strtok (NULL, " \t");
					if (ptr != NULL) {
						srv = isc_mem_allocate(mctx,
						    sizeof(struct dig_server));
						if (srv == NULL)
							fatal("Memory "
							      "allocation "
							      "failure.");
							strncpy(srv->
								servername,
								ptr,
								MXNAME - 1);
							ISC_LIST_APPEND
								(server_list,
								 srv, link);
					}
				}
			}
			fclose (fp);
		}
	}

	if (server_list.head == NULL) {
		srv = isc_mem_allocate(mctx, sizeof(dig_server_t));
		if (srv == NULL)
			fatal("Memory allocation failure");
		strcpy(srv->servername, "127.0.0.1");
		ISC_LIST_APPEND(server_list, srv, link);
	}
}
	
static void
setup_libs(void) {
	isc_result_t result;
	isc_buffer_t b;

	debug ("setup_libs()");
	result = isc_app_start();
	check_result(result, "isc_app_start");

	result = isc_net_probeipv4();
	check_result(result, "isc_net_probeipv4");

	result = isc_net_probeipv6();
	if (result == ISC_R_SUCCESS)
		have_ipv6=ISC_TRUE;

	result = isc_mem_create(0, 0, &mctx);
	check_result(result, "isc_mem_create");

	result = isc_taskmgr_create (mctx, 1, 0, &taskmgr);
	check_result(result, "isc_taskmgr_create");

	result = isc_task_create (taskmgr, 0, &task);
	check_result(result, "isc_task_create");

	result = isc_timermgr_create (mctx, &timermgr);
	check_result(result, "isc_timermgr_create");

	result = isc_socketmgr_create (mctx, &socketmgr);
	check_result(result, "isc_socketmgr_create");
	isc_buffer_init(&b, ".", 1);
	isc_buffer_add(&b, 1);
	dns_name_init(&rootorg, NULL);
	isc_buffer_init(&rootbuf, rootspace, BUFSIZE);
	result = dns_name_fromtext(&rootorg, &b, NULL, ISC_FALSE, &rootbuf);
	check_result(result, "dns_name_fromtext");
}

static void
add_type(dns_message_t *message, dns_name_t *name, dns_rdataclass_t rdclass,
	 dns_rdatatype_t rdtype)
{
	dns_rdataset_t *rdataset;
	isc_result_t result;

	debug ("add_type()"); 
	rdataset = NULL;
	result = dns_message_gettemprdataset(message, &rdataset);
	check_result(result, "dns_message_gettemprdataset()");
	dns_rdataset_init(rdataset);
	dns_rdataset_makequestion(rdataset, rdclass, rdtype);
	ISC_LIST_APPEND(name->list, rdataset, link);
}

static void
followup_lookup(dns_message_t *msg, dig_query_t *query) {
	dig_lookup_t *lookup = NULL;
	dig_server_t *srv = NULL;
	dns_rdataset_t *rdataset = NULL;
	dns_rdata_t rdata;
	dns_name_t *name = NULL;
	isc_result_t result, loopresult;
	isc_buffer_t *b = NULL;
	isc_region_t r;
	int len;

	debug ("followup_lookup()"); 
	result = dns_message_firstname (msg, DNS_SECTION_ANSWER);
	if (result != ISC_R_SUCCESS) {
		debug ("Firstname returned %s",
			isc_result_totext(result));
                return;
	}

	debug ("Following up %s", query->lookup->textname);

	for (;;) {
		name = NULL;
		dns_message_currentname(msg, DNS_SECTION_ANSWER,
					&name);
		for (rdataset = ISC_LIST_HEAD(name->list);
		     rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link)) {
			loopresult = dns_rdataset_first(rdataset);
			while (loopresult == ISC_R_SUCCESS) {
				dns_rdataset_current(rdataset, &rdata);
				if (rdata.type == dns_rdatatype_ns) {
					result = isc_buffer_allocate(mctx, &b,
								     BUFSIZE);
					check_result (result,
						      "isc_buffer_allocate");
					result = dns_rdata_totext (&rdata,
								   NULL,
								   b);
					check_result (result,
						      "dns_rdata_totext");
					isc_buffer_usedregion(b, &r);
					len = r.length-1;
					if (len >= MXNAME)
						len = MXNAME-1;
				/* Initialize lookup if we've not yet */
					debug ("Found NS %d %.*s",
						 (int)r.length, (int)r.length,
						 (char *)r.base);
					lookup = isc_mem_allocate
						(mctx,
						 sizeof(struct
							dig_lookup));
					if (lookup == NULL)
						fatal ("Memory "
						       "allocation "
						       "failure.");
					lookup->pending = ISC_FALSE;
					strncpy (lookup->textname,
						 query->lookup->
						 textname, MXNAME);
					strncpy (lookup->rttext, 
						 query->lookup->
						 rttext, 32);
					strncpy (lookup->rctext,
						 query->lookup->
						 rctext, 32);
					lookup->namespace[0]=0;
					lookup->sendspace[0]=0;
					lookup->sendmsg=NULL;
					lookup->name=NULL;
					lookup->timer = NULL;
					lookup->xfr_q = NULL;
					lookup->doing_xfr = ISC_FALSE;
					lookup->identify = ISC_TRUE;
					lookup->ns_search_only = 
						ISC_FALSE;
					lookup->use_my_server_list = 
						ISC_TRUE;
					ISC_LIST_INIT(lookup->
						      my_server_list);
					ISC_LIST_INIT(lookup->q);
					srv = isc_mem_allocate (mctx,
								sizeof(
								struct
								dig_server));
					if (srv == NULL)
						fatal("Memory allocation "
						      "failure.");
					strncpy(srv->servername, r.base,
						len);
					srv->servername[len]=0;
					ISC_LIST_APPEND
						(lookup->my_server_list,
						 srv, link);
					isc_buffer_free (&b);
				}
				debug ("Before insertion, init@%ld "
					 "-> %ld, new@%ld "
					 "-> %ld",(long int)query->lookup,
					 (long int)query->lookup->link.next,
					 (long int)lookup, (long int)lookup->
					 link.next);
				ISC_LIST_INSERTAFTER(lookup_list, query->
						     lookup, lookup,
						     link);
				debug ("After insertion, init -> "
					 "%ld, new = %ld, "
					 "new -> %ld",(long int)query->
					 lookup->link.next,
					 (long int)lookup, (long int)lookup->
					 link.next);
				loopresult = dns_rdataset_next(rdataset);
			}
		}
	result = dns_message_nextname (msg, DNS_SECTION_ANSWER);
	if (result != ISC_R_SUCCESS)
		break;
	}
	if (lookup == NULL)
		return; /* We didn't get a NS.  Just give up. */
}

void
setup_lookup(dig_lookup_t *lookup) {
	isc_result_t result;
	int len;
	dns_rdatatype_t rdtype;
	dns_rdataclass_t rdclass;
	dig_server_t *serv;
	dig_query_t *query;
	isc_textregion_t r;
	isc_buffer_t b;
	
	debug("setup_lookup()");
	debug("Setting up for looking up %s @%ld->%ld", 
		lookup->textname, (long int)lookup,
		(long int)lookup->link.next);
	len=strlen(lookup->textname);
	isc_buffer_init(&b, lookup->textname, len);
	isc_buffer_add(&b, len);

	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER,
				    &lookup->sendmsg);
	check_result(result, "dns_message_create");


	result = dns_message_gettempname(lookup->sendmsg, &lookup->name);
	check_result(result, "dns_message_gettempname");
	dns_name_init(lookup->name, NULL);

	isc_buffer_init(&lookup->namebuf, lookup->namespace, BUFSIZE);

	result = dns_name_fromtext(lookup->name, &b, &rootorg,
				    ISC_FALSE, &lookup->namebuf);
	if (result != ISC_R_SUCCESS) {
		dns_message_puttempname(lookup->sendmsg, &lookup->name);
		fatal("Aborting: %s is not a legal name syntax.",
		      lookup->textname);
	}

	if (lookup->rctext[0] == 0)
		strcpy(lookup->rctext, "IN");
	if (lookup->rttext[0] == 0)
		strcpy(lookup->rttext, "A");

	lookup->sendmsg->id = id++;
	lookup->sendmsg->opcode = dns_opcode_query;
	if (recurse)
		lookup->sendmsg->flags |= DNS_MESSAGEFLAG_RD;

	dns_message_addname(lookup->sendmsg, lookup->name,
			    DNS_SECTION_QUESTION);
	
	
	if (!lookup->ns_search_only) {
		r.base=lookup->rttext;
		r.length=strlen(lookup->rttext);
	} else {
		r.base="NS";
		r.length=2;
	}
	result = dns_rdatatype_fromtext(&rdtype, &r);
	check_result(result, "dns_rdatatype_fromtext");
	if (rdtype == dns_rdatatype_axfr) {
		lookup->doing_xfr = ISC_TRUE;
		/*
		 * Force TCP mode if we're doing an xfr.
		 */
		tcp_mode = ISC_TRUE;
	}
	if (!lookup->ns_search_only) {
		r.base=lookup->rctext;
		r.length=strlen(lookup->rctext);
	} else {
		r.base="IN";
		r.length=2;
	}
	result = dns_rdataclass_fromtext(&rdclass, &r);
	check_result(result, "dns_rdataclass_fromtext");
	add_type(lookup->sendmsg, lookup->name, rdclass, rdtype);

	isc_buffer_init(&lookup->sendbuf, lookup->sendspace, COMMSIZE);
	result = dns_message_renderbegin(lookup->sendmsg, &lookup->sendbuf);
	check_result(result, "dns_message_renderbegin");
	result = dns_message_rendersection(lookup->sendmsg,
					   DNS_SECTION_QUESTION, 0);
	check_result(result, "dns_message_rendersection");
	result = dns_message_renderend(lookup->sendmsg);
	check_result(result, "dns_message_renderend");

	lookup->pending = ISC_FALSE;

	if (lookup->use_my_server_list)
		serv = ISC_LIST_HEAD(lookup->my_server_list);
	else
		serv = ISC_LIST_HEAD(server_list);
	for (; serv != NULL;
	     serv = ISC_LIST_NEXT(serv, link)) {
		query = isc_mem_allocate(mctx, sizeof(dig_query_t));
		if (query == NULL)
			fatal("Memory allocation failure.");
		query->lookup = lookup;
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		query->first_pass = ISC_TRUE;
		query->first_soa_rcvd = ISC_FALSE;
		query->servname = serv->servername;
		ISC_LIST_INIT(query->sendlist);
		ISC_LIST_INIT(query->recvlist);
		ISC_LIST_INIT(query->lengthlist);
		query->sock = NULL;

		isc_buffer_init(&query->recvbuf, query->recvspace, COMMSIZE);
		isc_buffer_init(&query->lengthbuf, query->lengthspace, 2);
		isc_buffer_init(&query->slbuf, query->slspace, 2);

		ISC_LIST_ENQUEUE(lookup->q, query, link);
	}
}	

static void
send_done(isc_task_t *task, isc_event_t *event) {
	UNUSED(task);
	isc_event_free(&event);

	debug("send_done()");
}

static void
cancel_lookup(dig_lookup_t *lookup) {
	dig_query_t *query=NULL;

	debug("cancel_lookup()");
	if (!lookup->pending)
		return;
	lookup->pending = ISC_FALSE;
	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		if (query->working) {
			isc_socket_cancel(query->sock, task,
					  ISC_SOCKCANCEL_ALL);
		}
	}
}

/* connect_timeout is used for both UDP recieves and TCP connects. */
static void
connect_timeout(isc_task_t *task, isc_event_t *event) {
	dig_lookup_t *lookup=NULL;
	dig_query_t *q=NULL;
	isc_result_t result;
	isc_buffer_t *b=NULL;
	isc_region_t r;

	REQUIRE(event->ev_type == ISC_TIMEREVENT_IDLE);

	debug("connect_timeout()");
	lookup = event->ev_arg;

	debug ("Buffer Allocate connect_timeout");
	result = isc_buffer_allocate(mctx, &b, 256);
	check_result(result, "isc_buffer_allocate");
	for (q = ISC_LIST_HEAD(lookup->q);
	     q != NULL;
	     q = ISC_LIST_NEXT(q, link)) {
		if (q->working) {
			if (!free_now) {
				isc_buffer_clear(b);
				result = isc_sockaddr_totext(&q->sockaddr, b);
				check_result(result, "isc_sockaddr_totext");
				isc_buffer_usedregion(b, &r);
				printf(";; Connection to server %.*s for %s "
				       "failed: Connection timed out.\n",
				       (int)r.length, r.base,
				       q->lookup->textname);
			}
			isc_socket_cancel(q->sock, task,
					  ISC_SOCKCANCEL_ALL);
		}
	}
	ENSURE(lookup->timer != NULL);
	isc_timer_detach(&lookup->timer);
	isc_buffer_free(&b);
	isc_event_free(&event);
}

static void
recv_done(isc_task_t *task, isc_event_t *event);

static void
tcp_length_done(isc_task_t *task, isc_event_t *event) { 
	isc_socketevent_t *sevent;
	isc_buffer_t *b=NULL;
	isc_region_t r;
	isc_result_t result;
	dig_query_t *query=NULL;
	isc_uint16_t length;

	REQUIRE(event->ev_type == ISC_SOCKEVENT_RECVDONE);

	UNUSED(task);

	debug("tcp_length_done()");
	sevent = (isc_socketevent_t *)event;	

	query = event->ev_arg;

	if (sevent->result == ISC_R_CANCELED) {
		query->working = ISC_FALSE;
		check_next_lookup(query->lookup);
		isc_event_free(&event);
		return;
	}
	if (sevent->result != ISC_R_SUCCESS) {
		debug ("Buffer Allocate connect_timeout");
		result = isc_buffer_allocate(mctx, &b, 256);
		check_result(result, "isc_buffer_allocate");
		result = isc_sockaddr_totext(&query->sockaddr, b);
		check_result(result, "isc_sockaddr_totext");
		isc_buffer_usedregion(b, &r);
		printf("%.*s: %s\n", (int)r.length, r.base,
		       isc_result_totext(sevent->result));
		isc_buffer_free(&b);
		query->working = ISC_FALSE;
		isc_socket_detach(&query->sock);
		check_next_lookup(query->lookup);
		isc_event_free(&event);
		return;
	}
	b = ISC_LIST_HEAD(sevent->bufferlist);
	ISC_LIST_DEQUEUE(sevent->bufferlist, &query->lengthbuf, link);
	length = isc_buffer_getuint16(b);
	if (length > COMMSIZE) {
		isc_event_free (&event);
		fatal ("Length of %X was longer than I can handle!",
		       length);
	}
	/* XXXMWS Fix the above. */
	/*
	 * Even though the buffer was already init'ed, we need
	 * to redo it now, to force the length we want.
	 */
	isc_buffer_invalidate(&query->recvbuf);
	isc_buffer_init(&query->recvbuf, query->recvspace, length);
	ENSURE(ISC_LIST_EMPTY(query->recvlist));
	ISC_LIST_ENQUEUE(query->recvlist, &query->recvbuf, link);
	result = isc_socket_recvv(query->sock, &query->recvlist, length, task,
				  recv_done, query);
	check_result(result, "isc_socket_recvv");
	debug("Resubmitted recv request with length %d", length);
	isc_event_free(&event);
}

static void
launch_next_query(dig_query_t *query, isc_boolean_t include_question) {
	isc_result_t result;

	debug("launch_next_query()");

	if (!query->lookup->pending) {
		debug("Ignoring launch_next_query because !pending.");
		isc_socket_detach(&query->sock);
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		check_next_lookup(query->lookup);
		return;
	}

	isc_buffer_clear(&query->slbuf);
	isc_buffer_clear(&query->lengthbuf);
	isc_buffer_putuint16(&query->slbuf, query->lookup->sendbuf.used);
	ISC_LIST_ENQUEUE(query->sendlist, &query->slbuf, link);
	if (include_question) {
#ifdef TWIDDLE
		if (twiddle) {
			twiddlebuf(query->lookup->sendbuf);
		}
#endif
		ISC_LIST_ENQUEUE(query->sendlist, &query->lookup->sendbuf,
				 link);
	}
	ISC_LIST_ENQUEUE(query->lengthlist, &query->lengthbuf, link);

	result = isc_socket_recvv(query->sock, &query->lengthlist, 0, task,
				  tcp_length_done, query);
	check_result(result, "isc_socket_recvv");
	sendcount++;
	if (!query->first_soa_rcvd) {
		debug("Sending a request.");
		result = isc_socket_sendv(query->sock, &query->sendlist, task,
					  send_done, query);
		check_result(result, "isc_socket_recvv");
	}
	query->waiting_connect = ISC_FALSE;
	check_next_lookup(query->lookup);
	return;
}
	
static void
connect_done(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	isc_socketevent_t *sevent=NULL;
	dig_query_t *query=NULL;
	isc_buffer_t *b=NULL;
	isc_region_t r;

	UNUSED(task);

	REQUIRE(event->ev_type == ISC_SOCKEVENT_CONNECT);

	sevent = (isc_socketevent_t *)event;
	query = sevent->ev_arg;

	REQUIRE(query->waiting_connect);

	query->waiting_connect = ISC_FALSE;

	debug("connect_done()");
	if (sevent->result != ISC_R_SUCCESS) {
		debug ("Buffer Allocate connect_timeout");
		result = isc_buffer_allocate(mctx, &b, 256);
		check_result(result, "isc_buffer_allocate");
		result = isc_sockaddr_totext(&query->sockaddr, b);
		check_result(result, "isc_sockaddr_totext");
		isc_buffer_usedregion(b, &r);
		printf(";; Connection to server %.*s for %s failed: %s.\n",
		       (int)r.length, r.base, query->lookup->textname,
		       isc_result_totext(sevent->result));
		isc_buffer_free(&b);
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		check_next_lookup(query->lookup);
		isc_event_free(&event);
		return;
	}
	isc_event_free(&event);
	launch_next_query(query, ISC_TRUE);
}

static isc_boolean_t
msg_contains_soa(dns_message_t *msg, dig_query_t *query) {
	isc_result_t result;
	dns_name_t *name=NULL;

	debug("msg_contains_soa()");

	result = dns_message_findname(msg, DNS_SECTION_ANSWER,
				      query->lookup->name, dns_rdatatype_soa,
				      0, &name, NULL);
	if (result == ISC_R_SUCCESS) {
		debug("Found SOA", stderr);
		return (ISC_TRUE);
	} else {
		debug("Didn't find SOA, result=%d:%s",
			result, dns_result_totext(result));
		return (ISC_FALSE);
	}
	
}

static void
recv_done(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = NULL;
	dig_query_t *query = NULL;
	isc_buffer_t *b = NULL;
	dns_message_t *msg = NULL;
	isc_result_t result;
	isc_buffer_t ab;
	char abspace[MXNAME];
	isc_region_t r;
	
	UNUSED (task);

	debug("recv_done()");

	if (free_now) {
		debug("Bailing out, since freeing now.");
		isc_event_free (&event);
		return;
	}

	sendcount--;
	debug("In recv_done, counter down to %d", sendcount);
	REQUIRE(event->ev_type == ISC_SOCKEVENT_RECVDONE);
	sevent = (isc_socketevent_t *)event;
	query = event->ev_arg;

	if (!query->lookup->pending) {
		debug("No longer pending.  Got %s",
			isc_result_totext(sevent->result));
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		cancel_lookup(query->lookup);
		check_next_lookup(query->lookup);
		isc_event_free(&event);
		return;
	}

	if (sevent->result == ISC_R_SUCCESS) {
		b = ISC_LIST_HEAD(sevent->bufferlist);
		ISC_LIST_DEQUEUE(sevent->bufferlist, &query->recvbuf, link);
		result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE,
					    &msg);
		check_result(result, "dns_message_create");
		result = dns_message_parse(msg, b, ISC_TRUE);
		if (result != ISC_R_SUCCESS)
			hex_dump(b);
		check_result(result, "dns_message_parse");
		if (query->lookup->xfr_q == NULL)
			query->lookup->xfr_q = query;
		if (query->lookup->xfr_q == query) {
			if (query->lookup->ns_search_only)
				followup_lookup(msg, query);
			else {
				if (query->first_soa_rcvd &&
				    query->lookup->doing_xfr)
					printmessage(query, msg, ISC_FALSE);
				else
					printmessage(query, msg, ISC_TRUE);
			}
		}
#ifdef DEBUG
		if (query->lookup->pending)
			debug("Still pending.");
#endif
		if (query->lookup->doing_xfr) {
			if (!query->first_soa_rcvd) {
				debug("Not yet got first SOA");
				if (!msg_contains_soa(msg, query)) {
					puts("; Transfer failed.  "
					     "Didn't start with SOA answer.");
					query->working = ISC_FALSE;
					cancel_lookup(query->lookup);
					check_next_lookup (query->lookup);
					isc_event_free (&event);
					dns_message_destroy (&msg);
					return;
				}
				else {
					query->first_soa_rcvd = ISC_TRUE;
					launch_next_query(query, ISC_FALSE);
				}
			} 
			else {
				if (msg_contains_soa(msg, query)) {
					cancel_lookup(query->lookup);
					query->working = ISC_FALSE;
					check_next_lookup(query->lookup);
					isc_event_free(&event);
					dns_message_destroy (&msg);
					return;
				}
				else {
					launch_next_query(query, ISC_FALSE);
				}
			}
		}
		else {
			query->working = ISC_FALSE;
			cancel_lookup(query->lookup);
		}
		if (!query->lookup->pending) {
			isc_buffer_init(&ab, abspace, MXNAME);
			check_result(result, "isc_buffer_init");
			result = isc_sockaddr_totext(&sevent->address, &ab);
			check_result(result, "isc_sockaddr_totext");
			isc_buffer_usedregion(&ab, &r);
			if (!short_form)
				printf("; Received %u bytes from %s\n",
				       b->used, r.base);
			check_next_lookup(query->lookup);
		}
		dns_message_destroy(&msg);
		isc_event_free(&event);
		return;
	}
	/* In truth, we should never get into the CANCELED routine, since
	   the cancel_lookup() routine clears the pending flag. */
	if (sevent->result == ISC_R_CANCELED) {
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		check_next_lookup(query->lookup);
		isc_event_free(&event);
		return;
	}
	fatal("recv_done got result %s",
	      isc_result_totext(sevent->result));
}

static void
get_address(char *hostname, in_port_t port, isc_sockaddr_t *sockaddr) {
	struct in_addr in4;
	struct in6_addr in6;
	struct hostent *he;
	char host[MXNAME];

	debug("get_address()");

	sscanf (hostname, "%s", host); /* Force CR, etc... out */
	if (have_ipv6 && inet_pton(AF_INET6, host, &in6) == 1)
		isc_sockaddr_fromin6(sockaddr, &in6, port);
	else if (inet_pton(AF_INET, host, &in4) == 1)
		isc_sockaddr_fromin(sockaddr, &in4, port);
	else {
		he = gethostbyname(host);
		if (he == NULL)
		     fatal("Couldn't look up your server host %s.  errno=%d",
			      hostname, h_errno);
		INSIST(he->h_addrtype == AF_INET);
		isc_sockaddr_fromin(sockaddr,
				    (struct in_addr *)(he->h_addr_list[0]),
				    port);
	}
}

void
do_lookup_tcp(dig_lookup_t *lookup) {
	dig_query_t *query;
	isc_result_t result;

	debug("do_lookup_tcp()");
	lookup->pending = ISC_TRUE;
	isc_interval_set(&lookup->interval, timeout, 0);
	result = isc_timer_create(timermgr, isc_timertype_once, NULL,
				  &lookup->interval, task, connect_timeout,
				  lookup, &lookup->timer);
	check_result(result, "isc_timer_create");

	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		query->working = ISC_TRUE;
		query->waiting_connect = ISC_TRUE;
		get_address(query->servname, port, &query->sockaddr);

		result = isc_socket_create(socketmgr,
					   isc_sockaddr_pf(&query->sockaddr),
					   isc_sockettype_tcp, &query->sock) ;
		check_result(result, "isc_socket_create");
		result = isc_socket_connect(query->sock, &query->sockaddr,
					    task, connect_done, query);
		check_result (result, "isc_socket_connect");
	}
}

void
do_lookup_udp(dig_lookup_t *lookup) {
	dig_query_t *query;
	isc_result_t result;

#ifdef DEBUG
	debug("do_lookup_udp()");
	if (tcp_mode)
		debug("I'm starting UDP with tcp_mode set!!!");
#endif
	lookup->pending = ISC_TRUE;
	isc_interval_set(&lookup->interval, timeout, 0);
	result = isc_timer_create(timermgr, isc_timertype_once, NULL,
				  &lookup->interval, task, connect_timeout,
				  lookup, &lookup->timer);
	check_result(result, "isc_timer_create");

	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		query->working = ISC_TRUE;
		query->waiting_connect = ISC_FALSE;
		get_address(query->servname, port, &query->sockaddr);

		result = isc_socket_create(socketmgr,
					   isc_sockaddr_pf(&query->sockaddr),
					   isc_sockettype_udp, &query->sock) ;
		check_result(result, "isc_socket_create");
		ISC_LIST_ENQUEUE(query->recvlist, &query->recvbuf, link);
		result = isc_socket_recvv(query->sock, &query->recvlist, 1,
					  task, recv_done, query);
		check_result(result, "isc_socket_recvv");
		sendcount++;
		debug("Sent count number %d", sendcount);
#ifdef TWIDDLE
		if (twiddle) {
			twiddlebuf(lookup->sendbuf);
		}
#endif
		ISC_LIST_ENQUEUE(query->sendlist, &lookup->sendbuf, link);
		debug("Sending a request.");
		result = isc_socket_sendtov(query->sock, &query->sendlist,
					    task, send_done, query,
					    &query->sockaddr, NULL);
		check_result(result, "isc_socket_sendtov");
	}
}

static void
free_lists(void) {
	void *ptr;
	dig_lookup_t *l;
	dig_query_t *q;
	dig_server_t *s;

	debug("free_lists()");

	free_now = ISC_TRUE;

	l = ISC_LIST_HEAD(lookup_list);
	while (l != NULL) {
		q = ISC_LIST_HEAD(l->q);
		while (q != NULL) {
			if (q->sock != NULL) {
				isc_socket_cancel(q->sock, NULL,
						  ISC_SOCKCANCEL_ALL);
				isc_socket_detach(&q->sock);
			}
			if (ISC_LINK_LINKED(&q->recvbuf, link))
				ISC_LIST_DEQUEUE(q->recvlist, &q->recvbuf,
						 link);
			if (ISC_LINK_LINKED(&q->lengthbuf, link))
				ISC_LIST_DEQUEUE(q->lengthlist, &q->lengthbuf,
						 link);
			isc_buffer_invalidate(&q->recvbuf);
			isc_buffer_invalidate(&q->lengthbuf);
			ptr = q;
			q = ISC_LIST_NEXT(q, link);
			isc_mem_free(mctx, ptr);
		}
		if (l->use_my_server_list) {
			s = ISC_LIST_HEAD(l->my_server_list);
			while (s != NULL) {
				ptr = s;
				s = ISC_LIST_NEXT(s, link);
				isc_mem_free(mctx, ptr);

			}
		}
		if (l->sendmsg != NULL)
			dns_message_destroy (&l->sendmsg);
		if (l->timer != NULL)
			isc_timer_detach (&l->timer);
		ptr = l;
		l = ISC_LIST_NEXT(l, link);
		isc_mem_free(mctx, ptr);
	}
	s = ISC_LIST_HEAD(server_list);
	while (s != NULL) {
		ptr = s;
		s = ISC_LIST_NEXT(s, link);
		isc_mem_free(mctx, ptr);
	}
	dns_name_invalidate(&rootorg);
	if (socketmgr != NULL)
		isc_socketmgr_destroy(&socketmgr);
	if (timermgr != NULL)
		isc_timermgr_destroy(&timermgr);
	if (task != NULL)
		isc_task_detach(&task);
	if (taskmgr != NULL)
		isc_taskmgr_destroy(&taskmgr);
}

int
main(int argc, char **argv) {
	dig_lookup_t *lookup = NULL;
#ifdef TWIDDLE
	FILE *fp;
	int i,p;
#endif

	ISC_LIST_INIT(lookup_list);
	ISC_LIST_INIT(server_list);

#ifdef TWIDDLE
	fp = fopen("/dev/urandom","r");
	if (fp!=NULL) {
		fread (&i, sizeof(int), 1, fp);
		srandom(i);
	}
	else {
		srandom ((int)&main);
	}
	p = getpid()%16+8;
	for (i=0 ; i<p; i++);
#endif
	setup_libs();
	port = 53;
	timeout = 10;
	parse_args(ISC_FALSE, argc, argv);
	setup_system();
	lookup = ISC_LIST_HEAD(lookup_list);
	setup_lookup(lookup);
	if (tcp_mode)
		do_lookup_tcp(lookup);
	else
		do_lookup_udp(lookup);
	isc_app_run();
	free_lists();
#ifdef MEMDEBUG
	isc_mem_stats(mctx, stderr);
#endif
	isc_app_finish();
	if (mctx != NULL)
		isc_mem_destroy(&mctx);

	return (0);
}
