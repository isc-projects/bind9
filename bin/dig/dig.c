/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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
#include <dig/printmsg.h>

ISC_LIST(dig_lookup_t) lookup_list;
ISC_LIST(dig_server_t) server_list;

isc_boolean_t tcp_mode=ISC_FALSE,
	recurse=ISC_TRUE,
	have_ipv6=ISC_FALSE;
in_port_t port;
unsigned int timeout;
isc_mem_t *mctx=NULL;
isc_taskmgr_t *taskmgr=NULL;
isc_task_t *task=NULL;
isc_timermgr_t *timermgr=NULL;
isc_socketmgr_t *socketmgr=NULL;
dns_messageid_t id;
dns_name_t rootorg;
char *rootspace[BUFSIZE];
isc_buffer_t rootbuf;
int sendcount=0;

static void
free_lists();

static void
hex_dump(isc_buffer_t *b)
{
	unsigned int len;
	isc_region_t r;

	isc_buffer_remaining(b, &r);

	printf ("Printing a buffer with length %d\n",r.length);
	for (len = 0 ; len < r.length ; len++) {
		printf("%02x ", r.base[len]);
		if (len != 0 && len % 16 == 0)
			printf("\n");
	}
	if (len % 16 != 0)
		printf("\n");
}


static void
fatal(char *format, ...) {
	va_list args;

	va_start(args, format);	
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	free_lists();
	exit(1);
}

static inline void
check_result(isc_result_t result, char *msg) {
	if (result != ISC_R_SUCCESS)
		fatal("%s: %s", msg, isc_result_totext(result));
}

static isc_boolean_t
isclass(char *text) {
	/* Tests if a field is a class, without needing isc libs
	   initialized.  This list will have to be manually kept in 
	   sync with what the libs support. */
	static const char *classlist[] = {"in", "hs", "any"};
	static const int numclasses = 3;
	int i;

	for (i=0;i<numclasses;i++) {
		if (strcasecmp(text, classlist[i]) == 0)
			return ISC_TRUE;
	}
	return ISC_FALSE;
}

static isc_boolean_t
istype(char *text) {
	/* Tests if a field is a type, without needing isc libs
	   initialized.  This list will have to be manually kept in 
	   sync with what the libs support. */
	static const char *typelist[] = {"a", "ns", "md", "mf", "cname",
					  "soa", "mb", "mg", "mr", "null",
					  "wks", "ptr", "hinfo", "minfo",
					  "mx", "txt", "rp", "afsdb",
					  "x25", "isdn", "rt", "nsap",
					  "nsap_ptr", "sig", "key", "px",
					  "gpos", "aaaa", "loc", "nxt",
					  "srv", "naptr", "kx", "cert",
					  "a6", "dname", "opt", "unspec",
					  "tkey", "tsig", "axfr"};
	static const int numtypes = 41;
	int i;

	for (i=0;i<numtypes;i++) {
		if (strcasecmp(text, typelist[i]) == 0)
			return ISC_TRUE;
	}
	return ISC_FALSE;
}



static void
parse_args(isc_boolean_t is_batchfile, int argc, char **argv) {
	isc_boolean_t have_host=ISC_FALSE;
	dig_server_t *srv=NULL;
	dig_lookup_t *lookup=NULL;
	char *batchname=NULL;
	char batchline[MXNAME];
	FILE *fp=NULL;
	int bargc;
	char bargv[8][MXNAME];

	for (argc--, argv++; argc > 0; argc--, argv++) {
		if ((strncmp(argv[0],"@",1) == 0)
		    && (!is_batchfile)) {
			srv=isc_mem_allocate(mctx, sizeof(struct dig_server));
			if (srv == NULL)
				fatal ("Memory allocation failure.");
			strncpy(srv->servername,&argv[0][1],MXNAME-1);
			ISC_LIST_APPEND(server_list, srv, link);
		} else if ((strcmp(argv[0],"+vc") == 0)
			   && (!is_batchfile)) {
			tcp_mode = ISC_TRUE;
		} else if (strcmp(argv[0],"+norecurs") == 0) {
			recurse = ISC_FALSE;
		} else if (strcmp(argv[0],"-f") == 0) {
			batchname=argv[1];
			argv++;
			argc--;
		} else {
			if (have_host) {
				ENSURE ( lookup != NULL );
				if (isclass(argv[0])) {
					strncpy (lookup->rctext,argv[0],
						 MXRD);
					continue;
				} else if (istype(argv[0])) {
					strncpy (lookup->rttext,argv[0],
						 MXRD);
					continue;
				}
			}
			lookup = isc_mem_allocate (mctx, 
						   sizeof(struct dig_lookup));
			if (lookup == NULL)
				fatal ("Memory allocation failure.");
			lookup->pending = ISC_FALSE;
			strncpy (lookup->textname,argv[0], MXNAME-1);
			lookup->rttext[0]=0;
			lookup->rctext[0]=0;
			lookup->namespace[0]=0;
			lookup->sendspace[0]=0;
			lookup->sendmsg=NULL;
			lookup->name=NULL;
			lookup->timer = NULL;
			lookup->xfr_q = NULL;
			lookup->doing_xfr = ISC_FALSE;
			ISC_LIST_INIT(lookup->q);
			ISC_LIST_APPEND(lookup_list, lookup, link);
			have_host = ISC_TRUE;
		}
	}
	if (batchname != NULL) {
		fp = fopen (batchname, "r");
		if (fp == NULL) {
			perror (batchname);
			fatal ("Couldn't open specified batch file.");
		}
		while (fgets (batchline, MXNAME, fp) != 0) {
			bargc = sscanf ("%s %s %s %s %s %s %s",
					bargv[1], bargv[2], bargv[3],
					bargv[4], bargv[5], bargv[6],
					bargv[7]);
			bargc++;
			strcpy (bargv[0], "dig");
			parse_args(ISC_TRUE, bargc, (char**)bargv);
		}
	}
	if (lookup_list.head == NULL) {
		lookup = isc_mem_allocate (mctx, 
					   sizeof(struct dig_lookup));
		if (lookup == NULL)
			fatal ("Memory allocation failure.");
		lookup->pending = ISC_FALSE;
		lookup->rctext[0]=0;
		lookup->namespace[0]=0;
		lookup->sendspace[0]=0;
		lookup->sendmsg=NULL;
		lookup->name=NULL;
		lookup->timer = NULL;
		lookup->xfr_q = NULL;
		lookup->doing_xfr = ISC_FALSE;
		ISC_LIST_INIT(lookup->q);
		strcpy (lookup->textname,".");
		strcpy (lookup->rttext, "NS");
		lookup->rctext[0]=0;
		ISC_LIST_APPEND(lookup_list, lookup, link);
	}
}

static void
setup_system() {
	char rcinput[MXNAME];
	FILE *fp;
	char *ptr;
	dig_server_t *srv;

	port = 53;
	timeout = 10;
	id = getpid()<<8;

	if (server_list.head == NULL) {
		fp = fopen (RESOLVCONF, "r");
		if (fp != NULL) {
			while (fgets(rcinput, MXNAME, fp) != 0) {
				ptr = strtok (rcinput, " \t");
				if (ptr != NULL) {
					if (strcasecmp(ptr,"nameserver")
					    == 0) {
						ptr = strtok (NULL, " \t");
						if (ptr != NULL) {
							srv=isc_mem_allocate (mctx, sizeof(struct dig_server));
							if (srv == NULL)
								fatal ("Memory allocation failure.");
							strncpy(srv->servername, ptr,MXNAME-1);
							ISC_LIST_APPEND(server_list, srv, link);
						}
					}
				}
			}
			fclose (fp);
		}
	}
	if (server_list.head == NULL) {
		srv = isc_mem_allocate(mctx, sizeof(dig_server_t));
		if (srv == NULL)
			fatal ("Memory allocation failure");
		strcpy (srv->servername, "127.0.0.1");
		ISC_LIST_APPEND(server_list, srv, link);
	}
}
	
static void
setup_libs() {
	isc_result_t result;
	isc_buffer_t b;

	result = isc_app_start();
	check_result (result, "isc_app_start");

	result = isc_net_probeipv4();
	check_result (result, "isc_net_probeipv4");

	result = isc_net_probeipv6();
	if (result == ISC_R_SUCCESS)
		have_ipv6=ISC_TRUE;

	result = isc_mem_create (0, 0, &mctx);
	check_result (result, "isc_mem_create");

	result = isc_taskmgr_create (mctx, 1, 0, &taskmgr);
	check_result (result, "isc_taskmgr_create");

	result = isc_task_create (taskmgr, 0, &task);
	check_result (result, "isc_task_create");

	result = isc_timermgr_create (mctx, &timermgr);
	check_result (result, "isc_timermgr_create");

	result = isc_socketmgr_create (mctx, &socketmgr);
	check_result (result, "isc_socketmgr_create");

	isc_buffer_init (&b, ".", 1, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add (&b, 1);
	dns_name_init (&rootorg, NULL);
	isc_buffer_init (&rootbuf, rootspace, BUFSIZE,
			 ISC_BUFFERTYPE_BINARY);
	result = dns_name_fromtext (&rootorg, &b, NULL,
				    ISC_FALSE, &rootbuf);
	check_result (result, "dns_name_fromtext");

	
		
}

static void
add_type(dns_message_t *message, dns_name_t *name, dns_rdataclass_t rdclass,
	 dns_rdatatype_t rdtype)
{
	dns_rdataset_t *rdataset;
	isc_result_t result;

	rdataset = NULL;
	result = dns_message_gettemprdataset(message, &rdataset);
	check_result(result, "dns_message_gettemprdataset()");
	dns_rdataset_init(rdataset);
	dns_rdataset_makequestion(rdataset, rdclass, rdtype);
	ISC_LIST_APPEND(name->list, rdataset, link);
}

static void
setup_lookup(dig_lookup_t *lookup) {
	isc_result_t result;
	int len;
	dns_rdatatype_t rdtype;
	dns_rdataclass_t rdclass;
	dig_server_t *serv;
	dig_query_t *query;
	isc_textregion_t r;
	isc_buffer_t b;
	
#ifdef DEBUG
	printf ("Setting up for looking up %s\n",lookup->textname);
#endif
	len=strlen(lookup->textname);
	isc_buffer_init (&b, lookup->textname, len,
			 ISC_BUFFERTYPE_TEXT);
	isc_buffer_add (&b, len);

	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER,
				    &lookup->sendmsg);
	check_result (result, "dns_message_create");


	result = dns_message_gettempname(lookup->sendmsg, &lookup->name);
	check_result (result,"dns_message_gettempname");
	dns_name_init (lookup->name, NULL);

	isc_buffer_init (&lookup->namebuf, lookup->namespace, BUFSIZE,
			 ISC_BUFFERTYPE_BINARY);

	result = dns_name_fromtext (lookup->name, &b, &rootorg,
				    ISC_FALSE, &lookup->namebuf);
	check_result (result, "dns_name_fromtext");

	if (lookup->rctext[0] == 0)
		strcpy (lookup->rctext, "IN");
	if (lookup->rttext[0] == 0)
		strcpy (lookup->rttext, "A");

	lookup->sendmsg->id = id++;
	lookup->sendmsg->opcode = dns_opcode_query;
	if (recurse)
		lookup->sendmsg->flags |= DNS_MESSAGEFLAG_RD;

	dns_message_addname(lookup->sendmsg, lookup->name,
			    DNS_SECTION_QUESTION);
	
	
	r.base=lookup->rttext;
	r.length=strlen(lookup->rttext);
	result = dns_rdatatype_fromtext(&rdtype, &r);
	check_result (result, "dns_rdatatype_fromtext");
	if (rdtype  == dns_rdatatype_axfr)
		lookup->doing_xfr = ISC_TRUE;
	r.base=lookup->rctext;
	r.length=strlen(lookup->rctext);
	result = dns_rdataclass_fromtext(&rdclass, &r);
	check_result (result, "dns_rdataclass_fromtext");
	add_type(lookup->sendmsg, lookup->name, rdclass, rdtype);

	isc_buffer_init (&lookup->sendbuf, lookup->sendspace, COMMSIZE,
			 ISC_BUFFERTYPE_BINARY);
	result = dns_message_renderbegin(lookup->sendmsg, &lookup->sendbuf);
	check_result (result, "dns_message_renderbegin");
	result = dns_message_rendersection(lookup->sendmsg,
					   DNS_SECTION_QUESTION,0);
	check_result (result, "dns_message_rendersection");
	result = dns_message_renderend(lookup->sendmsg);
	check_result (result, "dns_message_renderend");

	lookup->pending = ISC_FALSE;

	for (serv = ISC_LIST_HEAD(server_list);
	     serv != NULL;
	     serv = ISC_LIST_NEXT(serv, link)) {
		query = isc_mem_allocate(mctx, sizeof(dig_query_t));
		if (query == NULL)
			fatal ("Memory allocation failure.");
		query->lookup = lookup;
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		query->first_pass = ISC_TRUE;
		query->first_soa_rcvd = ISC_FALSE;
		query->servname = serv->servername;
		ISC_LIST_INIT (query->sendlist);
		ISC_LIST_INIT (query->recvlist);
		ISC_LIST_INIT (query->lengthlist);
		query->sock = NULL;

		isc_buffer_init (&query->recvbuf, query->recvspace,
				 COMMSIZE, ISC_BUFFERTYPE_BINARY);
		isc_buffer_init (&query->lengthbuf, query->lengthspace,
				 2, ISC_BUFFERTYPE_BINARY);
		isc_buffer_init (&query->slbuf, query->slspace,
				 2, ISC_BUFFERTYPE_BINARY);

		ISC_LIST_ENQUEUE (lookup->q, query, link);
	}
}	

static void
send_done (isc_task_t *task, isc_event_t *event) {
	UNUSED (task);
	isc_event_free (&event);
}

static void
cancel_lookup (dig_lookup_t *lookup) {
	dig_query_t *query;

#ifdef DEBUG
	puts ("Cancelling all queries");
#endif
	if (!lookup->pending)
		return;
	lookup->pending = ISC_FALSE;
	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		if (query->working) {
			isc_socket_cancel (query->sock, task,
					   ISC_SOCKCANCEL_ALL);
		}
	}
}

static void
do_lookup_udp (dig_lookup_t *lookup);

static void
check_next_lookup (dig_lookup_t *lookup) {
	dig_lookup_t *next;
	dig_query_t *query;
	isc_boolean_t still_working=ISC_FALSE;
	
#ifdef DEBUG
	puts ("In check_next_lookup");
#endif
	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		if (query->working) {
#ifdef DEBUG
			puts ("Still have a worker.");
#endif
			still_working=ISC_TRUE;
		}
	}
	if (still_working)
		return;

	next = ISC_LIST_NEXT (lookup, link);
	if (next == NULL) {
#ifdef DEBUG
		puts ("Shutting Down.");
#endif
		isc_app_shutdown();
		return;
	}
	
	setup_lookup(next);
#ifdef NEVER
	if (tcp_mode)
		do_lookup_tcp(next);
	else
#endif	
		do_lookup_udp(next);

}

/* connect_timeout is used for both UDP recieves and TCP connects. */
static void
connect_timeout (isc_task_t *task, isc_event_t *event) {
	dig_lookup_t *lookup;
	dig_query_t *q=NULL;
	isc_result_t result;
	isc_buffer_t *b;
	isc_region_t r;

	lookup=event->ev_arg;

	REQUIRE (event->ev_type == ISC_TIMEREVENT_IDLE);

	result = isc_buffer_allocate(mctx, &b, 256, ISC_BUFFERTYPE_TEXT);
	check_result (result, "isc_buffer_allocate");
	for (q = ISC_LIST_HEAD(lookup->q);
	     q != NULL;
	     q = ISC_LIST_NEXT(q, link)) {
		if (q->working) {
			isc_buffer_clear (b);
			result = isc_sockaddr_totext(&q->sockaddr, b);
			check_result (result, "isc_sockaddr_totext");
			isc_buffer_used(b, &r);
			printf (";; Connection to server %.*s for %s failed: Connection timed out.\n",
				(int)r.length, r.base, q->lookup->textname);
			isc_socket_cancel(q->sock, task, ISC_SOCKCANCEL_ALL);
		}
	}
	ENSURE (lookup->timer != NULL);
	isc_timer_detach (&lookup->timer);
	isc_buffer_free (&b);
	isc_event_free (&event);
}

static void
recv_done (isc_task_t *task, isc_event_t *event) ;

static void
tcp_length_done (isc_task_t *task, isc_event_t *event) { 
	isc_socketevent_t *sevent;
	isc_buffer_t *b=NULL;
	isc_region_t r;
	isc_result_t result;
	dig_query_t *query=NULL;
	isc_uint16_t length;

	UNUSED (task);

#ifdef DEBUG
	puts ("In tcp_length_done");
#endif
	REQUIRE (event->ev_type == ISC_SOCKEVENT_RECVDONE);
	sevent = (isc_socketevent_t *)event;	

	query = event->ev_arg;

	if (sevent->result == ISC_R_CANCELED) {
		query->working = ISC_FALSE;
		isc_socket_detach (&query->sock);
		check_next_lookup(query->lookup);
		isc_event_free (&event);
		return;
	}
	if (sevent->result != ISC_R_SUCCESS) {
		result = isc_buffer_allocate(mctx, &b, 256,
					     ISC_BUFFERTYPE_TEXT);
		check_result (result, "isc_buffer_allocate");
		result = isc_sockaddr_totext(&query->sockaddr, b);
		check_result (result, "isc_sockaddr_totext");
		isc_buffer_used(b, &r);
		printf ("%.*s: %s\n",(int)r.length, r.base,
			isc_result_totext(sevent->result));
		isc_buffer_free (&b);
		query->working = ISC_FALSE;
		isc_socket_detach (&query->sock);
		check_next_lookup(query->lookup);
		isc_event_free (&event);
		return;
	}
	b = ISC_LIST_HEAD(sevent->bufferlist);
	ISC_LIST_DEQUEUE (sevent->bufferlist, &query->lengthbuf, link);
	length = isc_buffer_getuint16(b);
	if (length > COMMSIZE) 
		fatal ("Length was longer than I can handle!");
	/* XXXMWS Fix the above. */
	/* Even though the buffer was already init'ed, we need
	   to redo it now, to force the length we want. */
	isc_buffer_invalidate (&query->recvbuf);
	isc_buffer_init(&query->recvbuf, query->recvspace, 
			length, ISC_BUFFERTYPE_BINARY);
	ENSURE (ISC_LIST_EMPTY (query->recvlist));
	ISC_LIST_ENQUEUE (query->recvlist, &query->recvbuf, link);
	result = isc_socket_recvv (query->sock, &query->recvlist,
				   length, task, recv_done,
				   query);
	check_result (result, "isc_socket_recvv");
#ifdef DEBUG
	printf ("Resubmitted recv request with length %d\n",length);
#endif
	isc_event_free (&event);
}

static void
launch_next_query(dig_query_t *query, isc_boolean_t include_question) {
	isc_result_t result;

	if (!query->lookup->pending) {
#ifdef DEBUG
		puts ("Ignoring launch_next_query because !pending.");
#endif
		isc_socket_detach (&query->sock);
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		check_next_lookup (query->lookup);
		return;
	}

	isc_buffer_clear(&query->slbuf);
	isc_buffer_clear(&query->lengthbuf);
	isc_buffer_putuint16(&query->slbuf, query->lookup->sendbuf.used);
	ISC_LIST_ENQUEUE(query->sendlist, &query->slbuf, link);
	if (include_question)
		ISC_LIST_ENQUEUE(query->sendlist, &query->lookup->sendbuf,
				 link);
	ISC_LIST_ENQUEUE(query->lengthlist, &query->lengthbuf, link);

	result = isc_socket_recvv(query->sock, &query->lengthlist, 0, task,
				  tcp_length_done, query);
	check_result (result, "isc_socket_recvv");
	sendcount++;
#ifdef DEBUG
	puts ("Sending a request.");
#endif
	result = isc_socket_sendv(query->sock, &query->sendlist, task,
				  send_done, query);
	check_result (result, "isc_socket_recvv");
	query->waiting_connect = ISC_FALSE;
	check_next_lookup(query->lookup);
	return;
}
	
static void
connect_done (isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	isc_socketevent_t *sevent;
	dig_query_t *query;
	isc_buffer_t *b;
	isc_region_t r;

	UNUSED (task);

	REQUIRE (event->ev_type == ISC_SOCKEVENT_CONNECT);
	sevent = (isc_socketevent_t *)event;
	query = sevent->ev_arg;

	REQUIRE (query->waiting_connect);

	query->waiting_connect = ISC_FALSE;

#ifdef DEBUG
	puts ("In connect_done.");
#endif
	if (sevent->result != ISC_R_SUCCESS) {
		result = isc_buffer_allocate(mctx, &b, 256,
					     ISC_BUFFERTYPE_TEXT);
		check_result (result, "isc_buffer_allocate");
		result = isc_sockaddr_totext(&query->sockaddr, b);
		check_result (result, "isc_sockaddr_totext");
		isc_buffer_used(b, &r);
		printf (";; Connection to server %.*s for %s failed: %s.\n",
			(int)r.length, r.base, query->lookup->textname,
			isc_result_totext(sevent->result));
		isc_buffer_free(&b);
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		check_next_lookup(query->lookup);
		isc_event_free (&event);
		return;
	}
	isc_event_free (&event);
	launch_next_query (query, ISC_TRUE);
}

static isc_boolean_t
msg_contains_soa(dns_message_t *msg, dig_query_t *query) {
	isc_result_t result;
	dns_name_t *name=NULL;

	result = dns_message_findname (msg, DNS_SECTION_ANSWER,
				       query->lookup->name, dns_rdatatype_soa,
				       0, &name, NULL);
	if (result == ISC_R_SUCCESS) {
#ifdef DEBUG
		puts ("Found SOA");
#endif
		return (ISC_TRUE);
	} else {
#ifdef DEBUG
		printf ("Didn't find SOA, result=%d:%s\n",
			result, dns_result_totext(result));
#endif
		return (ISC_FALSE);
	}
	
}

static void
recv_done (isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent=NULL;
	dig_query_t *query=NULL;
	isc_buffer_t *b=NULL;
	dns_message_t *msg=NULL;
	isc_result_t result;
	isc_buffer_t ab;
	char abspace[MXNAME];
	isc_region_t r;
	
	UNUSED (task);

	sendcount--;
#ifdef DEBUG
	printf ("In recv_done, counter down to %d\n",sendcount);
#endif
	REQUIRE (event->ev_type == ISC_SOCKEVENT_RECVDONE);
	sevent = (isc_socketevent_t *)event;
	query = event->ev_arg;

	if (!query->lookup->pending) {
#ifdef DEBUG
		printf ("No longer pending.  Got %s\n",
			isc_result_totext (sevent->result));
#endif
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		cancel_lookup (query->lookup);
		check_next_lookup(query->lookup);
		isc_event_free (&event);
		return;
	}

	if (sevent->result == ISC_R_SUCCESS) {
		b = ISC_LIST_HEAD(sevent->bufferlist);
		ISC_LIST_DEQUEUE(sevent->bufferlist, &query->recvbuf, link);
		result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE,
					    &msg);
		check_result (result, "dns_message_create");
		result = dns_message_parse(msg, b, ISC_TRUE);
		if (result != ISC_R_SUCCESS)
			hex_dump (b);
		check_result (result, "dns_message_parse");
		if (query->lookup->xfr_q == NULL)
			query->lookup->xfr_q = query;
		if (query->lookup->xfr_q == query) {
			if (query->first_soa_rcvd &&
			    query->lookup->doing_xfr)
				printmessage(msg, ISC_FALSE);
			else
				printmessage (msg, ISC_TRUE);
		}
#ifdef DEBUG
		if (query->lookup->pending)
			puts ("Still pending.");
#endif
		if (query->lookup->doing_xfr) {
			if (!query->first_soa_rcvd) {
				if (!msg_contains_soa(msg,query)) {
					puts ("; Transfer failed.  Didn't start with SOA answer.");
					query->working = ISC_FALSE;
					check_next_lookup (query->lookup);
					isc_event_free (&event);
					return;
				}
				else {
					query->first_soa_rcvd = ISC_TRUE;
					launch_next_query (query, ISC_FALSE);
				}
			} 
			else {
				if (msg_contains_soa(msg, query)) {
					cancel_lookup (query->lookup);
					query->working = ISC_FALSE;
					check_next_lookup (query->lookup);
					isc_event_free (&event);
					return;
				}
				else {
					launch_next_query (query, ISC_FALSE);
				}
			}
		}
		else {
			query->working = ISC_FALSE;
			cancel_lookup (query->lookup);
		}
		if (!query->lookup->pending) {
			isc_buffer_init (&ab, abspace, MXNAME,
						  ISC_BUFFERTYPE_TEXT);
			check_result (result,"isc_buffer_init");
			result = isc_sockaddr_totext (&sevent->address, &ab);
			check_result (result, "isc_sockaddr_totext");
			isc_buffer_used (&ab, &r);
			printf ("; Received %u bytes from %s\n",
				b->used, r.base);
			check_next_lookup (query->lookup);
		}
		dns_message_destroy (&msg);
		isc_event_free (&event);
		return;
	}
	/* In truth, we should never get into the CANCELED routine, since
	   the cancel_lookup() routine clears the pending flag. */
	if (sevent->result == ISC_R_CANCELED) {
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		check_next_lookup(query->lookup);
		isc_event_free (&event);
		return;
	}
	fatal ("recv_done got result %s",isc_result_totext(sevent->result));
}

static void
get_address(char *hostname, in_port_t port, isc_sockaddr_t *sockaddr) {
	struct in_addr in4;
	struct in6_addr in6;
	struct hostent *he;

	if (have_ipv6 && inet_pton(AF_INET6, hostname, &in6) == 1)
		isc_sockaddr_fromin6(sockaddr, &in6, port);
	else if (inet_pton(AF_INET, hostname, &in4) == 1)
		isc_sockaddr_fromin(sockaddr, &in4, port);
	else {
		he = gethostbyname(hostname);
		if (he == NULL)
			fatal("gethostbyname() failed, h_errno = %d",
			      h_errno);
		INSIST(he->h_addrtype == AF_INET);
		isc_sockaddr_fromin(sockaddr,
				    (struct in_addr *)(he->h_addr_list[0]),
				    port);
	}
}

static void
do_lookup_tcp (dig_lookup_t *lookup) {
	dig_query_t *query;
	isc_result_t result;

#ifdef DEBUG
	puts ("Starting a TCP lookup");
#endif
	lookup->pending = ISC_TRUE;
	isc_interval_set (&lookup->interval, timeout, 0);
	result = isc_timer_create (timermgr, isc_timertype_once,
				   NULL, &lookup->interval, task,
				   connect_timeout, lookup,
				   &lookup->timer);
	check_result (result, "isc_timer_create");

	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		query->working = ISC_TRUE;
		query->waiting_connect = ISC_TRUE;
		get_address(query->servname, port, &query->sockaddr);

		result = isc_socket_create (socketmgr,
					    isc_sockaddr_pf(&query->sockaddr),
					    isc_sockettype_tcp,
					    &query->sock) ;
		check_result (result, "isc_socket_create");
		result = isc_socket_connect (query->sock,
					     &query->sockaddr, task,
					     connect_done, query);
		check_result (result, "isc_socket_connect");
	}
}

static void
do_lookup_udp (dig_lookup_t *lookup) {
	dig_query_t *query;
	isc_result_t result;

#ifdef DEBUG
	puts ("Starting a UDP lookup.");
#endif
	lookup->pending = ISC_TRUE;
	isc_interval_set (&lookup->interval, timeout, 0);
	result = isc_timer_create (timermgr, isc_timertype_once,
				   NULL, &lookup->interval, task,
				   connect_timeout, lookup,
				   &lookup->timer);
	check_result (result, "isc_timer_create");

	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		query->working = ISC_TRUE;
		query->waiting_connect = ISC_FALSE;
		get_address(query->servname, port, &query->sockaddr);

		result = isc_socket_create (socketmgr,
					    isc_sockaddr_pf(&query->sockaddr),
					    isc_sockettype_udp,
					    &query->sock) ;
		check_result (result, "isc_socket_create");
		ISC_LIST_ENQUEUE (query->recvlist, &query->recvbuf, link);
		result = isc_socket_recvv (query->sock, &query->recvlist,
					   1, task, recv_done, query);
		check_result (result, "isc_socket_recvv");
		sendcount++;
#ifdef DEBUG
		printf ("Sent count number %d\n",sendcount);
#endif
		ISC_LIST_ENQUEUE (query->sendlist, &lookup->sendbuf, link);
		result = isc_socket_sendtov(query->sock, &query->sendlist,
					    task, send_done, query,
					    &query->sockaddr, NULL);
		check_result (result, "isc_socket_sendtov");
	}
}

static void
free_lists() {
	void *ptr;
	dig_lookup_t *l;
	dig_query_t *q;
	dig_server_t *s;

	l = ISC_LIST_HEAD(lookup_list);
	while (l != NULL) {
		q = ISC_LIST_HEAD(l->q);
		while (q != NULL) {
			if (q->sock != NULL)
				isc_socket_detach (&q->sock);
			if (ISC_LINK_LINKED (&q->recvbuf, link))
				ISC_LIST_DEQUEUE (q->recvlist,
						  &q->recvbuf, link);
			if (ISC_LINK_LINKED (&q->lengthbuf, link))
				ISC_LIST_DEQUEUE (q->lengthlist,
						  &q->lengthbuf, link);
			isc_buffer_invalidate (&q->recvbuf);
			isc_buffer_invalidate (&q->lengthbuf);
			ptr = q;
			q = ISC_LIST_NEXT(q, link);
			isc_mem_free (mctx, ptr);
		}
		if (l->sendmsg != NULL)
			dns_message_destroy (&l->sendmsg);
		if (l->timer != NULL)
			isc_timer_detach (&l->timer);
		ptr = l;
		l = ISC_LIST_NEXT(l, link);
		isc_mem_free (mctx, ptr);
	}
	s = ISC_LIST_HEAD(server_list);
	while (s != NULL) {
		ptr = s;
		s = ISC_LIST_NEXT(s, link);
		isc_mem_free (mctx, ptr);
	}
	dns_name_invalidate (&rootorg);
	if (socketmgr != NULL)
		isc_socketmgr_destroy (&socketmgr);
	if (timermgr != NULL)
		isc_timermgr_destroy (&timermgr);
	if (task != NULL)
		isc_task_detach (&task);
	if (taskmgr != NULL)
		isc_taskmgr_destroy (&taskmgr);
}

int
main (int argc, char **argv) {
	dig_lookup_t *lookup = NULL;

	ISC_LIST_INIT(lookup_list);
	ISC_LIST_INIT(server_list);

	setup_libs();
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
	return (0);
}
