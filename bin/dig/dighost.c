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
ISC_LIST(dig_searchlist_t) search_list;

isc_boolean_t tcp_mode = ISC_FALSE, have_ipv6 = ISC_FALSE,
	free_now = ISC_FALSE, show_details = ISC_FALSE, usesearch=ISC_TRUE;
#ifdef TWIDDLE
isc_boolean_t twiddle = ISC_FALSE;
#endif
in_port_t port = 53;
unsigned int timeout = 5;
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
int ndots = -1;
int tries = 3;
char fixeddomain[MXNAME]="";

static void
free_lists(void);

static int
count_dots(char *string) {
	char *s;
	int i=0;

	s = string;
	while (*s != 0) {
		if (*s == '.')
			i++;
		s++;
	}
	return (i);
}

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
#ifdef NEVER
	isc_app_shutdown();
	free_lists();
	if (mctx != NULL) {
#ifdef MEMDEBUG
		isc_mem_stats(mctx,stderr);
#endif
		isc_mem_destroy(&mctx);
	}
#endif
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
	dig_searchlist_t *search;
	dig_lookup_t *l;
	isc_boolean_t get_servers;


	if (fixeddomain[0]!=0) {
		search = isc_mem_allocate( mctx, sizeof(struct dig_server));
		if (search == NULL)
			fatal("Memory allocation failure.");
		strncpy(search->origin, fixeddomain, MXNAME - 1);
		ISC_LIST_PREPEND(search_list, search, link);
	}

	debug ("setup_system()");
	id = getpid() << 8;
	get_servers = (server_list.head == NULL);
	fp = fopen (RESOLVCONF, "r");
	if (fp != NULL) {
		while (fgets(rcinput, MXNAME, fp) != 0) {
			ptr = strtok (rcinput, " \t\r\n");
			if (ptr != NULL) {
				if (get_servers &&
				    strcasecmp(ptr, "nameserver") == 0) {
					debug ("Got a nameserver line");
					ptr = strtok (NULL, " \t\r\n");
					if (ptr != NULL) {
						srv = isc_mem_allocate(mctx,
						   sizeof(struct dig_server));
						if (srv == NULL)
							fatal("Memory "
							      "allocation "
							      "failure.");
							strncpy((char *)srv->
								servername,
								ptr,
								MXNAME - 1);
							ISC_LIST_APPEND
								(server_list,
								 srv, link);
					}
				} else if (strcasecmp(ptr,"options") == 0) {
					ptr = strtok(NULL, " \t\r\n");
					if (ptr != NULL) {
						if ((strncasecmp(ptr, "ndots:",
							    6) == 0) &&
						    (ndots == -1)) {
							ndots = atoi(
							      &ptr[6]);
							debug ("ndots is "
							       "%d.",
							       ndots);
						}
					}
				} else if ((strcasecmp(ptr,"search") == 0)
					   && usesearch){
					while ((ptr = strtok(NULL, " \t\r\n"))
					       != NULL) {
						search = isc_mem_allocate(
						   mctx, sizeof(struct
								dig_server));
						if (search == NULL)
							fatal("Memory "
							      "allocation "
							      "failure.");
						strncpy(search->
							origin,
							ptr,
							MXNAME - 1);
						ISC_LIST_APPEND
							(search_list,
							 search,
							 link);
					}
				} else if ((strcasecmp(ptr,"domain") == 0) &&
					   (fixeddomain[0] == 0 )){
					while ((ptr = strtok(NULL, " \t\r\n"))
					       != NULL) {
						search = isc_mem_allocate(
						   mctx, sizeof(struct
								dig_server));
						if (search == NULL)
							fatal("Memory "
							      "allocation "
							      "failure.");
						strncpy(search->
							origin,
							ptr,
							MXNAME - 1);
						ISC_LIST_PREPEND
							(search_list,
							 search,
							 link);
					}
				}
						
			}
		}
		fclose (fp);
	}

	if (ndots == -1)
		ndots = 1;

	if (server_list.head == NULL) {
		srv = isc_mem_allocate(mctx, sizeof(dig_server_t));
		if (srv == NULL)
			fatal("Memory allocation failure");
		strcpy(srv->servername, "127.0.0.1");
		ISC_LIST_APPEND(server_list, srv, link);
	}

	for (l = ISC_LIST_HEAD(lookup_list) ;
	     l != NULL;
	     l = ISC_LIST_NEXT(l, link) ) {
	     l -> origin = ISC_LIST_HEAD(search_list);
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
					lookup->oname=NULL;
					lookup->timer = NULL;
					lookup->xfr_q = NULL;
					lookup->doing_xfr = ISC_FALSE;
					lookup->identify = ISC_TRUE;
					lookup->recurse = query->lookup->
						recurse;
					lookup->ns_search_only = 
						ISC_FALSE;
					lookup->use_my_server_list = 
						ISC_TRUE;
					lookup->retries = tries;
					lookup->comments =
						query->lookup->comments;
					lookup->section_question =
						query->lookup->
						section_question;
					lookup->section_answer =
						query->lookup->
						section_answer;
					lookup->section_authority =
						query->lookup->
						section_authority;
					lookup->section_additional =
						query->lookup->
						section_additional;
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
					strncpy(srv->servername, (char *)r.base,
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

static void
next_origin(dns_message_t *msg, dig_query_t *query) {
	dig_lookup_t *lookup;
	dig_server_t *srv;
	dig_server_t *s;

	UNUSED (msg);

	debug ("next_origin()"); 
	debug ("Following up %s", query->lookup->textname);

	if (query->lookup->origin == NULL) { /*Then we just did rootorg;
					      there's nothing left. */
		debug ("Made it to the root whith nowhere to go.");
		return;
	}
	lookup = isc_mem_allocate
		(mctx, sizeof(struct dig_lookup));
	if (lookup == NULL)
		fatal ("Memory allocation failure.");
	lookup->pending = ISC_FALSE;
	strncpy (lookup->textname, query->lookup-> textname, MXNAME);
	strncpy (lookup->rttext, query->lookup-> rttext, 32);
	strncpy (lookup->rctext, query->lookup-> rctext, 32);
	lookup->namespace[0]=0;
	lookup->sendspace[0]=0;
	lookup->sendmsg=NULL;
	lookup->name=NULL;
	lookup->oname=NULL;
	lookup->timer = NULL;
	lookup->xfr_q = NULL;
	lookup->doing_xfr = ISC_FALSE;
	lookup->identify = query->lookup->identify;
	lookup->recurse = query->lookup->recurse;
	lookup->ns_search_only = query->lookup->ns_search_only;
	lookup->use_my_server_list = query->lookup->use_my_server_list;
	lookup->origin = ISC_LIST_NEXT(query->lookup->origin,link);
	lookup->retries = tries;
	lookup->comments = query->lookup->comments;
	lookup->section_question = query->lookup->section_question;
	lookup->section_answer = query->lookup->section_answer;
	lookup->section_authority = query->lookup->section_authority;
	lookup->section_additional = query->lookup->section_additional;
	ISC_LIST_INIT(lookup->my_server_list);
	ISC_LIST_INIT(lookup->q);

	if (lookup->use_my_server_list) {
		s = ISC_LIST_HEAD(query->lookup->my_server_list);
		while (s != NULL) {
			srv = isc_mem_allocate (mctx, sizeof(struct
							     dig_server));
			if (srv == NULL)
				fatal("Memory allocation failure.");
			strncpy(srv->servername, s->servername, MXNAME);
			ISC_LIST_ENQUEUE(lookup->my_server_list, srv,
					 link);
			s = ISC_LIST_NEXT(s, link);
		}
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

}


void
setup_lookup(dig_lookup_t *lookup) {
	isc_result_t result, res2;
	int len;
	dns_rdatatype_t rdtype;
	dns_rdataclass_t rdclass;
	dig_server_t *serv;
	dig_query_t *query;
	isc_region_t r;
	isc_textregion_t tr;
	isc_buffer_t b;
	char store[MXNAME];
	
	debug("setup_lookup()");
	debug("Setting up for looking up %s @%ld->%ld", 
		lookup->textname, (long int)lookup,
		(long int)lookup->link.next);

	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER,
				    &lookup->sendmsg);
	check_result(result, "dns_message_create");


	result = dns_message_gettempname(lookup->sendmsg, &lookup->name);
	check_result(result, "dns_message_gettempname");
	dns_name_init(lookup->name, NULL);

	isc_buffer_init(&lookup->namebuf, lookup->namespace, BUFSIZE);
	isc_buffer_init(&lookup->onamebuf, lookup->onamespace, BUFSIZE);

	if (count_dots(lookup->textname) >= ndots)
		lookup->origin = NULL; /* Force root lookup */
	if (lookup->origin != NULL) {
		debug ("Trying origin %s",lookup->origin->origin);
		result = dns_message_gettempname(lookup->sendmsg,
						 &lookup->oname);
		check_result(result, "dns_message_gettempname");
		dns_name_init(lookup->oname, NULL);
		len=strlen(lookup->origin->origin);
		isc_buffer_init(&b, lookup->origin->origin, len);
		isc_buffer_add(&b, len);
		result = dns_name_fromtext(lookup->oname, &b, &rootorg,
					   ISC_FALSE, &lookup->onamebuf);
		if (result != ISC_R_SUCCESS) {
		dns_message_puttempname(lookup->sendmsg,
						&lookup->name);
			dns_message_puttempname(lookup->sendmsg,
						&lookup->oname);
			fatal("Aborting: %s is not a legal name syntax. (%s)",
			      lookup->origin->origin,
			      dns_result_totext(result));
		}
		len=strlen(lookup->textname);
		isc_buffer_init(&b, lookup->textname, len);
		isc_buffer_add(&b, len);
		result = dns_name_fromtext(lookup->name, &b, lookup->oname,
					   ISC_FALSE, &lookup->namebuf);
		if (result != ISC_R_SUCCESS) {
			dns_message_puttempname(lookup->sendmsg,
						&lookup->name);
			dns_message_puttempname(lookup->sendmsg,
						&lookup->oname);
			fatal("Aborting: %s is not a legal name syntax. (%s)",
			      lookup->textname, dns_result_totext(result));
		}
		dns_message_puttempname(lookup->sendmsg, &lookup->oname);
	} else {
		debug ("Using root origin.");
		len = strlen (lookup->textname);
		isc_buffer_init(&b, lookup->textname, len);
		isc_buffer_add(&b, len);
		result = dns_name_fromtext(lookup->name, &b, &rootorg,
					   ISC_FALSE, &lookup->namebuf);
		if (result != ISC_R_SUCCESS) {
			dns_message_puttempname(lookup->sendmsg,
						&lookup->name);
			isc_buffer_init(&b, store, MXNAME);
			res2 = dns_name_totext(&rootorg, ISC_FALSE, &b);
			check_result (res2, "dns_name_totext");
			isc_buffer_usedregion (&b, &r);
			fatal("Aborting: %s/%.*s is not a legal name syntax. "
			      "(%s)", lookup->textname, (int)r.length,
			      (char *)r.base, dns_result_totext(result));
		}
	}		
	isc_buffer_init (&b, store, MXNAME);
	dns_name_totext(lookup->name, ISC_FALSE, &b);
	isc_buffer_usedregion (&b, &r);
	trying((int)r.length, (char *)r.base, lookup);
#ifdef DEBUG
	if (dns_name_isabsolute(lookup->name))
		debug ("This is an absolute name.");
	else
		debug ("This is a relative name (which is wrong).");
#endif

	if (lookup->rctext[0] == 0)
		strcpy(lookup->rctext, "IN");
	if (lookup->rttext[0] == 0)
		strcpy(lookup->rttext, "A");

	lookup->sendmsg->id = id++;
	lookup->sendmsg->opcode = dns_opcode_query;
	if (lookup->recurse) {
		debug ("Recursive query");
		lookup->sendmsg->flags |= DNS_MESSAGEFLAG_RD;
	}

	dns_message_addname(lookup->sendmsg, lookup->name,
			    DNS_SECTION_QUESTION);
	
	
	if (!lookup->ns_search_only) {
		tr.base=lookup->rttext;
		tr.length=strlen(lookup->rttext);
	} else {
		tr.base="NS";
		tr.length=2;
	}
	result = dns_rdatatype_fromtext(&rdtype, &tr);
	check_result(result, "dns_rdatatype_fromtext");
	if (rdtype == dns_rdatatype_axfr) {
		lookup->doing_xfr = ISC_TRUE;
		/*
		 * Force TCP mode if we're doing an xfr.
		 */
		tcp_mode = ISC_TRUE;
	}
	if (!lookup->ns_search_only) {
		tr.base=lookup->rctext;
		tr.length=strlen(lookup->rctext);
	} else {
		tr.base="IN";
		tr.length=2;
	}
	result = dns_rdataclass_fromtext(&rdclass, &tr);
	check_result(result, "dns_rdataclass_fromtext");
	add_type(lookup->sendmsg, lookup->name, rdclass, rdtype);

	isc_buffer_init(&lookup->sendbuf, lookup->sendspace, COMMSIZE);
	debug ("Starting to render the message");
	result = dns_message_renderbegin(lookup->sendmsg, &lookup->sendbuf);
	check_result(result, "dns_message_renderbegin");
	result = dns_message_rendersection(lookup->sendmsg,
					   DNS_SECTION_QUESTION, 0);
	check_result(result, "dns_message_rendersection");
	result = dns_message_renderend(lookup->sendmsg);
	check_result(result, "dns_message_renderend");
	debug ("Done rendering.");

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
	lookup->retries = 0;
	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		if (query->working) {
			isc_socket_cancel(query->sock, task,
					  ISC_SOCKCANCEL_ALL);
		}
	}
}

static void
recv_done(isc_task_t *task, isc_event_t *event);

static void
connect_timeout(isc_task_t *task, isc_event_t *event);

void
send_udp(dig_lookup_t *lookup) {
	dig_query_t *query;
	isc_result_t result;

	debug ("send_udp()");

	isc_interval_set(&lookup->interval, timeout, 0);
	result = isc_timer_create(timermgr, isc_timertype_once, NULL,
				  &lookup->interval, task, connect_timeout,
				  lookup, &lookup->timer);
	check_result(result, "isc_timer_create");
	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		ISC_LIST_ENQUEUE(query->recvlist, &query->recvbuf, link);
		query->working = ISC_TRUE;
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
		result = isc_time_now(&query->time_sent);
		check_result(result, "isc_time_now");
		result = isc_socket_sendtov(query->sock, &query->sendlist,
					    task, send_done, query,
					    &query->sockaddr, NULL);
		check_result(result, "isc_socket_sendtov");
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
				if (q->lookup->retries > 1)
					printf(";; Connection to server %.*s "
					       "for %s timed out.  "
					       "Retrying.\n",
					       (int)r.length, r.base,
					       q->lookup->textname);
				else
					printf(";; Connection to server %.*s "
					       "for %s timed out.  "
					       "Giving up.\n",
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
	debug ("Done with connect_timeout()");
}

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
		result = isc_time_now(&query->time_sent);
		check_result(result, "isc_time_now");
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
			else if ((msg->rcode != 0) &&
				 (query->lookup->origin != NULL)) {
				next_origin(msg, query);
				if (show_details) {
				       printmessage(query, msg, ISC_TRUE);
				}
			} else {
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
					isc_buffer_init(&ab, abspace, MXNAME);
					check_result(result,
						     "isc_buffer_init");
					result = isc_sockaddr_totext(&sevent->
								     address,
								     &ab);
					check_result(result,
						     "isc_sockaddr_totext");
					isc_buffer_usedregion(&ab, &r);
					received(b->used, r.length,
						 (char *)r.base, query);
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
			if ((msg->rcode == 0) ||
			    (query->lookup->origin == NULL)) {
				isc_buffer_init(&ab, abspace, MXNAME);
				check_result(result, "isc_buffer_init");
				result = isc_sockaddr_totext(&sevent->address,
							     &ab);
				check_result(result, "isc_sockaddr_totext");
				isc_buffer_usedregion(&ab, &r);
				received(b->used, r.length, (char *)r.base,
					 query);
			}
			query->working = ISC_FALSE;
			cancel_lookup(query->lookup);
		}
		if (!query->lookup->pending) {
			check_next_lookup(query->lookup);
		}
		dns_message_destroy(&msg);
		isc_event_free(&event);
		return;
	}
	/* In truth, we should never get into the CANCELED routine, since
	   the cancel_lookup() routine clears the pending flag. */
	if (sevent->result == ISC_R_CANCELED) {
		debug ("In cancel handler");
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		check_next_lookup(query->lookup);
		isc_event_free(&event);
		return;
	}
	isc_event_free(&event);
	fatal("recv_done got result %s",
	      isc_result_totext(sevent->result));
}

static void
get_address(char *host, in_port_t port, isc_sockaddr_t *sockaddr) {
	struct in_addr in4;
	struct in6_addr in6;
	struct hostent *he;

	debug("get_address()");

	if (have_ipv6 && inet_pton(AF_INET6, host, &in6) == 1)
		isc_sockaddr_fromin6(sockaddr, &in6, port);
	else if (inet_pton(AF_INET, host, &in4) == 1)
		isc_sockaddr_fromin(sockaddr, &in4, port);
	else {
		he = gethostbyname(host);
		if (he == NULL)
		     fatal("Couldn't look up your server host %s.  errno=%d",
			      host, h_errno);
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
	}

	send_udp(lookup);
}

static void
free_lists(void) {
	void *ptr;
	dig_lookup_t *l;
	dig_query_t *q;
	dig_server_t *s;
	dig_searchlist_t *o;

	debug("free_lists()");

	if (free_now)
		return;

	free_now = ISC_TRUE;

	l = ISC_LIST_HEAD(lookup_list);
	while (l != NULL) {
		debug ("Freeing the lookup of %s", l->textname);
		q = ISC_LIST_HEAD(l->q);
		while (q != NULL) {
			debug ("Freeing the query of %s", q->servname);
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
				debug ("Freeing lookup server %s",
				       s->servername);
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
	debug ("Starting to free things globally.");
	s = ISC_LIST_HEAD(server_list);
	while (s != NULL) {
		debug ("Freeing global server list entry %s",
		       s->servername);
		ptr = s;
		s = ISC_LIST_NEXT(s, link);
		isc_mem_free(mctx, ptr);
	}
	o = ISC_LIST_HEAD(search_list);
	while (o != NULL) {
		debug ("Freeing origin list entry %s",
		       o->origin);
		ptr = o;
		o = ISC_LIST_NEXT(o, link);
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

#ifdef MEMDEBUG
	isc_mem_stats(mctx, stderr);
#endif
	isc_app_finish();
	if (mctx != NULL)
		isc_mem_destroy(&mctx);

	exit(0);
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
	ISC_LIST_INIT(search_list);

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
	exit (1); /* Should never get here. */
}
