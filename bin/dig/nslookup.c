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

#include <stdlib.h>

extern int h_errno;

#include <isc/app.h>
#include <isc/string.h>
#include <isc/util.h>
#include <isc/mutex.h>
#include <isc/condition.h>
#include <isc/commandline.h>

#include <dns/message.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>

#include <dig/dig.h>

extern ISC_LIST(dig_lookup_t) lookup_list;
extern ISC_LIST(dig_server_t) server_list;
extern ISC_LIST(dig_searchlist_t) search_list;

extern isc_boolean_t tcp_mode, have_ipv6, show_details,
	usesearch, trace, qr;
extern in_port_t port;
extern unsigned int timeout;
extern isc_mem_t *mctx;
extern isc_taskmgr_t *taskmgr;
extern isc_task_t *task;
extern isc_timermgr_t *timermgr;
extern isc_socketmgr_t *socketmgr;
extern dns_messageid_t id;
extern char *rootspace[BUFSIZE];
extern isc_buffer_t rootbuf;
extern int sendcount;
extern int ndots;
extern int tries;
extern int lookup_counter;
extern char fixeddomain[MXNAME];
#ifdef TWIDDLE
extern isc_boolean_t twiddle;
#endif
extern int exitcode;

isc_boolean_t short_form = ISC_FALSE, printcmd = ISC_TRUE,
	filter = ISC_FALSE, showallsoa = ISC_FALSE;

isc_uint16_t bufsize = 0;
isc_boolean_t identify = ISC_FALSE,
	trace = ISC_FALSE, ns_search_only = ISC_FALSE,
	forcecomment = ISC_FALSE, stats = ISC_TRUE,
	comments = ISC_TRUE, section_question = ISC_TRUE,
	section_answer = ISC_TRUE, section_authority = ISC_TRUE,
	section_additional = ISC_TRUE, recurse = ISC_TRUE,
	defname = ISC_TRUE, aaonly = ISC_FALSE;
isc_mutex_t lock;
isc_condition_t cond;
isc_boolean_t busy = ISC_FALSE, arg_lookup = ISC_FALSE;


static char *opcodetext[] = {
	"QUERY",
	"IQUERY",
	"STATUS",
	"RESERVED3",
	"NOTIFY",
	"UPDATE",
	"RESERVED6",
	"RESERVED7",
	"RESERVED8",
	"RESERVED9",
	"RESERVED10",
	"RESERVED11",
	"RESERVED12",
	"RESERVED13",
	"RESERVED14",
	"RESERVED15"
};

static char *rcodetext[] = {
	"NOERROR",
	"FORMERR",
	"SERVFAIL",
	"NXDOMAIN",
	"NOTIMPL",
	"REFUSED",
	"YXDOMAIN",
	"YXRRSET",
	"NXRRSET",
	"NOTAUTH",
	"NOTZONE",
	"RESERVED11",
	"RESERVED12",
	"RESERVED13",
	"RESERVED14",
	"RESERVED15",
	"BADVERS"
};

static void
show_usage() {
	fputs (
"Usage:\n"
, stderr);
}				

void
check_next_lookup(dig_lookup_t *lookup) {
	dig_lookup_t *next;
	dig_query_t *query;
	isc_boolean_t still_working=ISC_FALSE;
	
	debug("In check_next_lookup", stderr);
	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		if (query->working) {
			debug("Still have a worker.", stderr);
			still_working=ISC_TRUE;
		}
	}
	if (still_working)
		return;

	next = ISC_LIST_NEXT(lookup, link);
	debug ("Have %d retries left for %s\n",
	       lookup->retries, lookup->textname);
	if ((next == NULL)&&((lookup->retries <= 1)
			     ||tcp_mode || !lookup->pending)) {
		debug("Shutting Down.", stderr);
		isc_mutex_lock(&lock);
		busy = ISC_FALSE;
		isc_condition_signal(&cond);
		isc_mutex_unlock(&lock);
		return;
	}
	
	if (tcp_mode) {
		setup_lookup(next);
		do_lookup_tcp(next);
	} else {
		if ((lookup->retries > 1) && (lookup->pending)) {
			lookup->retries --;
			send_udp(lookup);
		} else {
			ENSURE (next != NULL);
			setup_lookup(next);
			do_lookup_udp(next);
		}
	}
}

void
received(int bytes, int frmsize, char *frm, dig_query_t *query) {
	isc_uint64_t diff;
	isc_time_t now;
	isc_result_t result;
	time_t tnow;

	result = isc_time_now(&now);
	check_result (result, "isc_time_now");
	
	if (query->lookup->stats) {
		diff = isc_time_microdiff(&now, &query->time_sent);
		printf(";; Query time: %ld msec\n", (long int)diff/1000);
		printf(";; SERVER: %.*s\n", frmsize, frm);
		time (&tnow);
		printf(";; WHEN: %s", ctime(&tnow));
		printf (";; MSG SIZE  rcvd: %d\n\n", bytes);
	} else if (query->lookup->identify && !short_form) {
		diff = isc_time_microdiff(&now, &query->time_sent);
		printf(";; Received %u bytes from %.*s in %d ms\n",
		       bytes, frmsize, frm, (int)diff/1000);
	}
}

void
trying(int frmsize, char *frm, dig_lookup_t *lookup) {
	UNUSED (frmsize);
	UNUSED (frm);
	UNUSED (lookup);

}

static void
say_message(dns_rdata_t *rdata, dig_query_t *query) {
	isc_buffer_t *b=NULL, *b2=NULL;
	isc_region_t r, r2;
	isc_result_t result;
	isc_uint64_t diff;
	isc_time_t now;

	result = isc_buffer_allocate(mctx, &b, BUFSIZE);
	check_result (result, "isc_buffer_allocate");
	result = dns_rdata_totext(rdata, NULL, b);
	check_result(result, "dns_rdata_totext");
	isc_buffer_usedregion(b, &r);
	if (!query->lookup->trace && !query->lookup->ns_search_only)
		printf ( "%.*s", (int)r.length, (char *)r.base);
	else {
		result = isc_buffer_allocate(mctx, &b2, BUFSIZE);
		check_result (result, "isc_buffer_allocate");
		result = dns_rdatatype_totext(rdata->type, b2);
		check_result(result, "dns_rdatatype_totext");
		isc_buffer_usedregion(b2, &r2);
		printf ( "%.*s %.*s",(int)r2.length, (char *)r2.base, 
			 (int)r.length, (char *)r.base);
		isc_buffer_free (&b2);
	}
	if (query->lookup->identify) {
		result = isc_time_now(&now);
		check_result (result, "isc_time_now");
		diff = isc_time_microdiff(&now, &query->time_sent);
		printf (" from server %s in %d ms", query->servname,
			(int)diff/1000);
	}
	printf ("\n");
	isc_buffer_free(&b);
}

static isc_result_t
printsection(dns_message_t *msg, dns_section_t sectionid, char *section_name,
	     isc_boolean_t headers, dig_query_t *query)
{
	dns_name_t *name, *print_name;
	dns_rdataset_t *rdataset;
	isc_buffer_t target;
	isc_result_t result, loopresult;
	isc_region_t r;
	dns_name_t empty_name;
	char t[4096];
	isc_boolean_t first;
	isc_boolean_t no_rdata;
	dns_rdata_t rdata;
	
	if (sectionid == DNS_SECTION_QUESTION)
		no_rdata = ISC_TRUE;
	else
		no_rdata = ISC_FALSE;

	if (headers && query->lookup->comments && !short_form)
		printf(";; %s SECTION:\n", section_name);

	dns_name_init(&empty_name, NULL);

	result = dns_message_firstname(msg, sectionid);
	if (result == ISC_R_NOMORE)
		return (ISC_R_SUCCESS);
	else if (result != ISC_R_SUCCESS)
		return (result);

	for (;;) {
		name = NULL;
		dns_message_currentname(msg, sectionid, &name);

		isc_buffer_init(&target, t, sizeof(t));
		first = ISC_TRUE;
		print_name = name;

		for (rdataset = ISC_LIST_HEAD(name->list);
		     rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link)) {
			if (!short_form) {
				result = dns_rdataset_totext(rdataset,
							     print_name,
							     ISC_FALSE,
							     no_rdata,
							     &target);
				if (result != ISC_R_SUCCESS)
					return (result);
#ifdef USEINITALWS
				if (first) {
					print_name = &empty_name;
					first = ISC_FALSE;
				}
#endif
			} else {
				loopresult = dns_rdataset_first(rdataset);
				while (loopresult == ISC_R_SUCCESS) {
					dns_rdataset_current(rdataset, &rdata);
					say_message(&rdata, query);
					loopresult = dns_rdataset_next(
								 rdataset);
				}
			}

		}
		isc_buffer_usedregion(&target, &r);
		if (no_rdata)
			printf(";%.*s", (int)r.length, (char *)r.base);
		else
			printf("%.*s", (int)r.length, (char *)r.base);

		result = dns_message_nextname(msg, sectionid);
		if (result == ISC_R_NOMORE)
			break;
		else if (result != ISC_R_SUCCESS)
			return (result);
	}
	
	return (ISC_R_SUCCESS);
}

static isc_result_t
printrdata(dns_message_t *msg, dns_rdataset_t *rdataset, dns_name_t *owner,
	   char *set_name, isc_boolean_t headers)
{
	isc_buffer_t target;
	isc_result_t result;
	isc_region_t r;
	char t[4096];

	UNUSED(msg);
	if (headers) 
		printf(";; %s SECTION:\n", set_name);

	isc_buffer_init(&target, t, sizeof(t));

	result = dns_rdataset_totext(rdataset, owner, ISC_FALSE, ISC_FALSE,
				     &target);
	if (result != ISC_R_SUCCESS)
		return (result);
	isc_buffer_usedregion(&target, &r);
	printf("%.*s", (int)r.length, (char *)r.base);

	return (ISC_R_SUCCESS);
}

isc_result_t
printmessage(dig_query_t *query, dns_message_t *msg, isc_boolean_t headers) {
	isc_boolean_t did_flag = ISC_FALSE;
	isc_result_t result;
	dns_rdataset_t *opt, *tsig = NULL;
	dns_name_t *tsigname;

	UNUSED (query);

	/*
	 * Exitcode 9 means we timed out, but if we're printing a message,
	 * we much have recovered.  Go ahead and reset it to code 0, and
	 * call this a success.
	 */
	if (exitcode == 9)
		exitcode = 0;

	result = ISC_R_SUCCESS;

	if (query->lookup->comments && !short_form) {
		if (msg == query->lookup->sendmsg)
			printf (";; Sending:\n");
		else
			printf (";; Got answer:\n");
	}

	if (headers) {
		if (query->lookup->comments && !short_form) {
			printf(";; ->>HEADER<<- opcode: %s, status: %s, "
			       "id: %u\n",
			       opcodetext[msg->opcode], rcodetext[msg->rcode],
			       msg->id);
			printf(";; flags: ");
			if ((msg->flags & DNS_MESSAGEFLAG_QR) != 0) {
				printf("qr");
				did_flag = ISC_TRUE;
			}
			if ((msg->flags & DNS_MESSAGEFLAG_AA) != 0) {
				printf("%saa", did_flag ? " " : "");
				did_flag = ISC_TRUE;
				if ((msg->flags & DNS_MESSAGEFLAG_TC) != 0) {
					printf("%stc", did_flag ? " " : "");
					did_flag = ISC_TRUE;
				}	
				if ((msg->flags & DNS_MESSAGEFLAG_RD) != 0) {
					printf("%srd", did_flag ? " " : "");
					did_flag = ISC_TRUE;
				}
				if ((msg->flags & DNS_MESSAGEFLAG_RA) != 0) {
					printf("%sra", did_flag ? " " : "");
					did_flag = ISC_TRUE;
				}
				if ((msg->flags & DNS_MESSAGEFLAG_AD) != 0) {
					printf("%sad", did_flag ? " " : "");
					did_flag = ISC_TRUE;
				}
				if ((msg->flags & DNS_MESSAGEFLAG_CD) != 0) {
					printf("%scd", did_flag ? " " : "");
					did_flag = ISC_TRUE;
				}
			
				printf("; QUERY: %u, ANSWER: %u, "
				       "AUTHORITY: %u, ADDITIONAL: %u\n",
				       msg->counts[DNS_SECTION_QUESTION],
				       msg->counts[DNS_SECTION_ANSWER],
				       msg->counts[DNS_SECTION_AUTHORITY],
				       msg->counts[DNS_SECTION_ADDITIONAL]);
			}
			opt = dns_message_getopt(msg);
			if (opt != NULL)
				printf(";; EDNS: version: %u, udp=%u\n",
				       (unsigned int)((opt->ttl & 
						       0x00ff0000) >> 16),
				       (unsigned int)opt->rdclass);
			tsigname = NULL;
			tsig = dns_message_gettsig(msg, &tsigname);
			if (tsig != NULL)
				printf(";; PSEUDOSECTIONS: TSIG\n");
		}
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_QUESTION]) &&
	    headers && query->lookup->section_question) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_QUESTION, "QUESTION",
				      ISC_TRUE, query);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_ANSWER]) && 
	    query->lookup->section_answer ) {
		if (headers && query->lookup->comments && !short_form)
			printf("\n");
		result = printsection(msg, DNS_SECTION_ANSWER, "ANSWER",
				      headers, query);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if ((! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_AUTHORITY]) &&
	    headers && query->lookup->section_authority) || 
	    ( ISC_LIST_EMPTY(msg->sections[DNS_SECTION_ANSWER]) &&
	      headers && query->lookup->section_answer &&
	      query->lookup->trace )) {
		if (headers && query->lookup->comments && !short_form)
			printf("\n");
		result = printsection(msg, DNS_SECTION_AUTHORITY, "AUTHORITY",
				      ISC_TRUE, query);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_ADDITIONAL]) &&
	    headers && query->lookup->section_additional) {
		if (headers && query->lookup->comments && !short_form)
			printf("\n");
		result = printsection(msg, DNS_SECTION_ADDITIONAL,
				      "ADDITIONAL", ISC_TRUE, query);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if ((tsig != NULL) && headers && query->lookup->section_additional) {
		if (headers && query->lookup->comments && !short_form)
			printf("\n");
		result = printrdata(msg, tsig, tsigname,
				    "PSEUDOSECTION TSIG", ISC_TRUE);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (headers && query->lookup->comments && !short_form)
		printf("\n");

	return (result);
}

static void
printgreeting(int argc, char **argv) {
	int i = 1;

	if (printcmd) {
		puts ("");
		printf ("; <<>> DiG 9.0 <<>>");
		while (i < argc) {
			printf (" %s", argv[i++]);
		}
		puts ("");
		printf (";; global options: %s %s\n",
			short_form?"short_form":"",
			printcmd?"printcmd":"");
	}
}

/*
 * Reorder an argument list so that server names all come at the end.
 * This is a bit of a hack, to allow batch-mode processing to properly
 * handle the server options.
 */
static void
reorder_args(int argc, char *argv[]) {
	int i, j;
	char *ptr;
	int end;

	debug ("reorder_args()");
	end = argc-1;
	while (argv[end][0] == '@') {
		end--;
		if (end == 0)
			return;
	}
	debug ("arg[end]=%s",argv[end]);
	for (i=1; i<end-1; i++) {
		if (argv[i][0]=='@') {
			debug ("Arg[%d]=%s", i, argv[i]);
			ptr=argv[i];
			for (j=i+1; j<end; j++) {
				debug ("Moving %s to %d", argv[j], j-1);
				argv[j-1]=argv[j];
			}
			debug ("Moving %s to end, %d", ptr, end-1);
			argv[end-1]=ptr;
			end--;
			if (end < 1)
				return;
		}
	}
}

void
parse_args(isc_boolean_t is_batchfile, int argc, char **argv) {
	isc_boolean_t have_host=ISC_FALSE,
		recursion=ISC_TRUE,
		xfr_mode=ISC_FALSE,
		nsfind=ISC_FALSE;
	char hostname[MXNAME];
	char querytype[32]="";
	char queryclass[32]="";
	dig_server_t *srv;
	dig_lookup_t *lookup;
	int i, c, n, adrs[4];
	char store[MXNAME];

	UNUSED(is_batchfile);

	while ((c = isc_commandline_parse(argc, argv, "lvwrdt:c:aTCN:R:W:"))
	       != EOF) {
		switch (c) {
		case 'l':
			tcp_mode = ISC_TRUE;
			xfr_mode = ISC_TRUE;
			filter = ISC_TRUE;
			strcpy (querytype, "axfr");
			break;
		case 'v':
		case 'd':
			short_form = ISC_FALSE;
			break;
		case 'r':
			recursion = ISC_FALSE;
			break;
		case 't':
			strncpy (querytype, isc_commandline_argument, 32);
			break;
		case 'c':
			strncpy (queryclass, isc_commandline_argument, 32);
			break;
		case 'a':
			strcpy (querytype, "any");
			short_form = ISC_FALSE;
			break;
		case 'w':
			/* XXXMWS This should be a system-indep.
			 * thing! */
			timeout = 32767;
			break;
		case 'W':
			timeout = atoi(isc_commandline_argument);
			if (timeout < 1)
				timeout = 1;
			break;
		case 'R':
			tries = atoi(isc_commandline_argument);
			if (tries < 1)
				tries = 1;
			break;
		case 'T':
			tcp_mode = ISC_TRUE;
			break;
		case 'C':
			debug ("Showing all SOA's");
			if (querytype[0] == 0)
				strcpy (querytype, "soa");
			if (queryclass[0] == 0)
				strcpy (queryclass, "in");
			nsfind = ISC_TRUE;
			showallsoa = ISC_TRUE;
			show_details = ISC_TRUE;
			break;
		case 'N':
			debug ("Setting NDOTS to %s", 
			       isc_commandline_argument);
			ndots = atoi(isc_commandline_argument);
			break;
		}
	}
	if (isc_commandline_index >= argc) {
		show_usage();
	}
	strncpy (hostname, argv[isc_commandline_index], MXNAME);
	if (argc > isc_commandline_index+1) {
			srv=isc_mem_allocate(mctx, sizeof(struct dig_server));
			if (srv == NULL)
				fatal ("Memory allocation failure.");
			strncpy(srv->servername,
				argv[isc_commandline_index+1], MXNAME-1);
			debug("Server is %s", srv->servername);
			ISC_LIST_APPEND(server_list, srv, link);
	}
	
	lookup_counter++;
	if (lookup_counter > LOOKUP_LIMIT)
		fatal ("Too many lookups.");
	lookup = isc_mem_allocate (mctx, 
				   sizeof(struct dig_lookup));
	if (lookup == NULL)	
		fatal ("Memory allocation failure.");
	lookup->pending = ISC_FALSE;
	/* 
	 * XXXMWS Add IPv6 translation here, probably using inet_pton
	 * to extract the formatted text.
	 */
	if (strcspn(hostname, "0123456789.") != strlen(hostname)) {
		lookup->textname[0]=0;
		n = sscanf(hostname, "%d.%d.%d.%d", &adrs[0], &adrs[1],
				   &adrs[2], &adrs[3]);
		if (n==0) {
			show_usage();
			exit (exitcode);
		}
		for (i = n - 1; i >= 0; i--) {
			snprintf(store, MXNAME/8, "%d.",
				 adrs[i]);
			strncat(lookup->textname, store, MXNAME);
		}
		strncat(lookup->textname, "in-addr.arpa.", MXNAME);
		if (querytype[0] == 0)
			strcpy (querytype, "ptr");
	} else
		strncpy (lookup->textname, hostname, MXNAME);
	if (querytype[0] == 0)
		strcpy (querytype, "a");
	if (queryclass[0] == 0)
		strcpy (queryclass, "in");
	strncpy (lookup->rttext, querytype, 32);
	strncpy (lookup->rctext, queryclass, 32);
	lookup->namespace[0]=0;
	lookup->sendspace[0]=0;
	lookup->sendmsg=NULL;
	lookup->name=NULL;
	lookup->oname=NULL;
	lookup->timer = NULL;
	lookup->xfr_q = NULL;
	lookup->origin = NULL;
	lookup->doing_xfr = ISC_FALSE;
	lookup->defname = ISC_FALSE;
	lookup->identify = ISC_FALSE;
	lookup->recurse = recursion;
	lookup->ns_search_only = showallsoa;
	lookup->use_my_server_list = ISC_FALSE;
	lookup->retries = tries;
	lookup->nsfound = 0;
	lookup->trace = showallsoa;
	lookup->trace_root = ISC_FALSE;
	ISC_LIST_INIT(lookup->q);
	ISC_LIST_APPEND(lookup_list, lookup, link);
	lookup->origin = NULL;
	ISC_LIST_INIT(lookup->my_server_list);
	have_host = ISC_TRUE;
}

int
main(int argc, char **argv) {
	dig_lookup_t *lookup = NULL;
	isc_result_t result;
#ifdef TWIDDLE
	FILE *fp;
	int i, p;
#endif

	ISC_LIST_INIT(lookup_list);
	ISC_LIST_INIT(server_list);
	ISC_LIST_INIT(search_list);

#ifdef TWIDDLE
	fp = fopen("/dev/urandom", "r");
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
	result = isc_mutex_init(&lock);
	check_result(result, "isc_mutex_init");
	result = isc_condition_init(&cond);
	check_result(result, "isc_condition_init");
	result = isc_mutex_trylock(&lock);
	check_result(result, "isc_mutex_trylock");

	parse_args(ISC_FALSE, argc, argv);
	setup_system();

	if (arg_lookup) {
		busy = ISC_TRUE;
		lookup = ISC_LIST_HEAD(lookup_list);
		setup_lookup(lookup);
		if (tcp_mode)
			do_lookup_tcp(lookup);
		else
			do_lookup_udp(lookup);
	}

	while (busy) {
		result = isc_condition_wait(&cond, &lock);
		check_result(result, "isc_condition_wait");
#ifdef NEVER
		if (!arg_lookup)
			get_next_command();
#endif
	}

	debug ("Fell through app_run");
	free_lists(0);
	isc_mutex_destroy(&lock);
	isc_condition_destroy(&cond);
	
	return (0);
}

