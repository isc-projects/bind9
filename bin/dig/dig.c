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

#include <dns/message.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>

#include <dig/dig.h>

extern ISC_LIST(dig_lookup_t) lookup_list;
extern ISC_LIST(dig_server_t) server_list;
extern ISC_LIST(dig_searchlist_t) search_list;

extern isc_boolean_t have_ipv6, show_details, specified_source,
	usesearch, qr;
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
extern isc_sockaddr_t bind_address;

isc_boolean_t short_form = ISC_FALSE, printcmd = ISC_TRUE;

isc_uint16_t bufsize = 0;
isc_boolean_t identify = ISC_FALSE,
	trace = ISC_FALSE, ns_search_only = ISC_FALSE,
	forcecomment = ISC_FALSE, stats = ISC_TRUE,
	comments = ISC_TRUE, section_question = ISC_TRUE,
	section_answer = ISC_TRUE, section_authority = ISC_TRUE,
	section_additional = ISC_TRUE, recurse = ISC_TRUE,
	defname = ISC_TRUE, aaonly = ISC_FALSE, tcpmode = ISC_FALSE;


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
"Usage:  dig [@global-server] [domain] [q-type] [q-class] {q-opt}\n"
"        {global-d-opt} host [@local-server] {local-d-opt}\n"
"        [ host [@local-server] {local-d-opt} [...]]\n"
"Where:  domain	  are in the Domain Name System\n"
"        q-class  is one of (in,chaos,...) [default: in]\n"
"        q-type   is one of (a,any,mx,ns,soa,hinfo,axfr,txt,...) [default:a]\n"
"        q-opt    is one of:\n"
"                 -x dot-notation     (shortcut for in-addr lookups)\n"
"                 -f filename         (batch mode)\n"
"                 -p port             (specify port number)\n"
"                 -t type             (specify query type)\n"
"                 -c class            (specify query class)\n"
"        d-opt    is of the form +keyword[=value], where keyword is:\n"
"                 +[no]vc             (TCP mode)\n"
"                 +[no]tcp            (TCP mode, alternate syntax)\n"
"                 +time=###           (Set query timeout) [5]\n"
"                 +tries=###          (Set number of UDP attempts) [3]\n"
"                 +domain=###         (Set default domainname)\n"
"                 +bufsize=###        (Set EDNS0 Max UDP packet size)\n"
"                 +[no]search         (Set whether to use searchlist)\n"
"                 +[no]defname        (Set whether to use default domaon)\n"
"                 +[no]recursive      (Recursive mode)\n"
"                 +[no]aaonly         (Set AA flag in query)\n"
"                 +[no]details        (Show details of all requests)\n"
#ifdef TWIDDLE
"                 +twiddle            (Intentionally form bad requests)\n"
#endif
"                 +ndots=###          (Set NDOTS value)\n"
"                 +[no]comments       (Control display of comment lines)\n"
"                 +[no]question       (Control display of question)\n"
"                 +[no]answer         (Control display of answer)\n"
"                 +[no]authority      (Control display of authority)\n"
"                 +[no]additional     (Control display of additional)\n"
"                 +[no]short          (Disable everything except short\n"
"                                      form of answer)\n"
"                 +qr                 (Print question before sending)\n"
"        Additional d-opts subject to removal before release:\n"
"                 +[no]nssearch       (Search all authorative nameservers)\n"
"                 +[no]identify       (ID responders in short answers)\n"
"        Available but not yet completed:\n"
"                 +[no]trace          (Trace delegation down from root)\n"
"        global d-opts and servers (before host name) affect all queries.\n"
"        local d-opts and servers (after host name) affect only that lookup.\n"
, stderr);
}				

void
dighost_shutdown(void) {
	isc_app_shutdown();
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

	if (query->lookup->comments && !short_form &&
	    !query->lookup->doing_xfr) {
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
				did_flag = ISC_TRUE; }
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

/*
 * We're not using isc_commandline_parse() here since the command line
 * syntax of dig is quite a bit different from that which can be described
 * that routine.  There is a portability issue here.
 */
static void
parse_args(isc_boolean_t is_batchfile, int argc, char **argv) {
	isc_boolean_t have_host = ISC_FALSE;
	dig_server_t *srv = NULL;
	dig_lookup_t *lookup = NULL;
	char *batchname = NULL;
	char batchline[MXNAME];
	char address[MXNAME];
	FILE *fp = NULL;
	int bargc;
	char *bargv[16];
	int i, n;
	int adrs[4];
	int rc;
	char **rv;

	/*
	 * The semantics for parsing the args is a bit complex; if
	 * we don't have a host yet, make the arg apply globally,
	 * otherwise make it apply to the latest host.  This is
	 * a bit different than the previous versions, but should
	 * form a consistent user interface.
	 */

	rc = argc;
	rv = argv;
	for (rc--, rv++; rc > 0; rc--, rv++) {
		debug ("Main parsing %s", rv[0]);
		if (strncmp(rv[0], "@", 1) == 0) {
			srv=isc_mem_allocate(mctx, sizeof(struct dig_server));
			if (srv == NULL)
				fatal("Memory allocation failure.");
			strncpy(srv->servername, &rv[0][1], MXNAME-1);
			if (is_batchfile && have_host) {
				if (!lookup->use_my_server_list) {
					ISC_LIST_INIT (lookup->
						       my_server_list);
					lookup->use_my_server_list =
						ISC_TRUE;
				}
				ISC_LIST_APPEND(lookup->my_server_list,
						srv, link);
			} else {
				ISC_LIST_APPEND(server_list, srv, link);
			}
		} else if ((strcmp(rv[0], "+vc") == 0)
			   && (!is_batchfile)) {
			if (have_host)
				lookup->tcp_mode = ISC_TRUE;
			else
				tcpmode = ISC_TRUE;
		} else if ((strcmp(rv[0], "+novc") == 0)
			   && (!is_batchfile)) {
			if (have_host)
				lookup->tcp_mode = ISC_FALSE;
			else
				tcpmode = ISC_FALSE;
		} else if ((strcmp(rv[0], "+tcp") == 0)
			   && (!is_batchfile)) {
			if (have_host)
				lookup->tcp_mode = ISC_TRUE;
			else
				tcpmode = ISC_TRUE;
		} else if ((strcmp(rv[0], "+notcp") == 0)
			   && (!is_batchfile)) {
			if (have_host)
				lookup->tcp_mode = ISC_FALSE;
			else
				tcpmode = ISC_FALSE;
		} else if (strncmp(rv[0], "+domain=", 8) == 0) {
			/* Global option always */
			strncpy (fixeddomain, &rv[0][8], MXNAME);
		} else if (strncmp(rv[0], "+sea", 4) == 0) {
			/* Global option always */
			usesearch = ISC_TRUE;
		} else if (strncmp(rv[0], "+nosea", 6) == 0) {
			usesearch = ISC_FALSE;
		} else if (strncmp(rv[0], "+defn", 5) == 0) {
			if (have_host)
				lookup->defname = ISC_TRUE;
			else
				defname = ISC_TRUE;
		} else if (strncmp(rv[0], "+nodefn", 7) == 0) {
			if (have_host)
				lookup->defname = ISC_FALSE;
			else
				defname = ISC_FALSE;
		} else if (strncmp(rv[0], "+time=", 6) == 0) {
			/* Global option always */
			timeout = atoi(&rv[0][6]);
			if (timeout <= 0)
				timeout = 1;
		} else if (strncmp(rv[0], "+tries=", 7) == 0) {
			if (have_host) {
				lookup->retries = atoi(&rv[0][7]);
				if (lookup->retries <= 0)
					lookup->retries = 1;
			} else {
				tries = atoi(&rv[0][7]);
				if (tries <= 0)
					tries = 1;
			}
		} else if (strncmp(rv[0], "+buf=", 5) == 0) {
			if (have_host) {
				lookup->udpsize = atoi(&rv[0][5]);
				if (lookup->udpsize <= 0)
					lookup->udpsize = 0;
				if (lookup->udpsize > COMMSIZE)
					lookup->udpsize = COMMSIZE;
			} else {
				bufsize = atoi(&rv[0][5]);
				if (bufsize <= 0)
					bufsize = 0;
				if (bufsize > COMMSIZE)
					bufsize = COMMSIZE;
			}
		} else if (strncmp(rv[0], "+bufsize=", 9) == 0) {
			if (have_host) {
				lookup->udpsize = atoi(&rv[0][9]);
				if (lookup->udpsize <= 0)
					lookup->udpsize = 0;
				if (lookup->udpsize > COMMSIZE)
					lookup->udpsize = COMMSIZE;
			} else {
				bufsize = atoi(&rv[0][9]);
				if (bufsize <= 0)
					bufsize = 0;
				if (bufsize > COMMSIZE)
					bufsize = COMMSIZE;
			}
		} else if (strncmp(rv[0], "+ndots=", 7) == 0) {
			/* Global option always */
			ndots = atoi(&rv[0][7]);
			if (ndots < 0)
				ndots = 0;
		} else if (strncmp(rv[0], "+rec", 4) == 0) {
			if (have_host)
				lookup->recurse = ISC_TRUE;
			else
				recurse = ISC_TRUE;
		} else if (strncmp(rv[0], "+norec", 6) == 0) {
			if (have_host)
				lookup->recurse = ISC_FALSE;
			else
				recurse = ISC_FALSE;
		} else if (strncmp(rv[0], "+aa", 3) == 0) {
			if (have_host) 
				lookup->aaonly = ISC_TRUE;
			else
				aaonly = ISC_TRUE;
		} else if (strncmp(rv[0], "+noaa", 5) == 0) {
			if (have_host) 
				lookup->aaonly = ISC_FALSE;
			else
				aaonly = ISC_FALSE;
		} else if (strncmp(rv[0], "+ns", 3) == 0) {
			if (have_host) {
				lookup->ns_search_only = ISC_TRUE;
				lookup->recurse = ISC_FALSE;
				lookup->identify = ISC_TRUE;
				lookup->trace = ISC_TRUE;
				if (!forcecomment)
					lookup->comments = ISC_FALSE;
				lookup->section_additional = ISC_FALSE;
				lookup->section_authority = ISC_FALSE;
				lookup->section_question = ISC_FALSE;
			} else {
				ns_search_only = ISC_TRUE;
				recurse = ISC_FALSE;
				identify = ISC_TRUE;
				if (!forcecomment)
					comments = ISC_FALSE;
				section_additional = ISC_FALSE;
				section_authority = ISC_FALSE;
				section_question = ISC_FALSE;
			}
		} else if (strncmp(rv[0], "+nons", 6) == 0) {
			if (have_host)
				lookup->ns_search_only = ISC_FALSE;
			else
				ns_search_only = ISC_FALSE;
		} else if (strncmp(rv[0], "+tr", 3) == 0) {
			if (have_host) {
				lookup->trace = ISC_TRUE;
				lookup->trace_root = ISC_TRUE;
				lookup->recurse = ISC_FALSE;
				lookup->identify = ISC_TRUE;
				if (!forcecomment) {
					lookup->comments = ISC_FALSE;
					lookup->stats = ISC_FALSE;
				}
				lookup->section_additional = ISC_FALSE;
				lookup->section_authority = ISC_FALSE;
				lookup->section_question = ISC_FALSE;
				show_details = ISC_TRUE;
			} else {
				trace = ISC_TRUE;
				recurse = ISC_FALSE;
				identify = ISC_TRUE;
				if (!forcecomment) {
					comments = ISC_FALSE;
					stats = ISC_FALSE;
				}
				section_additional = ISC_FALSE;
				section_authority = ISC_FALSE;
				section_question = ISC_FALSE;
				show_details = ISC_TRUE;
			}
		} else if (strncmp(rv[0], "+notr", 6) == 0) {
			if (have_host) {
				lookup->trace = ISC_FALSE;
				lookup->trace_root = ISC_FALSE;
			}
			else
				trace = ISC_FALSE;
		} else if (strncmp(rv[0], "+det", 4) == 0) {
			show_details = ISC_TRUE;
		} else if (strncmp(rv[0], "+nodet", 6) == 0) {
			show_details = ISC_FALSE;
		} else if (strncmp(rv[0], "+cmd", 4) == 0) {
			printcmd = ISC_TRUE;
		} else if (strncmp(rv[0], "+nocmd", 6) == 0) {
			printcmd = ISC_FALSE;
		} else if (strncmp(rv[0], "+sho", 4) == 0) {
			short_form = ISC_TRUE;
			printcmd = ISC_FALSE;
			if (have_host) {
				lookup->section_additional = ISC_FALSE;
				lookup->section_authority = ISC_FALSE;
				lookup->section_question = ISC_FALSE;
				if (!forcecomment) {
					lookup->comments = ISC_FALSE;
					lookup->stats = ISC_FALSE;
				}
			} else {
				section_additional = ISC_FALSE;
				section_authority = ISC_FALSE;
				section_question = ISC_FALSE;
				if (!forcecomment) {
					comments = ISC_FALSE;
					stats = ISC_FALSE;
				}
			}
		} else if (strncmp(rv[0], "+nosho", 6) == 0) {
			short_form = ISC_FALSE;
		} else if (strncmp(rv[0], "+id", 3) == 0) {
			if (have_host)
				lookup->identify = ISC_TRUE;
			else
				identify = ISC_TRUE;
		} else if (strncmp(rv[0], "+noid", 5) == 0) {
			if (have_host)
				lookup->identify = ISC_FALSE;
			else
				identify = ISC_FALSE;
		} else if (strncmp(rv[0], "+com", 4) == 0) {
			if (have_host)
				lookup->comments = ISC_TRUE;
			else
				comments = ISC_TRUE;
			forcecomment = ISC_TRUE;
		} else if (strncmp(rv[0], "+nocom", 6) == 0) {
			if (have_host) {
				lookup->comments = ISC_FALSE;
				lookup->stats = ISC_FALSE;
			} else {
				comments = ISC_FALSE;
				stats = ISC_FALSE;
			}
			forcecomment = ISC_FALSE;
		} else if (strncmp(rv[0], "+sta", 4) == 0) {
			if (have_host)
				lookup->stats = ISC_TRUE;
			else
				stats = ISC_TRUE;
		} else if (strncmp(rv[0], "+nosta", 6) == 0) {
			if (have_host)
				lookup->stats = ISC_FALSE;
			else
				stats = ISC_FALSE;
		} else if (strncmp(rv[0], "+qr", 3) == 0) {
			qr = ISC_TRUE;
		} else if (strncmp(rv[0], "+noqr", 5) == 0) {
			qr = ISC_FALSE;
		} else if (strncmp(rv[0], "+que", 4) == 0) {
			if (have_host)
				lookup->section_question = ISC_TRUE;
			else
				section_question = ISC_TRUE;
		} else if (strncmp(rv[0], "+noque", 6) == 0) {
			if (have_host)
				lookup->section_question = ISC_FALSE;
			else
				section_question = ISC_FALSE;
		} else if (strncmp(rv[0], "+ans", 4) == 0) {
			if (have_host)
				lookup->section_answer = ISC_TRUE;
			else
				section_answer = ISC_TRUE;
		} else if (strncmp(rv[0], "+noans", 6) == 0) {
			if (have_host)
				lookup->section_answer = ISC_FALSE;
			else
				section_answer = ISC_FALSE;
		} else if (strncmp(rv[0], "+add", 4) == 0) {
			if (have_host)
				lookup->section_additional = ISC_TRUE;
			else
				section_additional = ISC_TRUE;
		} else if (strncmp(rv[0], "+noadd", 6) == 0) {
			if (have_host)
				lookup->section_additional = ISC_FALSE;
			else
				section_additional = ISC_FALSE;
		} else if (strncmp(rv[0], "+aut", 4) == 0) {
			if (have_host)
				lookup->section_authority = ISC_TRUE;
			else
				section_authority = ISC_TRUE;
		} else if (strncmp(rv[0], "+noaut", 6) == 0) {
			if (have_host)
				lookup->section_authority = ISC_FALSE;
			else
				section_authority = ISC_FALSE;
		} else if (strncmp(rv[0], "+all", 4) == 0) {
			if (have_host) {
				lookup->section_question = ISC_TRUE;
				lookup->section_authority = ISC_TRUE;
				lookup->section_answer = ISC_TRUE;
				lookup->section_additional = ISC_TRUE;
				lookup->comments = ISC_TRUE;
			} else {
				section_question = ISC_TRUE;
				section_authority = ISC_TRUE;
				section_answer = ISC_TRUE;
				section_additional = ISC_TRUE;
				comments = ISC_TRUE;
			}
		} else if (strncmp(rv[0], "+noall", 6) == 0) {
			if (have_host) {
				lookup->section_question = ISC_FALSE;
				lookup->section_authority = ISC_FALSE;
				lookup->section_answer = ISC_FALSE;
				lookup->section_additional = ISC_FALSE;
				lookup->comments = ISC_FALSE;
			} else {
				section_question = ISC_FALSE;
				section_authority = ISC_FALSE;
				section_answer = ISC_FALSE;
				section_additional = ISC_FALSE;
				comments = ISC_FALSE;
			}

#ifdef TWIDDLE
		} else if (strncmp(rv[0], "+twiddle", 6) == 0) {
			twiddle = ISC_TRUE;
#endif
		} else if (strncmp(rv[0], "-c", 2) == 0) {
 			if (have_host) {
				if (rv[0][2]!=0) {
					strncpy(lookup->rctext, &rv[0][2],
						MXRD);
				} else {
					strncpy(lookup->rctext, rv[1],
						MXRD);
					rv++;
					rc--;
				}
			}
		} else if (strncmp(rv[0], "-t", 2) == 0) {
 			if (have_host) {
				if (rv[0][2]!=0) {
					strncpy(lookup->rttext, &rv[0][2],
						MXRD);
				} else {
					strncpy(lookup->rttext, rv[1],
						MXRD);
					rv++;
					rc--;
				}
			}
		} else if (strncmp(rv[0], "-f", 2) == 0) {
			if (rv[0][2]!=0) {
				batchname=&rv[0][2];
			} else {
				batchname=rv[1];
				rv++;
				rc--;
			}
		} else if (strncmp(rv[0], "-p", 2) == 0) {
			if (rv[0][2]!=0) {	
				port=atoi(&rv[0][2]);
			} else {
				port=atoi(rv[1]);
				rv++;
				rc--;
			}
		} else if (strncmp(rv[0], "-b", 2) == 0) {
			if (rv[0][2]!=0) {
				strncpy(address, &rv[0][2],
					MXRD);
			} else {
				strncpy(address, rv[1],
					MXRD);
				rv++;
				rc--;
			}
			get_address(address, 0, &bind_address);
			specified_source = ISC_TRUE;
		} else if (strncmp(rv[0], "-h", 2) == 0) {
			show_usage();
			exit (exitcode);
		} else if (strncmp(rv[0], "-x", 2) == 0) {
			/*
			 *XXXMWS Only works for ipv4 now.
			 * Can't use inet_pton here, since we allow
			 * partial addresses.
			 */
			if (rc == 1) {
				show_usage();
				exit (exitcode);
			}
			n = sscanf(rv[1], "%d.%d.%d.%d", &adrs[0], &adrs[1],
				    &adrs[2], &adrs[3]);
			if (n == 0)
				show_usage();
			lookup_counter++;
			if (lookup_counter > LOOKUP_LIMIT)
				fatal ("Too many lookups.");
			lookup = isc_mem_allocate(mctx,
						  sizeof(struct dig_lookup));
			if (lookup == NULL)
				fatal("Memory allocation failure.");
			lookup->pending = ISC_FALSE;
			lookup->textname[0]=0;
			for (i = n - 1; i >= 0; i--) {
				snprintf(batchline, MXNAME/8, "%d.",
					  adrs[i]);
				strncat(lookup->textname, batchline, MXNAME);
			}
			strncat(lookup->textname, "in-addr.arpa.", MXNAME);
			debug("Looking up %s", lookup->textname);
			strcpy(lookup->rttext, "ptr");
			strcpy(lookup->rctext, "in");
			lookup->namespace[0]=0;
			lookup->sendspace[0]=0;
			lookup->sendmsg=NULL;
			lookup->name=NULL;
			lookup->oname=NULL;
			lookup->timer = NULL;
			lookup->xfr_q = NULL;
			lookup->origin = NULL;
			lookup->use_my_server_list = ISC_FALSE;
			lookup->trace = (trace || ns_search_only);
			lookup->trace_root = trace;
			lookup->ns_search_only = ns_search_only;
			lookup->doing_xfr = ISC_FALSE;
			lookup->defname = ISC_FALSE;
			lookup->identify = identify;
			lookup->recurse = recurse;
			lookup->aaonly = aaonly;
			lookup->retries = tries;
			lookup->udpsize = bufsize;
			lookup->nsfound = 0;
			lookup->comments = comments;
			lookup->tcp_mode = tcpmode;
			lookup->stats = stats;
			lookup->section_question = section_question;
			lookup->section_answer = section_answer;
			lookup->section_authority = section_authority;
			lookup->section_additional = section_additional;
			ISC_LIST_INIT(lookup->q);
			lookup->origin = NULL;
			ISC_LIST_INIT(lookup->my_server_list);
			ISC_LIST_APPEND(lookup_list, lookup, link);
			have_host = ISC_TRUE;
			rv++;
			rc--;
		} else {
 			if (have_host) {
				ENSURE(lookup != NULL);
			       if (istype(rv[0])) {
					strncpy(lookup->rttext, rv[0], MXRD);
					continue;
			       } else if (isclass(rv[0])) {
				       strncpy(lookup->rctext, rv[0],
					       MXRD);
				       continue;
			       }
			}
			lookup_counter++;
			if (lookup_counter > LOOKUP_LIMIT)
				fatal ("Too many lookups.");
			lookup = isc_mem_allocate(mctx, 
						  sizeof(struct dig_lookup));
			if (lookup == NULL)
				fatal("Memory allocation failure.");
			lookup->pending = ISC_FALSE;
			strncpy(lookup->textname, rv[0], MXNAME-1);
			lookup->rttext[0]=0;
			lookup->rctext[0]=0;
			lookup->namespace[0]=0;
			lookup->sendspace[0]=0;
			lookup->sendmsg=NULL;
			lookup->name=NULL;
			lookup->oname=NULL;
			lookup->timer = NULL;
			lookup->xfr_q = NULL;
			lookup->origin = NULL;
			lookup->use_my_server_list = ISC_FALSE;
			lookup->doing_xfr = ISC_FALSE;
			lookup->defname = ISC_FALSE;
			lookup->trace = (trace || ns_search_only);
			lookup->trace_root = trace;
			lookup->ns_search_only = ns_search_only;
			lookup->identify = identify;
			lookup->recurse = recurse;
			lookup->aaonly = aaonly;
			lookup->retries = tries;
			lookup->udpsize = bufsize;
			lookup->nsfound = 0;
			lookup->comments = comments;
			lookup->tcp_mode = tcpmode;
			lookup->stats = stats;
			lookup->section_question = section_question;
			lookup->section_answer = section_answer;
			lookup->section_authority = section_authority;
			lookup->section_additional = section_additional;
			ISC_LIST_INIT(lookup->q);
			ISC_LIST_APPEND(lookup_list, lookup, link);
			lookup->origin = NULL;
			ISC_LIST_INIT(lookup->my_server_list);
			have_host = ISC_TRUE;
			debug("Looking up %s", lookup->textname);
		}
	}
	if (batchname != NULL) {
		fp = fopen(batchname, "r");
		if (fp == NULL) {
			perror(batchname);
			if (exitcode < 10)
				exitcode = 10;
			fatal("Couldn't open specified batch file.");
		}
		while (fgets(batchline, MXNAME, fp) != 0) {
			debug ("Batch line %s", batchline);
			bargc=1;
			bargv[bargc]=strtok(batchline, " \t\r\n");
			while ((bargv[bargc] != NULL) &&
			       (bargc < 14 )) {
				bargc++;
				bargv[bargc]=strtok(NULL, " \t\r\n");
			}
			bargc--;
			bargv[0]="dig";
			reorder_args(bargc+1, (char**)bargv);
			parse_args(ISC_TRUE, bargc+1, (char**)bargv);
		}
	}
	if (lookup_list.head == NULL) {
		lookup_counter++;
		if (lookup_counter > LOOKUP_LIMIT)
			fatal ("Too many lookups.");
		lookup = isc_mem_allocate(mctx, sizeof(struct dig_lookup));
		if (lookup == NULL)
			fatal("Memory allocation failure.");
		lookup->pending = ISC_FALSE;
		lookup->rctext[0]=0;
		lookup->namespace[0]=0;
		lookup->sendspace[0]=0;
		lookup->sendmsg=NULL;
		lookup->name=NULL;
		lookup->oname=NULL;
		lookup->timer = NULL;
		lookup->xfr_q = NULL;
		lookup->origin = NULL;
		lookup->use_my_server_list = ISC_FALSE;
		lookup->doing_xfr = ISC_FALSE;
		lookup->defname = ISC_FALSE;
		lookup->trace = (trace || ns_search_only);
		lookup->trace_root = trace;
		lookup->ns_search_only = ns_search_only;
		lookup->identify = identify;
		lookup->recurse = recurse;
		lookup->aaonly = aaonly;
		lookup->retries = tries;
		lookup->udpsize = bufsize;
		lookup->nsfound = 0;
		lookup->comments = comments;
		lookup->tcp_mode = tcpmode;
		lookup->stats = stats;
		lookup->section_question = section_question;
		lookup->section_answer = section_answer;
		lookup->section_authority = section_authority;
		lookup->section_additional = section_additional;
		ISC_LIST_INIT(lookup->q);
		ISC_LIST_INIT(lookup->my_server_list);
		strcpy(lookup->textname, ".");
		strcpy(lookup->rttext, "NS");
		lookup->rctext[0]=0;
		ISC_LIST_APPEND(lookup_list, lookup, link);
	}
	if (!is_batchfile)
		printgreeting (argc, argv);
}

int
main(int argc, char **argv) {
#ifdef TWIDDLE
	FILE *fp;
	int i, p;
#endif

	ISC_LIST_INIT(lookup_list);
	ISC_LIST_INIT(server_list);
	ISC_LIST_INIT(search_list);

	debug ("dhmain()");
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
	parse_args(ISC_FALSE, argc, argv);
	setup_system();
	start_lookup();
	isc_app_run();
	free_lists(0);
	return (exitcode);
}

