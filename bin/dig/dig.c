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
#include <time.h>

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

extern ISC_LIST(dig_lookup_t) lookup_list;
extern ISC_LIST(dig_server_t) server_list;

extern isc_boolean_t tcp_mode, have_ipv6, show_details,
	usesearch;
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
extern char fixeddomain[MXNAME];
#ifdef TWIDDLE
extern isc_boolean_t twiddle;
#endif

isc_boolean_t short_form = ISC_FALSE;
isc_boolean_t ns_search_only = ISC_FALSE;
isc_boolean_t comments = ISC_TRUE, section_question = ISC_TRUE,
	section_answer = ISC_TRUE, section_authority = ISC_TRUE,
	section_additional = ISC_TRUE, recurse = ISC_TRUE;

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
"Usage:  dig [@server] [domain] [q-type] [q-class] {q-opt} {d-opt}\n"
"where:  server,\n"
"        domain	  are in the Domain Name System\n"
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
"                 +[no]search         (Set whether to use searchlist)\n"
"                 +[no]recursive      (Recursive mode)\n"
"                 +[no]details        (Show details of all requests)\n"
"                 +[no]nssearch       (Search for info on all authorative\n"
"                                      nameservers for the domain.)\n"
#ifdef TWIDDLE
"                 +twiddle            (Intentionally form bad requests)\n"
#endif
"                 +ndots=###          (Set NDOTS value)\n"
"                 +[no]comments       (Control display of comment lines)\n"
"                 +[no]question       (Control display of question)\n"
"                 +[no]answer         (Control display of answer)\n"
"                 +[no]authority      (Control display of authority)\n"
"                 +[no]additional     (Control display of additional)\n"
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
			     ||tcp_mode)) {
		debug("Shutting Down.", stderr);
		isc_app_shutdown();
		return;
	}
	
	if (tcp_mode) {
		setup_lookup(next);
		do_lookup_tcp(next);
	} else {
		if (lookup->retries > 1) {
			lookup->retries --;
			send_udp(lookup);
		} else {
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
	if (!short_form && query->lookup->comments) {
		diff = isc_time_microdiff(&now, &query->time_sent);
		printf(";; Query time: %ld msec\n", (long int)diff/1000);
		printf(";; Received %u bytes from %.*s\n",
		       bytes, frmsize, frm);
		time (&tnow);
		printf(";; When: %s\n", ctime(&tnow));
	}
}

void
trying(int frmsize, char *frm, dig_lookup_t *lookup) {
	if (lookup->comments)
		printf ("; Trying %.*s\n", frmsize, frm);
}


static isc_result_t
printsection(dns_message_t *msg, dns_section_t sectionid, char *section_name,
	     isc_boolean_t headers, dig_query_t *query)
{
	dns_name_t *name, *print_name;
	dns_rdataset_t *rdataset;
	isc_buffer_t target;
	isc_result_t result;
	isc_region_t r;
	dns_name_t empty_name;
	char t[4096];
	isc_boolean_t first;
	isc_boolean_t no_rdata;
	
	if (sectionid == DNS_SECTION_QUESTION)
		no_rdata = ISC_TRUE;
	else
		no_rdata = ISC_FALSE;

	if (headers && query->lookup->comments)
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

	result = ISC_R_SUCCESS;

	if (headers) {
		if (query->lookup->comments) {
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
		if (headers && query->lookup->comments)
			printf("\n");
		result = printsection(msg, DNS_SECTION_ANSWER, "ANSWER",
				      headers, query);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_AUTHORITY]) &&
	    headers && query->lookup->section_authority) {
		if (headers && query->lookup->comments)
			printf("\n");
		result = printsection(msg, DNS_SECTION_AUTHORITY, "AUTHORITY",
				      ISC_TRUE, query);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_ADDITIONAL]) &&
	    headers && query->lookup->section_additional) {
		if (headers && query->lookup->comments)
			printf("\n");
		result = printsection(msg, DNS_SECTION_ADDITIONAL,
				      "ADDITIONAL", ISC_TRUE, query);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if ((tsig != NULL) && headers && query->lookup->section_additional) {
		if (headers && query->lookup->comments)
			printf("\n");
		result = printrdata(msg, tsig, tsigname,
				    "PSEUDOSECTION TSIG", ISC_TRUE);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (headers && query->lookup->comments)
		printf("\n");

	return (result);
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
void
parse_args(isc_boolean_t is_batchfile, int argc, char **argv) {
	isc_boolean_t have_host = ISC_FALSE;
	dig_server_t *srv = NULL;
	dig_lookup_t *lookup = NULL;
	char *batchname = NULL;
	char batchline[MXNAME];
	FILE *fp = NULL;
	int bargc;
	char *bargv[16];
	int i, n;
	int adrs[4];

	for (argc--, argv++; argc > 0; argc--, argv++) {
		debug ("Main parsing %s", argv[0]);
		if (strncmp(argv[0], "@", 1) == 0) {
			srv=isc_mem_allocate(mctx, sizeof(struct dig_server));
			if (srv == NULL)
				fatal("Memory allocation failure.");
			strncpy(srv->servername, &argv[0][1], MXNAME-1);
			if ((is_batchfile) || (!have_host)) {
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
		} else if ((strcmp(argv[0], "+vc") == 0)
			   && (!is_batchfile)) {
			tcp_mode = ISC_TRUE;
		} else if ((strcmp(argv[0], "+novc") == 0)
			   && (!is_batchfile)) {
			tcp_mode = ISC_FALSE;
		} else if ((strcmp(argv[0], "+tcp") == 0)
			   && (!is_batchfile)) {
			tcp_mode = ISC_TRUE;
		} else if ((strcmp(argv[0], "+notcp") == 0)
			   && (!is_batchfile)) {
			tcp_mode = ISC_FALSE;
		} else if (strncmp(argv[0], "+domain=", 8) == 0) {
			strncpy (fixeddomain, &argv[0][8], MXNAME);
		} else if (strncmp(argv[0], "+sea", 4) == 0) {
			usesearch = ISC_TRUE;
		} else if (strncmp(argv[0], "+nosea", 6) == 0) {
			usesearch = ISC_FALSE;
		} else if (strncmp(argv[0], "+time=", 6) == 0) {
			timeout = atoi(&argv[0][6]);
			if (timeout <= 0)
				timeout = 1;
		} else if (strncmp(argv[0], "+tries=", 7) == 0) {
			tries = atoi(&argv[0][7]);
			if (tries <= 0)
				tries = 1;
		} else if (strncmp(argv[0], "+ndots=", 7) == 0) {
			ndots = atoi(&argv[0][7]);
			if (timeout <= 0)
				timeout = 1;
		} else if (strncmp(argv[0], "+rec", 4) == 0) {
			recurse = ISC_TRUE;
		} else if (strncmp(argv[0], "+norec", 6) == 0) {
			recurse = ISC_FALSE;
		} else if (strncmp(argv[0], "+ns", 3) == 0) {
			ns_search_only = ISC_TRUE;
		} else if (strncmp(argv[0], "+nons", 6) == 0) {
			ns_search_only = ISC_FALSE;
		} else if (strncmp(argv[0], "+det", 4) == 0) {
			show_details = ISC_TRUE;
		} else if (strncmp(argv[0], "+nodet", 6) == 0) {
			show_details = ISC_FALSE;
		} else if (strncmp(argv[0], "+com", 4) == 0) {
			comments = ISC_TRUE;
		} else if (strncmp(argv[0], "+nocom", 6) == 0) {
			comments = ISC_FALSE;
		} else if (strncmp(argv[0], "+que", 4) == 0) {
			section_question = ISC_TRUE;
		} else if (strncmp(argv[0], "+noque", 6) == 0) {
			section_question = ISC_FALSE;
		} else if (strncmp(argv[0], "+ans", 4) == 0) {
			section_answer = ISC_TRUE;
		} else if (strncmp(argv[0], "+noans", 6) == 0) {
			section_answer = ISC_FALSE;
		} else if (strncmp(argv[0], "+add", 4) == 0) {
			section_additional = ISC_TRUE;
		} else if (strncmp(argv[0], "+noadd", 6) == 0) {
			section_additional = ISC_FALSE;
		} else if (strncmp(argv[0], "+aut", 4) == 0) {
			section_authority = ISC_TRUE;
		} else if (strncmp(argv[0], "+noaut", 6) == 0) {
			section_authority = ISC_FALSE;
#ifdef TWIDDLE
		} else if (strncmp(argv[0], "+twiddle", 6) == 0) {
			twiddle = ISC_TRUE;
#endif
		} else if (strncmp(argv[0], "-c", 2) == 0) {
 			if (have_host) {
				if (argv[0][2]!=0) {
					strncpy(lookup->rctext, &argv[0][2],
						MXRD);
				} else {
					strncpy(lookup->rctext, argv[1],
						MXRD);
					argv++;
					argc--;
				}
			}
		} else if (strncmp(argv[0], "-t", 2) == 0) {
 			if (have_host) {
				if (argv[0][2]!=0) {
					strncpy(lookup->rttext, &argv[0][2],
						MXRD);
				} else {
					strncpy(lookup->rttext, argv[1],
						MXRD);
					argv++;
					argc--;
				}
			}
		} else if (strncmp(argv[0], "-f", 2) == 0) {
			if (argv[0][2]!=0) {
				batchname=&argv[0][2];
			} else {
				batchname=argv[1];
				argv++;
				argc--;
			}
		} else if (strncmp(argv[0], "-p", 2) == 0) {
			if (argv[0][2]!=0) {	
				port=atoi(&argv[0][2]);
			} else {
				port=atoi(argv[1]);
				argv++;
				argc--;
			}
		} else if (strncmp(argv[0], "-h", 2) == 0) {
			show_usage();
			exit (0);
		} else if (strncmp(argv[0], "-x", 2) == 0) {
			n = sscanf(argv[1], "%d.%d.%d.%d", &adrs[0], &adrs[1],
				    &adrs[2], &adrs[3]);
			if (n == 0)
				show_usage();
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
			lookup->use_my_server_list = ISC_FALSE;
			lookup->ns_search_only = ns_search_only;
			lookup->doing_xfr = ISC_FALSE;
			lookup->identify = ISC_FALSE;
			lookup->recurse = recurse;
			lookup->retries = tries;
			lookup->comments = comments;
			lookup->section_question = section_question;
			lookup->section_answer = section_answer;
			lookup->section_authority = section_authority;
			lookup->section_additional = section_additional;
			ISC_LIST_INIT(lookup->q);
			lookup->origin = NULL;
			ISC_LIST_INIT(lookup->my_server_list);
			ISC_LIST_APPEND(lookup_list, lookup, link);
			have_host = ISC_TRUE;
			argv++;
			argc--;
		} else {
 			if (have_host) {
				ENSURE(lookup != NULL);
				if (isclass(argv[0])) {
					strncpy(lookup->rctext, argv[0],
						 MXRD);
					continue;
				} else if (istype(argv[0])) {
					strncpy(lookup->rttext, argv[0], MXRD);
					continue;
				}
			}
			lookup = isc_mem_allocate(mctx, 
						  sizeof(struct dig_lookup));
			if (lookup == NULL)
				fatal("Memory allocation failure.");
			lookup->pending = ISC_FALSE;
			strncpy(lookup->textname, argv[0], MXNAME-1);
			lookup->rttext[0]=0;
			lookup->rctext[0]=0;
			lookup->namespace[0]=0;
			lookup->sendspace[0]=0;
			lookup->sendmsg=NULL;
			lookup->name=NULL;
			lookup->oname=NULL;
			lookup->timer = NULL;
			lookup->xfr_q = NULL;
			lookup->use_my_server_list = ISC_FALSE;
			lookup->doing_xfr = ISC_FALSE;
			lookup->ns_search_only = ns_search_only;
			lookup->identify = ISC_FALSE;
			lookup->recurse = recurse;
			lookup->retries = tries;
			lookup->comments = comments;
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
		lookup->use_my_server_list = ISC_FALSE;
		lookup->doing_xfr = ISC_FALSE;
		lookup->ns_search_only = ns_search_only;
		lookup->identify = ISC_FALSE;
		lookup->recurse = recurse;
		lookup->retries = tries;
		lookup->comments = comments;
		lookup->section_question = section_question;
		lookup->section_answer = section_answer;
		lookup->section_authority = section_authority;
		lookup->section_additional = section_additional;
		ISC_LIST_INIT(lookup->q);
		lookup->origin = NULL;
		ISC_LIST_INIT(lookup->my_server_list);
		strcpy(lookup->textname, ".");
		strcpy(lookup->rttext, "NS");
		lookup->rctext[0]=0;
		ISC_LIST_APPEND(lookup_list, lookup, link);
	}
}
