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

/* $Id: host.c,v 1.29.2.6 2000/09/15 22:56:14 gson Exp $ */

#include <config.h>
#include <stdlib.h>
#include <limits.h>

extern int h_errno;

#include <isc/app.h>
#include <isc/commandline.h>
#include <isc/string.h>
#include <isc/util.h>
#include <isc/task.h>

#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>

#include <dig/dig.h>

extern ISC_LIST(dig_lookup_t) lookup_list;
extern ISC_LIST(dig_server_t) server_list;
extern ISC_LIST(dig_searchlist_t) search_list;

extern isc_boolean_t have_ipv6, show_details, debugging;
extern in_port_t port;
extern unsigned int timeout;
extern isc_mem_t *mctx;
extern dns_messageid_t id;
extern dns_name_t rootorg;
extern char *rootspace[BUFSIZE];
extern isc_buffer_t rootbuf;
extern int sendcount;
extern int ndots;
extern int tries;
extern isc_boolean_t usesearch;
extern int lookup_counter;
extern int exitcode;
extern isc_taskmgr_t *taskmgr;
extern char *progname;
extern isc_task_t *global_task;

isc_boolean_t 
	short_form = ISC_TRUE,
	filter = ISC_FALSE,
	showallsoa = ISC_FALSE,
	tcpmode = ISC_FALSE,
	listed_server = ISC_FALSE;

static const char *opcodetext[] = {
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

static const char *rcodetext[] = {
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

static const char *rtypetext[] = {
	"zero",				/* 0 */
	"has address",			/* 1 */
	"name server",			/* 2 */
	"MD",				/* 3 */
	"MF",				/* 4 */
	"is an alias for",		/* 5 */
	"SOA",				/* 6 */
	"MB",				/* 7 */	
	"MG",				/* 8 */
	"MR",				/* 9 */
	"NULL",				/* 10 */
	"has well known services",	/* 11 */
	"domain name pointer",		/* 12 */
	"host information",		/* 13 */
	"MINFO",			/* 14 */
	"mail is handled by",	       	/* 15 */
	"text",				/* 16 */
	"RP",				/* 17 */
	"AFSDB",			/* 18 */
	"x25 address",			/* 19 */
	"isdn address",			/* 20 */
	"RT",				/* 21 */
	"NSAP",				/* 22 */
	"NSAP_PTR",			/* 23 */
	"has signature",		/* 24 */
	"has key",			/* 25 */
	"PX",				/* 26 */
	"GPOS",				/* 27 */
	"has AAAA address",		/* 28 */
	"LOC",				/* 29 */
	"has next record",		/* 30 */
	"EID",				/* 31 */
	"NIMLOC",			/* 32 */
	"SRV",				/* 33 */
	"ATMA",				/* 34 */
	"NAPTR",			/* 35 */
	"KX",				/* 36 */
	"CERT",				/* 37 */
	"has v6 address",		/* 38 */
	"DNAME",			/* 39 */
	"has optional information",	/* 41 */
	"has 42 record",       		/* 42 */
	"has 43 record",       		/* 43 */
	"has 44 record",       		/* 44 */
	"has 45 record",       		/* 45 */
	"has 46 record",       		/* 46 */
	"has 47 record",       		/* 47 */
	"has 48 record",       		/* 48 */
	"has 49 record",       		/* 49 */
	"has 50 record",       		/* 50 */
	"has 51 record",       		/* 51 */
	"has 52 record",       		/* 52 */
	"has 53 record",       		/* 53 */
	"has 54 record",       		/* 54 */
	"has 55 record",       		/* 55 */
	"has 56 record",       		/* 56 */
	"has 57 record",       		/* 57 */
	"has 58 record",       		/* 58 */
	"has 59 record",       		/* 59 */
	"has 60 record",       		/* 60 */
	"has 61 record",       		/* 61 */
	"has 62 record",       		/* 62 */
	"has 63 record",       		/* 63 */
	"has 64 record",       		/* 64 */
	"has 65 record",       		/* 65 */
	"has 66 record",       		/* 66 */
	"has 67 record",       		/* 67 */
	"has 68 record",       		/* 68 */
	"has 69 record",       		/* 69 */
	"has 70 record",       		/* 70 */
	"has 71 record",       		/* 71 */
	"has 72 record",       		/* 72 */
	"has 73 record",       		/* 73 */
	"has 74 record",       		/* 74 */
	"has 75 record",       		/* 75 */
	"has 76 record",       		/* 76 */
	"has 77 record",       		/* 77 */
	"has 78 record",       		/* 78 */
	"has 79 record",       		/* 79 */
	"has 80 record",       		/* 80 */
	"has 81 record",       		/* 81 */
	"has 82 record",       		/* 82 */
	"has 83 record",       		/* 83 */
	"has 84 record",       		/* 84 */
	"has 85 record",       		/* 85 */
	"has 86 record",       		/* 86 */
	"has 87 record",       		/* 87 */
	"has 88 record",       		/* 88 */
	"has 89 record",       		/* 89 */
	"has 90 record",       		/* 90 */
	"has 91 record",       		/* 91 */
	"has 92 record",       		/* 92 */
	"has 93 record",       		/* 93 */
	"has 94 record",       		/* 94 */
	"has 95 record",       		/* 95 */
	"has 96 record",       		/* 96 */
	"has 97 record",       		/* 97 */
	"has 98 record",       		/* 98 */
	"has 99 record",       		/* 99 */
	"UNIFO",			/* 100 */
	"UID",				/* 101 */
	"GID",				/* 102 */
	"UNSPEC"};			/* 103 */


static void
show_usage(void) {
	fputs(
"Usage: host [-aCdlrTwv] [-c class] [-N ndots] [-t type] [-W time]\n"
"            [-R number] hostname [server]\n"
"       -a is equivalent to -v -t *\n"
"       -c specifies query class for non-IN data\n"
"       -C compares SOA records on authorative nameservers\n"
"       -d is equivalent to -v\n"
"       -l lists all hosts in a domain, using AXFR\n"
"       -N changes the number of dots allowed before root lookup is done\n"
"       -r disables recursive processing\n"
"       -R specifies number of retries for UDP packets\n"
"       -t specifies the query type\n"
"       -T enables TCP/IP mode\n"
"       -v enables verbose output\n"
"       -w specifies to wait forever for a reply\n"
"       -W specifies how long to wait for a reply\n", stderr);
	exit(exitcode);
}				

void
dighost_shutdown(void) {
	free_lists();
	isc_app_shutdown();
}

void
received(int bytes, int frmsize, char *frm, dig_query_t *query) {
	isc_time_t now;
	isc_result_t result;
	int diff;

	if ((!short_form) || (show_details)) {
		result = isc_time_now(&now);
		check_result(result, "isc_time_now");
		diff = isc_time_microdiff(&now, &query->time_sent);
		printf("Received %u bytes from %.*s in %d ms\n",
		       bytes, frmsize, frm, diff/1000);
	}
}

void
trying(int frmsize, char *frm, dig_lookup_t *lookup) {
	UNUSED(lookup);

	if (!short_form)
		printf ("Trying \"%.*s\"\n", frmsize, frm);
}

static void
say_message(dns_name_t *name, const char *msg, dns_rdata_t *rdata,
	    dig_query_t *query)
{
	isc_buffer_t *b = NULL, *b2 = NULL;
	isc_region_t r, r2;
	isc_result_t result;

	result = isc_buffer_allocate(mctx, &b, BUFSIZE);
	check_result(result, "isc_buffer_allocate");
	result = isc_buffer_allocate(mctx, &b2, BUFSIZE);
	check_result(result, "isc_buffer_allocate");
	result = dns_name_totext(name, ISC_FALSE, b);
	check_result(result, "dns_name_totext");
	isc_buffer_usedregion(b, &r);
	result = dns_rdata_totext(rdata, NULL, b2);
	check_result(result, "dns_rdata_totext");
	isc_buffer_usedregion(b2, &r2);
	printf ( "%.*s %s %.*s", (int)r.length, (char *)r.base,
		 msg, (int)r2.length, (char *)r2.base);
	if (query->lookup->identify) {
		printf (" on server %s", query->servname);
	}
	printf ("\n");
	isc_buffer_free(&b);
	isc_buffer_free(&b2);
}


static isc_result_t
printsection(dns_message_t *msg, dns_section_t sectionid,
	     const char *section_name, isc_boolean_t headers,
	     dig_query_t *query)
{
	dns_name_t *name, *print_name;
	dns_rdataset_t *rdataset;
	dns_rdata_t rdata;
	isc_buffer_t target;
	isc_result_t result, loopresult;
	isc_region_t r;
	dns_name_t empty_name;
	char t[4096];
	isc_boolean_t first;
	isc_boolean_t no_rdata;
	const char *rtt;
	
	if (sectionid == DNS_SECTION_QUESTION)
		no_rdata = ISC_TRUE;
	else
		no_rdata = ISC_FALSE;

	if (headers)
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
#else
				UNUSED(first); /* Shut up compiler. */
#endif
			} else { 
				loopresult = dns_rdataset_first(rdataset);
				while (loopresult == ISC_R_SUCCESS) {
					dns_rdataset_current(rdataset, &rdata);
					if (rdata.type <= 103)
						rtt=rtypetext[rdata.type];
					else if (rdata.type == 249)
						rtt = "key";
					else if (rdata.type == 250)
						rtt = "signature";
					else
						rtt = "unknown";
					say_message(print_name, rtt,
						    &rdata, query);
					loopresult =
						dns_rdataset_next(rdataset);
				}
			}
		}
		if (!short_form) {
			isc_buffer_usedregion(&target, &r);
			if (no_rdata)
				printf(";%.*s", (int)r.length,
				       (char *)r.base);
			else
				printf("%.*s", (int)r.length, (char *)r.base);
		}
		
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
	   const char *set_name, isc_boolean_t headers)
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
	dns_rdataset_t *opt, *tsig = NULL;
	dns_name_t *tsigname;
	isc_result_t result = ISC_R_SUCCESS;
	isc_buffer_t *b = NULL;
	isc_region_t r;

	UNUSED(headers);

	/*
	 * Exitcode 9 means we timed out, but if we're printing a message,
	 * we much have recovered.  Go ahead and reset it to code 0, and
	 * call this a success.
	 */
	if (exitcode == 9)
		exitcode = 0;

	if (msg->rcode != 0) {
		result = isc_buffer_allocate(mctx, &b, MXNAME);
		check_result(result, "isc_buffer_allocate");
		result = dns_name_totext(query->lookup->name, ISC_FALSE,
					 b);
		check_result(result, "dns_name_totext");
		isc_buffer_usedregion(b, &r);
		printf("Host %.*s not found: %d(%s)\n",
		       (int)r.length, (char *)r.base,
		       msg->rcode, rcodetext[msg->rcode]);
		isc_buffer_free(&b);
		return (ISC_R_SUCCESS);
	}
	if (!short_form) {
		printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n",
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
		}
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
			       (unsigned int)((opt->ttl & 0x00ff0000) >> 16),
			       (unsigned int)opt->rdclass);
		tsigname = NULL;
		tsig = dns_message_gettsig(msg, &tsigname);
		if (tsig != NULL)
			printf(";; PSEUDOSECTIONS: TSIG\n");
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_QUESTION]) &&
	    !short_form) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_QUESTION, "QUESTION",
				      ISC_TRUE, query);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_ANSWER])) {
		if (!short_form)
			printf("\n");
		result = printsection(msg, DNS_SECTION_ANSWER, "ANSWER",
				      ISC_TF(!short_form), query);
		if (result != ISC_R_SUCCESS)
			return (result);
       } else {
               if ((short_form) && (listed_server)) {
                        printf("Using domain server:\n");
                        printf("Name: %s\n", query->servname);
                        result = isc_buffer_allocate(mctx, &b, MXNAME);
                        check_result(result, "isc_buffer_allocate");
                        result = isc_sockaddr_totext(&query->sockaddr, b);
                        check_result(result, "isc_sockaddr_totext");
                        printf("Address: %.*s\n",
                               (int)isc_buffer_usedlength(b),
                               (char*)isc_buffer_base(b));
                        isc_buffer_free(&b);
                        printf("Aliases: \n\n");
                }
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_AUTHORITY]) &&
	    !short_form) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_AUTHORITY, "AUTHORITY",
				      ISC_TRUE, query);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_ADDITIONAL]) &&
	    !short_form) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_ADDITIONAL,
				      "ADDITIONAL", ISC_TRUE, query);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if ((tsig != NULL) && !short_form) {
		printf("\n");
		result = printrdata(msg, tsig, tsigname,
				    "PSEUDOSECTION TSIG", ISC_TRUE);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (!short_form)
		printf("\n");

	return (result);
}

static void
parse_args(isc_boolean_t is_batchfile, int argc, char **argv) {
	isc_boolean_t recursion = ISC_TRUE;
	char hostname[MXNAME];
	char querytype[32] = "";
	char queryclass[32] = "";
	dig_server_t *srv;
	dig_lookup_t *lookup;
	int i, c, n, adrs[4];
	char store[MXNAME];

	UNUSED(is_batchfile);

	while ((c = isc_commandline_parse(argc, argv, "lvwrdt:c:aTCN:R:W:D"))
	       != EOF) {
		switch (c) {
		case 'l':
			tcpmode = ISC_TRUE;
			filter = ISC_TRUE;
			strcpy(querytype, "axfr");
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
			/*
			 * The timer routines are coded such that
			 * timeout==MAXINT doesn't enable the timer
			 */
			timeout = INT_MAX;
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
			tcpmode = ISC_TRUE;
			break;
		case 'C':
			debug("showing all SOAs");
			if (querytype[0] == 0)
				strcpy(querytype, "soa");
			if (queryclass[0] == 0)
				strcpy(queryclass, "in");
			showallsoa = ISC_TRUE;
			show_details = ISC_TRUE;
			break;
		case 'N':
			debug("setting NDOTS to %s", 
			      isc_commandline_argument);
			ndots = atoi(isc_commandline_argument);
			break;
		case 'D':
			debugging = ISC_TRUE;
			break;
		}
	}
	if (isc_commandline_index >= argc) {
		show_usage();
	}
	strncpy(hostname, argv[isc_commandline_index], MXNAME);
	if (argc > isc_commandline_index + 1) {
		srv = isc_mem_allocate(mctx, sizeof(struct dig_server));
		if (srv == NULL)
			fatal("Memory allocation failure.");
		strncpy(srv->servername,
			argv[isc_commandline_index+1], MXNAME-1);
		debug("server is %s", srv->servername);
		ISC_LIST_APPEND(server_list, srv, link);
		listed_server = ISC_TRUE;
	}
	
	lookup = isc_mem_allocate(mctx, sizeof(struct dig_lookup));
	if (lookup == NULL)	
		fatal("Memory allocation failure.");
	lookup->pending = ISC_FALSE;
	/* 
	 * XXXMWS Add IPv6 translation here, probably using inet_pton
	 * to extract the formatted text.
	 */
	if (strspn(hostname, "0123456789.") == strlen(hostname)) {
		lookup->textname[0] = 0;
		n = sscanf(hostname, "%d.%d.%d.%d", &adrs[0], &adrs[1],
				   &adrs[2], &adrs[3]);
		if (n == 0) {
			show_usage();
			exit(exitcode);
		}
		for (i = n - 1; i >= 0; i--) {
			snprintf(store, MXNAME/8, "%d.",
				 adrs[i]);
			strncat(lookup->textname, store, MXNAME);
		}
		strncat(lookup->textname, "in-addr.arpa.", MXNAME);
		if (querytype[0] == 0)
			strcpy(querytype, "ptr");
	} else {
		strncpy(lookup->textname, hostname, MXNAME);
	}
	if (querytype[0] == 0)
		strcpy(querytype, "a");
	if (queryclass[0] == 0)
		strcpy(queryclass, "in");
	strncpy(lookup->rttext, querytype, 32);
	strncpy(lookup->rctext, queryclass, 32);
	lookup->namespace[0] = 0;
	lookup->sendspace = NULL;
	lookup->sendmsg = NULL;
	lookup->name = NULL;
	lookup->oname = NULL;
	lookup->timer = NULL;
	lookup->xfr_q = NULL;
	lookup->origin = NULL;
	lookup->querysig = NULL;
	lookup->doing_xfr = ISC_FALSE;
	lookup->ixfr_serial = 0;
	lookup->defname = ISC_FALSE;
	lookup->identify = ISC_FALSE;
	lookup->recurse = recursion;
	lookup->ns_search_only = showallsoa;
	lookup->use_my_server_list = ISC_FALSE;
	lookup->retries = tries;
	lookup->udpsize = 0;
	lookup->nsfound = 0;
	lookup->trace = ISC_FALSE;
	lookup->trace_root = showallsoa;
	lookup->tcp_mode = tcpmode;
	lookup->new_search = ISC_TRUE;
	lookup->aaonly = ISC_FALSE;
	lookup->adflag = ISC_FALSE;
	lookup->cdflag = ISC_FALSE;
	ISC_LIST_INIT(lookup->q);
	ISC_LIST_APPEND(lookup_list, lookup, link);
	lookup->origin = NULL;
	ISC_LIST_INIT(lookup->my_server_list);

	usesearch = ISC_TRUE;
}

int
main(int argc, char **argv) {
	isc_result_t result;

	ISC_LIST_INIT(lookup_list);
	ISC_LIST_INIT(server_list);
	ISC_LIST_INIT(search_list);

	debug("main()");
	progname = argv[0];
	setup_libs();
	parse_args(ISC_FALSE, argc, argv);
	setup_system();
	result = isc_app_onrun(mctx, global_task, onrun_callback, NULL);
	check_result(result, "isc_app_onrun");
	isc_app_run();
	/*
	 * XXXMWS This code should really NOT be bypassed.  However,
	 * until the proper code can be added to handle SIGTERM/INT
	 * correctly, just exit out "hard" and deal as best we can.
	 */
#if 0
	if (taskmgr != NULL) {
		debug("freeing taskmgr");
		isc_taskmgr_destroy(&taskmgr);
        }
	if (isc_mem_debugging)
		isc_mem_stats(mctx, stderr);
	isc_app_finish();
	if (mctx != NULL)
		isc_mem_destroy(&mctx);	
#endif
	return (0);
}

