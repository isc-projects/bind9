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
#include <isc/commandline.h>

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
extern ISC_LIST(dig_searchlist_t) search_list;

extern isc_boolean_t tcp_mode,
	have_ipv6;
extern in_port_t port;
extern unsigned int timeout;
extern isc_mem_t *mctx;
extern isc_taskmgr_t *taskmgr;
extern isc_task_t *task;
extern isc_timermgr_t *timermgr;
extern isc_socketmgr_t *socketmgr;
extern dns_messageid_t id;
extern dns_name_t rootorg;
extern char *rootspace[BUFSIZE];
extern isc_buffer_t rootbuf;
extern int sendcount;
extern int ndots;
extern int tries;

isc_boolean_t short_form=ISC_TRUE,
	filter=ISC_FALSE,
	showallsoa=ISC_FALSE;

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

static char *rtypetext[] = {
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
	"RT"				/* 21 */
	"NSAP",				/* 22 */
	"NSAP_PTR",			/* 23 */
	"has signature",		/* 24 */
	"has key",			/* 25 */
	"PX",				/* 26 */
	"GPOS",				/* 27 */
	"has AAAA address",		/* 28 */
	"LOC",				/* 29 */
	"has next record",		/* 30 */
	"has 31 record",		/* 31 */
	"has 32 record",		/* 32 */
	"SRV",				/* 33 */
	"has 34 record",		/* 34 */
	"NAPTR",			/* 35 */
	"KX",				/* 36 */
	"CERT",				/* 37 */
	"has v6 address",		/* 38 */
	"DNAME",			/* 39 */
	"has 40 record",       		/* 40 */
	"has optional information"};	/* 41 */

void
check_next_lookup (dig_lookup_t *lookup) {
	dig_lookup_t *next;
	dig_query_t *query;
	isc_boolean_t still_working=ISC_FALSE;
	
	debug("In check_next_lookup");
	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		if (query->working) {
			debug("Still have a worker.");
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

#ifdef NEVER
	next = ISC_LIST_NEXT (lookup, link);
	if (next == NULL) {
		debug ("Shutting Down.");
		isc_app_shutdown();
		return;
	}
	
	setup_lookup(next);
	if (tcp_mode)
		do_lookup_tcp(next);
	else
		do_lookup_udp(next);
#endif
}

static void
show_usage() {
	fputs (
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
	exit (0);
}				

void
received(int bytes, int frmsize, char *frm, dig_query_t *query) {
	UNUSED(query);
	if (!short_form)
		printf("Received %u bytes from %.*s\n",
		       bytes, frmsize, frm);
}

void
trying(int frmsize, char *frm, dig_lookup_t *lookup) {
	UNUSED (lookup);

	if (!short_form)
		printf ("Trying \"%.*s\"\n", frmsize, frm);
}

static void
say_message(dns_name_t *name, char *msg, dns_rdata_t *rdata,
	    dig_query_t *query)
{
	isc_buffer_t *b=NULL, *b2=NULL;
	isc_region_t r, r2;
	isc_result_t result;

	result = isc_buffer_allocate(mctx, &b, BUFSIZE);
	check_result (result, "isc_buffer_allocate");
	result = isc_buffer_allocate(mctx, &b2, BUFSIZE);
	check_result (result, "isc_buffer_allocate");
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
printsection(dns_message_t *msg, dns_section_t sectionid, char *section_name,
	     isc_boolean_t headers, dig_query_t *query)
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
	char *rtt;
	
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
#endif
			} else { 
				loopresult = dns_rdataset_first(rdataset);
				while (loopresult == ISC_R_SUCCESS) {
					dns_rdataset_current(rdataset, &rdata);
					if (rdata.type <= 41)
						rtt=rtypetext[rdata.type];
					else if (rdata.type == 103)
						rtt="unspecified data";
					else if (rdata.type == 249)
						rtt="key";
					else if (rdata.type == 250)
						rtt="signature";
					else
						rtt="unknown";
					say_message(print_name,
						    rtypetext[rdata.type],
						    &rdata, query);
					loopresult = dns_rdataset_next(
								 rdataset);
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
	dns_rdataset_t *opt, *tsig = NULL;
	dns_name_t *tsigname;
	isc_result_t result = ISC_R_SUCCESS;

	UNUSED (headers);

	if (msg->rcode != 0) {
		printf ("Host not found: %d(%s)\n",
			msg->rcode, rcodetext[msg->rcode]);
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
	    !short_form ) {
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
				      !short_form, query);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_AUTHORITY]) &&
	    !short_form ) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_AUTHORITY, "AUTHORITY",
				      ISC_TRUE, query);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_ADDITIONAL]) &&
	    !short_form ) {
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
	int c;

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
	
	if (querytype[0] == 0)
		strcpy (querytype, "a");
	if (queryclass[0] == 0)
		strcpy (queryclass, "in");

	lookup = isc_mem_allocate (mctx, 
				   sizeof(struct dig_lookup));
	if (lookup == NULL)	
		fatal ("Memory allocation failure.");
	lookup->pending = ISC_FALSE;
	strncpy (lookup->textname, hostname, MXNAME);
	strncpy (lookup->rttext, querytype, 32);
	strncpy (lookup->rctext, queryclass, 32);
	lookup->namespace[0]=0;
	lookup->sendspace[0]=0;
	lookup->sendmsg=NULL;
	lookup->name=NULL;
	lookup->oname=NULL;
	lookup->timer = NULL;
	lookup->xfr_q = NULL;
	lookup->doing_xfr = ISC_FALSE;
	lookup->identify = ISC_FALSE;
	lookup->recurse = recursion;
	lookup->ns_search_only = showallsoa;
	lookup->use_my_server_list = ISC_FALSE;
	lookup->retries = tries;
	ISC_LIST_INIT(lookup->q);
	ISC_LIST_APPEND(lookup_list, lookup, link);
	lookup->origin = NULL;
	ISC_LIST_INIT(lookup->my_server_list);
	have_host = ISC_TRUE;
}

