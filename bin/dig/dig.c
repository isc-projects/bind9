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
#include <dig/printmsg.h>

extern ISC_LIST(dig_lookup_t) lookup_list;
extern ISC_LIST(dig_server_t) server_list;

extern isc_boolean_t tcp_mode,
	recurse,
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

isc_boolean_t short_form=ISC_FALSE;

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
	fatal ("Usage.");
}				

void
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

static isc_result_t
printsection(dns_message_t *msg, dns_section_t sectionid, char *section_name,
	     isc_boolean_t headers)
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

		isc_buffer_init(&target, t, sizeof t, ISC_BUFFERTYPE_TEXT);
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
		isc_buffer_used(&target, &r);
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

	isc_buffer_init(&target, t, sizeof t, ISC_BUFFERTYPE_TEXT);

	result = dns_rdataset_totext(rdataset, owner, ISC_FALSE, ISC_FALSE,
				     &target);
	if (result != ISC_R_SUCCESS)
		return (result);
	isc_buffer_used(&target, &r);
	printf("%.*s", (int)r.length, (char *)r.base);

	return (ISC_R_SUCCESS);
}

isc_result_t
printmessage(dns_message_t *msg, isc_boolean_t headers) {
	isc_boolean_t did_flag = ISC_FALSE;
	isc_result_t result;
	dns_rdataset_t *opt, *tsig;
	dns_name_t *tsigname;

	result = ISC_R_SUCCESS;

	if (headers) {
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
		printf("; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
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
	    headers ) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_QUESTION, "QUESTION",
				      ISC_TRUE);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_ANSWER])) {
		if (headers)
			printf("\n");
		result = printsection(msg, DNS_SECTION_ANSWER, "ANSWER",
				      headers);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_AUTHORITY]) &&
	    headers ) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_AUTHORITY, "AUTHORITY",
				      ISC_TRUE);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (! ISC_LIST_EMPTY(msg->sections[DNS_SECTION_ADDITIONAL]) &&
	    headers ) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_ADDITIONAL,
				      "ADDITIONAL", ISC_TRUE);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if ((tsig != NULL) && headers) {
		printf("\n");
		result = printrdata(msg, tsig, tsigname,
				    "PSEUDOSECTION TSIG", ISC_TRUE);
		if (result != ISC_R_SUCCESS)
			return (result);
	}
	if (headers)
		printf("\n");

	return (result);
}

/*
** We're not using isc_commandline_parse() here since the command line
** syntax of dig is quite a bit different from that which can be described
** that routine.  There is a portability issue here.
*/
void
parse_args(isc_boolean_t is_batchfile, int argc, char **argv) {
	isc_boolean_t have_host=ISC_FALSE;
	dig_server_t *srv=NULL;
	dig_lookup_t *lookup=NULL;
	char *batchname=NULL;
	char batchline[MXNAME];
	FILE *fp=NULL;
	int bargc;
	char *bargv[8];
	char *ptr;
	int i,n;
	int adrs[4];

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
		} else if (strncmp(argv[0],"+time=",6) == 0) {
			timeout = atoi(&argv[0][6]);
			if (timeout <= 0)
				timeout = 1;
		} else if (strcmp(argv[0],"+norecurs") == 0) {
			recurse = ISC_FALSE;
		} else if (strncmp(argv[0],"-f",2) == 0) {
			if (argv[0][2]!=0) {
				batchname=&argv[0][2];
			} else {
				batchname=argv[1];
				argv++;
				argc--;
			}
		} else if (strncmp(argv[0],"-p",2) == 0) {
			if (argv[0][2]!=0) {	
				port=atoi(&argv[0][2]);
			} else {
				port=atoi(argv[1]);
				argv++;
				argc--;
			}
		} else if (strncmp(argv[0],"-x",2) == 0) {
			n = sscanf (argv[1],"%d.%d.%d.%d", &adrs[0], &adrs[1],
				    &adrs[2], &adrs[3]);
			if (n == 0)
				show_usage();
			lookup = isc_mem_allocate (mctx, 
						   sizeof(struct dig_lookup));
			if (lookup == NULL)
				fatal ("Memory allocation failure.");
			lookup->pending = ISC_FALSE;
			lookup->textname[0]=0;
			for (i=n-1; i>=0; i--) {
				snprintf (batchline, MXNAME/8, "%d.",
					  adrs[i]);
				strncat (lookup->textname, batchline, MXNAME);
			}
			strncat (lookup->textname, "in-addr.arpa.", MXNAME);
#ifdef DEBUG
			printf ("Looking up %s\n",lookup->textname);
#endif
			strcpy (lookup->rttext, "ptr");
			strcpy (lookup->rctext, "in");
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
#ifdef DEBUG
			printf ("Looking up %s\n",lookup->textname);
#endif
		}
	}
	if (batchname != NULL) {
		fp = fopen (batchname, "r");
		if (fp == NULL) {
			perror (batchname);
			fatal ("Couldn't open specified batch file.");
		}
		while (fgets (batchline, MXNAME, fp) != 0) {
			bargc=1;
			bargv[bargc]=strtok(batchline, " \t");
			while (bargv[bargc] != NULL) {
				bargc++;
				bargv[bargc]=strtok(NULL, " \t");
			}
			bargc--;
			bargv[0]="dig";
#ifdef DEBUG
			printf ("Parsing %d:%s\n",bargc,bargv[1]);
#endif
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

