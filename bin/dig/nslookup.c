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

/* $Id: nslookup.c,v 1.13 2000/06/06 23:06:25 mws Exp $ */

#include <config.h>

#include <stdlib.h>

extern int h_errno;

#include <isc/app.h>
#include <isc/string.h>
#include <isc/util.h>
#include <isc/mutex.h>
#include <isc/condition.h>
#include <isc/commandline.h>
#include <isc/timer.h>
#include <isc/buffer.h>

#include <dns/message.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>
#include <dns/name.h>

#include <dig/dig.h>

extern ISC_LIST(dig_lookup_t) lookup_list;
extern ISC_LIST(dig_server_t) server_list;
extern ISC_LIST(dig_searchlist_t) search_list;

extern isc_boolean_t have_ipv6, show_details,
	usesearch, trace, qr;
extern in_port_t port;
extern unsigned int timeout;
extern isc_mem_t *mctx;
extern dns_messageid_t id;
extern char *rootspace[BUFSIZE];
extern isc_buffer_t rootbuf;
extern int sendcount;
extern int ndots;
extern int tries;
extern int lookup_counter;
extern char fixeddomain[MXNAME];
extern int exitcode;

isc_boolean_t short_form = ISC_TRUE, printcmd = ISC_TRUE,
	filter = ISC_FALSE, showallsoa = ISC_FALSE,
	tcpmode = ISC_FALSE;

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
isc_boolean_t busy = ISC_FALSE, in_use = ISC_FALSE;
char defclass[MXRD] = "IN";
char deftype[MXRD] = "A";

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
	"rtype_0 = ",			/* 0 */
	"internet address = ",		/* 1 */
	"nameserver = ",		/* 2 */
	"md = ",			/* 3 */
	"mf = ",			/* 4 */
	"canonical name = ",		/* 5 */
	"soa = ",		       	/* 6 */
	"mb = ",		       	/* 7 */	
	"mg = ",		       	/* 8 */
	"mr = ",		       	/* 9 */
	"rtype_10 = ",		       	/* 10 */
	"protocol = ",			/* 11 */
	"name = ",			/* 12 */
	"hinfo = ",			/* 13 */
	"minfo = ",			/* 14 */
	"mail exchanger = ",	       	/* 15 */
	"text = ",			/* 16 */
	"rp = ",       			/* 17 */
	"afsdb = ",			/* 18 */
	"x25 address = ",		/* 19 */
	"isdn address = ",		/* 20 */
	"rt = "				/* 21 */
	"nsap = ",			/* 22 */
	"nsap_ptr = ",			/* 23 */
	"signature = ",			/* 24 */
	"key = ",			/* 25 */
	"px = ",		       	/* 26 */
	"gpos = ",		       	/* 27 */
	"has AAAA address",	        /* 28 */
	"loc = ",		       	/* 29 */
	"next = ",			/* 30 */
	"rtype_31 = ",			/* 31 */
	"rtype_32 = ",			/* 32 */
	"service = ",	       		/* 33 */
	"rtype_34 = ",			/* 34 */
	"naptr = ",			/* 35 */
	"kx = ",			/* 36 */
	"cert = ",			/* 37 */
	"v6 address = ",		/* 38 */
	"dname = ",			/* 39 */
	"rtype_40 = ",       		/* 40 */
	"optional = "};			/* 41 */


static void
show_usage() {
	fputs (
"Usage:\n"
, stderr);
}				

void
dighost_shutdown(void) {
	isc_mutex_lock(&lock);
	busy = ISC_FALSE;
	isc_condition_signal(&cond);
	isc_mutex_unlock(&lock);

}
void
received(int bytes, int frmsize, char *frm, dig_query_t *query) {
	UNUSED (bytes);
	UNUSED (frmsize);
	UNUSED (frm);
	UNUSED (query);
}

void
trying(int frmsize, char *frm, dig_lookup_t *lookup) {
	UNUSED (frmsize);
	UNUSED (frm);
	UNUSED (lookup);

}


static isc_result_t
printsection(dig_query_t *query, dns_message_t *msg, isc_boolean_t headers,
	     dns_section_t section) {
	isc_result_t result, loopresult;
	isc_buffer_t *b = NULL;
	dns_name_t *name;
	dns_rdataset_t *rdataset = NULL;
	dns_rdata_t rdata;
	char *ptr;

	UNUSED (query);
	UNUSED (headers);

	debug("printsection()");

	/*
	 * Exitcode 9 means we timed out, but if we're printing a message,
	 * we much have recovered.  Go ahead and reset it to code 0, and
	 * call this a success.
	 */
	if (exitcode == 9)
		exitcode = 0;

	result = dns_message_firstname(msg, section);
	if (result == ISC_R_NOMORE)
		return (ISC_R_SUCCESS);
	else if (result != ISC_R_SUCCESS)
		return (result);
	result = isc_buffer_allocate(mctx, &b, MXNAME);
	check_result(result, "isc_buffer_allocate");
	for (;;) {
		name = NULL;
		dns_message_currentname(msg, section, 
					&name);
		for (rdataset = ISC_LIST_HEAD(name->list);
		     rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link)) {
			loopresult = dns_rdataset_first(rdataset);
			while (loopresult == ISC_R_SUCCESS) {
				dns_rdataset_current(rdataset, &rdata);
				switch (rdata.type) {
				case dns_rdatatype_a:
					if (section != DNS_SECTION_ANSWER)
						goto def_short_section;
					isc_buffer_clear(b);
					result = dns_name_totext(name,
							ISC_TRUE,
							b);
					check_result(result,
						     "dns_name_totext");
					printf("Name:\t%.*s\n",
					       (int)isc_buffer_usedlength(b),
					       (char*)isc_buffer_base(b));
					isc_buffer_clear(b);
					result = dns_rdata_totext(&rdata,
								  NULL,
								  b);
					check_result(result,
						     "dns_rdata_totext");
					printf("Address: %.*s\n",
					       (int)isc_buffer_usedlength(b),
					       (char*)isc_buffer_base(b));
					break;
				case dns_rdatatype_soa:
					isc_buffer_clear(b);
					result = dns_name_totext(name,
							ISC_TRUE,
							b);
					check_result(result,
						     "dns_name_totext");
					printf("%.*s\n",
					       (int)isc_buffer_usedlength(b),
					       (char*)isc_buffer_base(b));
					isc_buffer_clear(b);
					result = dns_rdata_totext(&rdata,
								  NULL,
								  b);
					check_result(result,
						     "dns_rdata_totext");
					((char *)isc_buffer_used(b))[0]=0;
					ptr = strtok(isc_buffer_base(b),
						     " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\torigin = %s\n",
					       ptr);
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tmail addr = %s\n",
					       ptr);
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tserial = %s\n",
					       ptr);
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\trefresh = %s\n",
					       ptr);
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tretry = %s\n",
					       ptr);
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\texpire = %s\n",
					       ptr);
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tminimum = %s\n",
					       ptr);
					break;
				default:
				def_short_section:
					isc_buffer_clear(b);
					result = dns_name_totext(name,
							ISC_TRUE,
							b);
					check_result(result,
						     "dns_name_totext");
					if (rdata.type <= 41)
						printf ("%.*s\t%s",
						(int)isc_buffer_usedlength(b),
						(char*)isc_buffer_base(b),
						rtypetext[rdata.type]);
					else
						printf ("%.*s\trdata_%d = ",
						(int)isc_buffer_usedlength(b),
						(char*)isc_buffer_base(b),
						 rdata.type);
					isc_buffer_clear(b);
					result = dns_rdata_totext(&rdata, 
								  NULL, b);
					check_result(result,
						     "dns_rdata_totext");
					printf("%.*s\n",
					       (int)isc_buffer_usedlength(b),
					       (char*)isc_buffer_base(b));
				}	
				loopresult = dns_rdataset_next(rdataset);
			}
		}
		result = dns_message_nextname(msg, section);
		if (result == ISC_R_NOMORE)
			break;
		else if (result != ISC_R_SUCCESS) {
			isc_buffer_free (&b);
			return (result);
		}
	}
	isc_buffer_free(&b);
	return (ISC_R_SUCCESS);
}

static isc_result_t
detailsection(dig_query_t *query, dns_message_t *msg, isc_boolean_t headers,
	     dns_section_t section) {
	isc_result_t result, loopresult;
	isc_buffer_t *b = NULL;
	dns_name_t *name;
	dns_rdataset_t *rdataset = NULL;
	dns_rdata_t rdata;
	char *ptr;

	UNUSED (query);

	debug("printsection()");

	/*
	 * Exitcode 9 means we timed out, but if we're printing a message,
	 * we much have recovered.  Go ahead and reset it to code 0, and
	 * call this a success.
	 */
	if (exitcode == 9)
		exitcode = 0;

	if (headers) {
		switch (section) {
		case DNS_SECTION_QUESTION:
			puts ("    QUESTIONS:");
			break;
		case DNS_SECTION_ANSWER:
			puts ("    ANSWERS:");
			break;
		case DNS_SECTION_AUTHORITY:
			puts ("    AUTHORITY RECORDS:");
			break;
		case DNS_SECTION_ADDITIONAL:
			puts ("    ADDITIONAL RECORDS:");
			break;
		}
	}

	result = dns_message_firstname(msg, section);
	if (result == ISC_R_NOMORE)
		return (ISC_R_SUCCESS);
	else if (result != ISC_R_SUCCESS)
		return (result);
	result = isc_buffer_allocate(mctx, &b, MXNAME);
	check_result(result, "isc_buffer_allocate");
	for (;;) {
		name = NULL;
		dns_message_currentname(msg, section, 
					&name);
		for (rdataset = ISC_LIST_HEAD(name->list);
		     rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link)) {
			loopresult = dns_rdataset_first(rdataset);
			while (loopresult == ISC_R_SUCCESS) {
				dns_rdataset_current(rdataset, &rdata);
				isc_buffer_clear(b);
				result = dns_name_totext(name,
							 ISC_TRUE,
							 b);
				check_result(result,
					     "dns_name_totext");
				printf("    ->  %.*s\n",
				       (int)isc_buffer_usedlength(b),
				       (char*)isc_buffer_base(b));
				switch (rdata.type) {
				case dns_rdatatype_soa:
					isc_buffer_clear(b);
					result = dns_rdata_totext(&rdata,
								  NULL,
								  b);
					check_result(result,
						     "dns_rdata_totext");
					((char *)isc_buffer_used(b))[0]=0;
					ptr = strtok(isc_buffer_base(b),
						     " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\torigin = %s\n",
					       ptr);
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tmail addr = %s\n",
					       ptr);
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tserial = %s\n",
					       ptr);
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\trefresh = %s\n",
					       ptr);
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tretry = %s\n",
					       ptr);
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\texpire = %s\n",
					       ptr);
					ptr = strtok(NULL, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tminimum = %s\n",
					       ptr);
					break;
				default:
					isc_buffer_clear(b);
					if (rdata.type <= 41)
						printf ("\t%s",
						rtypetext[rdata.type]);
					else
						printf ("\trdata_%d = ",
						 rdata.type);
					isc_buffer_clear(b);
					result = dns_rdata_totext(&rdata, 
								  NULL, b);
					check_result(result,
						     "dns_rdata_totext");
					printf("%.*s\n",
					       (int)isc_buffer_usedlength(b),
					       (char*)isc_buffer_base(b));
				}	
				loopresult = dns_rdataset_next(rdataset);
			}
		}
		result = dns_message_nextname(msg, section);
		if (result == ISC_R_NOMORE)
			break;
		else if (result != ISC_R_SUCCESS) {
			isc_buffer_free (&b);
			return (result);
		}
	}
	isc_buffer_free(&b);
	return (ISC_R_SUCCESS);
}

isc_result_t
printmessage(dig_query_t *query, dns_message_t *msg, isc_boolean_t headers) {
	isc_buffer_t *b = NULL;
	isc_region_t r;
	isc_result_t result;

	debug ("printmessage()");

	if (msg->rcode != 0) {
		result = isc_buffer_allocate(mctx, &b, MXNAME);
		check_result(result, "isc_buffer_allocate");
		result = dns_name_totext(query->lookup->name, ISC_FALSE,
					 b);
		check_result(result, "dns_name_totext");
		isc_buffer_usedregion(b, &r);
		printf("** server can't find %.*s: %s\n",
		       (int)r.length, (char*)r.base,
		       rcodetext[msg->rcode]);
		isc_buffer_free(&b);
		debug ("Returning with rcode == 0");
		return (ISC_R_SUCCESS);
	}
	debug ("Continuing on with rcode != 0");
	result = isc_buffer_allocate(mctx, &b, MXNAME);
	check_result(result, "isc_buffer_allocate");
	printf("Server:\t\t%s\n", query->servname);
	result = isc_sockaddr_totext(&query->sockaddr, b);
	check_result(result, "isc_sockaddr_totext");
	printf("Address:\t%.*s\n", (int)isc_buffer_usedlength(b),
	       (char*)isc_buffer_base(b));
	isc_buffer_free(&b);
	puts("");
	if (!short_form){
		puts ("------------");
		/*		detailheader(query, msg);*/
		detailsection(query, msg, headers, DNS_SECTION_QUESTION);
		detailsection(query, msg, headers, DNS_SECTION_ANSWER);
		detailsection(query, msg, headers, DNS_SECTION_AUTHORITY);
		detailsection(query, msg, headers, DNS_SECTION_ADDITIONAL);
		puts ("------------");
	}
	
	if ((msg->flags & DNS_MESSAGEFLAG_AA) == 0)
		puts ("Non-authorative answer:");
	printsection(query, msg, headers, DNS_SECTION_ANSWER);
	
	if (((msg->flags & DNS_MESSAGEFLAG_AA) == 0) &&
	    (strcasecmp(query->lookup->rttext,"a") != 0)) {
		puts ("\nAuthorative answers can be found from:");
		printsection(query, msg, headers,
			     DNS_SECTION_AUTHORITY);
		printsection(query, msg, headers,
			     DNS_SECTION_ADDITIONAL);
	}
	return (ISC_R_SUCCESS);
}

static void
show_settings(isc_boolean_t full) {
	dig_server_t *srv;
	isc_sockaddr_t sockaddr;
	isc_buffer_t *b = NULL;
	isc_result_t result;
	
	srv = ISC_LIST_HEAD(server_list);

	while (srv != NULL) {
		result = isc_buffer_allocate(mctx, &b, MXNAME);
		check_result(result, "isc_buffer_allocate");
		get_address(srv->servername, 53, &sockaddr);
		result = isc_sockaddr_totext(&sockaddr, b);
		check_result(result, "isc_sockaddr_totext");
		printf ("Default server: %s\nAddress: %.*s\n",
			srv->servername, (int)isc_buffer_usedlength(b),
			(char*)isc_buffer_base(b));
		isc_buffer_free(&b);
		if (!full)
			return;
		srv = ISC_LIST_NEXT(srv, link);
	}
	printf ("\n\tSet options:\n");
	printf ("\t  %s\t\t\t%s\t\t%s\n",
		tcpmode?"vc":"novc", short_form?"nodebug":"debug",
		recurse?"recurse":"norecurse");
	printf ("\t  %s\t\t%s\t\tport = %d\n",
		defname?"defname":"nodefname",
		usesearch?"search":"nosearch",
		port);
	printf ("\t  timeout = %d\t\tretry = %d\n",
		timeout, tries);
	printf ("\t  querytype = %-8s\tclass=%s\n",deftype, defclass);


}

static void
setoption(char *opt) {

	if (strncasecmp(opt,"all",4) == 0) {
		show_settings(ISC_TRUE);
	} else if (strncasecmp(opt, "class=", 6) == 0) {
		strncpy(defclass, &opt[6], MXRD);
	} else if (strncasecmp(opt, "cl=", 3) == 0) {
		strncpy(defclass, &opt[3], MXRD);
	} else if (strncasecmp(opt, "type=", 5) == 0) {
		strncpy(deftype, &opt[5], MXRD);
	} else if (strncasecmp(opt, "ty=", 3) == 0) {
		strncpy(deftype, &opt[3], MXRD);
	} else if (strncasecmp(opt, "querytype=", 10) == 0) {
		strncpy(deftype, &opt[10], MXRD);
	} else if (strncasecmp(opt, "query=", 6) == 0) {
		strncpy(deftype, &opt[6], MXRD);
	} else if (strncasecmp(opt, "qu=", 3) == 0) {
		strncpy(deftype, &opt[3], MXRD);
	} else if (strncasecmp(opt, "domain=", 7) == 0) {
		strncpy(fixeddomain, &opt[7], MXNAME);
	} else if (strncasecmp(opt, "do=", 3) == 0) {
		strncpy(fixeddomain, &opt[3], MXNAME);
	} else if (strncasecmp(opt, "port=", 5) == 0) {
		port = atoi(&opt[5]);
	} else if (strncasecmp(opt, "po=", 3) == 0) {
		port = atoi(&opt[3]);
	} else if (strncasecmp(opt, "timeout=", 8) == 0) {
		timeout = atoi(&opt[8]);
	} else if (strncasecmp(opt, "t=", 2) == 0) {
		timeout = atoi(&opt[2]);
	} else if (strncasecmp(opt, "retry=", 6) == 0) {
		tries = atoi(&opt[6]);
	} else if (strncasecmp(opt, "ret=", 4) == 0) {
		tries = atoi(&opt[4]);
 	} else if (strncasecmp(opt, "def", 3) == 0) {
		defname = ISC_TRUE;
	} else if (strncasecmp(opt, "nodef", 5) == 0) {
		defname = ISC_FALSE;
 	} else if (strncasecmp(opt, "deb", 3) == 0) {
		short_form = ISC_FALSE;
	} else if (strncasecmp(opt, "nodeb", 5) == 0) {
		short_form = ISC_TRUE;
	}
}

static void
addlookup(char *opt) {
	dig_lookup_t *lookup;

	debug ("addlookup()");
	lookup = isc_mem_allocate(mctx, sizeof(struct dig_lookup));
	if (lookup == NULL)
		fatal("Memory allocation failure.");
	lookup->pending = ISC_FALSE;
	strncpy(lookup->textname, opt, MXNAME-1);
	strncpy (lookup->rttext, deftype, MXNAME);
	strncpy (lookup->rctext, defclass, MXNAME);
	lookup->namespace[0]=0;
	lookup->sendspace[0]=0;
	lookup->sendmsg=NULL;
	lookup->name=NULL;
	lookup->oname=NULL;
	lookup->timer = NULL;
	lookup->xfr_q = NULL;
	lookup->origin = NULL;
	lookup->querysig = NULL;
	lookup->use_my_server_list = ISC_FALSE;
	lookup->doing_xfr = ISC_FALSE;
	lookup->ixfr_serial = 0;
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
	lookup->new_search = ISC_TRUE;
	ISC_LIST_INIT(lookup->q);
	ISC_LIST_APPEND(lookup_list, lookup, link);
	lookup->origin = NULL;
	ISC_LIST_INIT(lookup->my_server_list);
	debug("Looking up %s", lookup->textname);
}

static void
flush_server_list() {
	dig_server_t *s, *ps;

	debug ("flush_lookup_list()");
	s = ISC_LIST_HEAD(server_list);
	while (s != NULL) {
		ps = s;
		s = ISC_LIST_NEXT(s, link);
		ISC_LIST_DEQUEUE(server_list, ps, link);
		isc_mem_free(mctx, ps);
	}

}

/* 
 * This works on the global server list, instead of on a per-lookup
 * server list, since the change is persistent.
 */
static void
setsrv(char *opt) {
	dig_server_t *srv;

	flush_server_list();
	srv=isc_mem_allocate(mctx, sizeof(struct dig_server));
	if (srv == NULL)
		fatal("Memory allocation failure.");
	strncpy(srv->servername, opt, MXNAME-1);
	ISC_LIST_APPEND(server_list, srv, link);
}

static void
get_next_command() {
	char input[COMMSIZE];
	char *ptr, *arg;

	fputs("> ", stderr);
	ptr = fgets(input, COMMSIZE, stdin);
	if (ptr == NULL) {
		in_use = ISC_FALSE;
		return;
	}
	ptr = strtok(input, " \t\r\n");
	if (ptr == NULL) {
		in_use = ISC_FALSE;
		return;
	}
	arg = strtok(NULL, " \t\r\n");
	if ((strcasecmp(ptr, "set") == 0) &&
	    (arg != NULL))
		setoption(arg);
	else if ((strcasecmp(ptr, "server") == 0) ||
		 (strcasecmp(ptr, "lserver") == 0)) {
		printf("Server:\t%s\n", arg); 
		setsrv(arg);
	} else 
		addlookup(ptr);
}

static void
parse_args(int argc, char **argv) {
	dig_lookup_t *lookup = NULL;

	for (argc--, argv++; argc > 0; argc--, argv++) {
		debug ("Main parsing %s", argv[0]);
		if (argv[0][0] == '-') {
			if ((argv[0][1] == 'h') &&
			    (argv[0][2] == 0)) {
				show_usage();
				exit (1);
			}
			if (argv[0][1] != 0)
				setoption(&argv[0][1]);
		} else {
			if (lookup == NULL) {
				in_use = ISC_TRUE;
				addlookup(argv[0]);
			}
			else
				setsrv(argv[0]);
		}
	}
}

static void
flush_lookup_list(void) {
	dig_lookup_t *l, *lp;
	dig_query_t *q, *qp;
	dig_server_t *s, *sp;

	lookup_counter = 0;
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
			qp = q;
			q = ISC_LIST_NEXT(q, link);
			ISC_LIST_DEQUEUE(l->q, qp, link);
			isc_mem_free(mctx, qp);
		}
		if (l->use_my_server_list) {
			s = ISC_LIST_HEAD(l->my_server_list);
			while (s != NULL) {
				sp = s;
				s = ISC_LIST_NEXT(s, link);
				ISC_LIST_DEQUEUE(l->my_server_list, sp, link);
				isc_mem_free(mctx, sp);

			}
		}
		if (l->sendmsg != NULL)
			dns_message_destroy(&l->sendmsg);
		if (l->timer != NULL)
			isc_timer_detach(&l->timer);
		lp = l;
		l = ISC_LIST_NEXT(l, link);
		ISC_LIST_DEQUEUE(lookup_list, lp, link);
		isc_mem_free(mctx, lp);
	}
}	

int
main(int argc, char **argv) {
	isc_result_t result;

	ISC_LIST_INIT(lookup_list);
	ISC_LIST_INIT(server_list);
	ISC_LIST_INIT(search_list);

	setup_libs();
	result = isc_mutex_init(&lock);
	check_result(result, "isc_mutex_init");
	result = isc_condition_init(&cond);
	check_result(result, "isc_condition_init");
	result = isc_mutex_trylock(&lock);
	check_result(result, "isc_mutex_trylock");

	parse_args(argc, argv);
	setup_system();

	if (in_use) {
		busy = ISC_TRUE;
		start_lookup();
		while (busy) {
			result = isc_condition_wait(&cond, &lock);
			check_result(result, "isc_condition_wait");
		}
		flush_lookup_list();
		in_use = ISC_FALSE;
	} else {
		show_settings(ISC_FALSE);
		in_use = ISC_TRUE;
	}

	while (in_use) {
		get_next_command();
		if (ISC_LIST_HEAD(lookup_list) != NULL) {
			busy = ISC_TRUE;
			start_lookup();
			while (busy) {
				result = isc_condition_wait(&cond, &lock);
				check_result(result, "isc_condition_wait");
			}
			flush_lookup_list();
		}
	}

	puts ("");
	debug ("Fell through app_run");
	free_lists(0);
	isc_mutex_destroy(&lock);
	isc_condition_destroy(&cond);
	
	return (0);
}

