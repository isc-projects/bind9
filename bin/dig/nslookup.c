/*
 * Copyright (C) 2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: nslookup.c,v 1.63 2000/10/31 03:21:39 marka Exp $ */

#include <config.h>

#include <stdlib.h>

extern int h_errno;

#include <isc/app.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/event.h>
#include <isc/string.h>
#include <isc/timer.h>
#include <isc/util.h>
#include <isc/task.h>
#include <isc/netaddr.h>

#include <dns/message.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>
#include <dns/byaddr.h>

#include <dig/dig.h>

extern ISC_LIST(dig_lookup_t) lookup_list;
extern ISC_LIST(dig_server_t) server_list;
extern ISC_LIST(dig_searchlist_t) search_list;

extern isc_boolean_t have_ipv6,
	usesearch, trace, qr, debugging, is_blocking;
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
extern isc_taskmgr_t *taskmgr;
extern isc_task_t *global_task;
extern char *progname;

isc_boolean_t short_form = ISC_TRUE, printcmd = ISC_TRUE,
	filter = ISC_FALSE, showallsoa = ISC_FALSE,
	tcpmode = ISC_FALSE, deprecation_msg = ISC_TRUE;

isc_uint16_t bufsize = 0;
isc_boolean_t identify = ISC_FALSE,
	trace = ISC_FALSE, ns_search_only = ISC_FALSE,
	forcecomment = ISC_FALSE, stats = ISC_TRUE,
	comments = ISC_TRUE, section_question = ISC_TRUE,
	section_answer = ISC_TRUE, section_authority = ISC_TRUE,
	section_additional = ISC_TRUE, recurse = ISC_TRUE,
	defname = ISC_TRUE, aaonly = ISC_FALSE;
isc_boolean_t busy = ISC_FALSE, in_use = ISC_FALSE;
char defclass[MXRD] = "IN";
char deftype[MXRD] = "A";
isc_event_t *global_event = NULL;

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
	"rt = ",			/* 21 */
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


static void flush_lookup_list(void);
static void getinput(isc_task_t *task, isc_event_t *event);

static void
show_usage(void) {
	fputs("Usage:\n", stderr);
}

void
dighost_shutdown(void) {
	isc_event_t *event = global_event;

	flush_lookup_list();
	debug("dighost_shutdown()");

	if (!in_use) {
		isc_app_shutdown();
		return;
	}

	isc_task_send(global_task, &event);
}

void
received(int bytes, int frmsize, char *frm, dig_query_t *query) {
	UNUSED(bytes);
	UNUSED(frmsize);
	UNUSED(frm);
	UNUSED(query);
}

void
trying(int frmsize, char *frm, dig_lookup_t *lookup) {
	UNUSED(frmsize);
	UNUSED(frm);
	UNUSED(lookup);

}

static isc_result_t
printsection(dig_query_t *query, dns_message_t *msg, isc_boolean_t headers,
	     dns_section_t section) {
	isc_result_t result, loopresult;
	isc_buffer_t *b = NULL;
	dns_name_t *name;
	dns_rdataset_t *rdataset = NULL;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	char *ptr;
	char *input;

	UNUSED(query);
	UNUSED(headers);

	debug("printsection()");

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
					input = isc_buffer_base(b);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\torigin = %s\n",
					       ptr);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tmail addr = %s\n",
					       ptr);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tserial = %s\n",
					       ptr);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\trefresh = %s\n",
					       ptr);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tretry = %s\n",
					       ptr);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\texpire = %s\n",
					       ptr);
					ptr = next_token(&input, " \t\r\n");
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
						printf("%.*s\t%s",
						(int)isc_buffer_usedlength(b),
						(char*)isc_buffer_base(b),
						rtypetext[rdata.type]);
					else
						printf("%.*s\trdata_%d = ",
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
				dns_rdata_reset(&rdata);
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
	dns_rdata_t rdata = DNS_RDATA_INIT;
	char *ptr;
	char *input;

	UNUSED(query);

	debug("detailsection()");

	if (headers) {
		switch (section) {
		case DNS_SECTION_QUESTION:
			puts("    QUESTIONS:");
			break;
		case DNS_SECTION_ANSWER:
			puts("    ANSWERS:");
			break;
		case DNS_SECTION_AUTHORITY:
			puts("    AUTHORITY RECORDS:");
			break;
		case DNS_SECTION_ADDITIONAL:
			puts("    ADDITIONAL RECORDS:");
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
					input = isc_buffer_base(b);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\torigin = %s\n",
					       ptr);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tmail addr = %s\n",
					       ptr);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tserial = %s\n",
					       ptr);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\trefresh = %s\n",
					       ptr);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tretry = %s\n",
					       ptr);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\texpire = %s\n",
					       ptr);
					ptr = next_token(&input, " \t\r\n");
					if (ptr == NULL)
						break;
					printf("\tminimum = %s\n",
					       ptr);
					break;
				default:
					isc_buffer_clear(b);
					if (rdata.type <= 41)
						printf("\t%s",
						rtypetext[rdata.type]);
					else
						printf("\trdata_%d = ",
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
				dns_rdata_reset(&rdata);
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

	debug("printmessage()");
	debug("continuing on with rcode != 0");
	result = isc_buffer_allocate(mctx, &b, MXNAME);
	check_result(result, "isc_buffer_allocate");
	printf("Server:\t\t%s\n", query->servname);
	result = isc_sockaddr_totext(&query->sockaddr, b);
	check_result(result, "isc_sockaddr_totext");
	printf("Address:\t%.*s\n", (int)isc_buffer_usedlength(b),
	       (char*)isc_buffer_base(b));
	isc_buffer_free(&b);
	puts("");

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
		debug("returning with rcode == 0");
		return (ISC_R_SUCCESS);
	}
	if (!short_form){
		puts("------------");
		/*		detailheader(query, msg);*/
		detailsection(query, msg, headers, DNS_SECTION_QUESTION);
		detailsection(query, msg, headers, DNS_SECTION_ANSWER);
		detailsection(query, msg, headers, DNS_SECTION_AUTHORITY);
		detailsection(query, msg, headers, DNS_SECTION_ADDITIONAL);
		puts("------------");
	}

	if ((msg->flags & DNS_MESSAGEFLAG_AA) == 0)
		puts("Non-authoritative answer:");
	if (!ISC_LIST_EMPTY(msg->sections[DNS_SECTION_ANSWER]))
		printsection(query, msg, headers, DNS_SECTION_ANSWER);
	else
		printf("*** Can't find %s: No answer\n",
		       query->lookup->textname);

	if (((msg->flags & DNS_MESSAGEFLAG_AA) == 0) &&
	    (query->lookup->rdtype != dns_rdatatype_a)) {
		puts("\nAuthoritative answers can be found from:");
		printsection(query, msg, headers,
			     DNS_SECTION_AUTHORITY);
		printsection(query, msg, headers,
			     DNS_SECTION_ADDITIONAL);
	}
	return (ISC_R_SUCCESS);
}

static void
show_settings(isc_boolean_t full, isc_boolean_t serv_only) {
	dig_server_t *srv;
	isc_sockaddr_t sockaddr;
	isc_buffer_t *b = NULL;
	isc_result_t result;

	srv = ISC_LIST_HEAD(server_list);

	while (srv != NULL) {
		result = isc_buffer_allocate(mctx, &b, MXNAME);
		check_result(result, "isc_buffer_allocate");
		get_address(srv->servername, port, &sockaddr);
		result = isc_sockaddr_totext(&sockaddr, b);
		check_result(result, "isc_sockaddr_totext");
		printf("Default server: %s\nAddress: %.*s\n",
			srv->servername, (int)isc_buffer_usedlength(b),
			(char*)isc_buffer_base(b));
		isc_buffer_free(&b);
		if (!full)
			return;
		srv = ISC_LIST_NEXT(srv, link);
	}
	if (serv_only)
		return;
	printf("\n\tSet options:\n");
	printf("\t  %s\t\t\t%s\t\t%s\n",
		tcpmode?"vc":"novc", short_form?"nodebug":"debug",
		debugging?"d2":"nod2");
	printf("\t  %s\t\t%s\t%s\n",
		defname?"defname":"nodefname",
		usesearch?"search  ":"nosearch",
		recurse?"recurse":"norecurse");
	printf("\t  timeout = %d\t\tretry = %d\tport = %d\n",
		timeout, tries, port);
	printf("\t  querytype = %-8s\tclass = %s\n", deftype, defclass);
	printf("\t  domain = %s\n", fixeddomain);

}

static isc_boolean_t
testtype(char *typetext) {
	isc_result_t result;
	isc_textregion_t tr;
	dns_rdatatype_t rdtype;

	tr.base = typetext;
	tr.length = strlen(typetext);
	result = dns_rdatatype_fromtext(&rdtype, &tr);
	if (result == ISC_R_SUCCESS)
		return (ISC_TRUE);
	else {
		printf("unknown query type: %s\n", typetext);
		return (ISC_FALSE);
	}
}

static isc_boolean_t
testclass(char *typetext) {
	isc_result_t result;
	isc_textregion_t tr;
	dns_rdataclass_t rdclass;

	tr.base = typetext;
	tr.length = strlen(typetext);
	result = dns_rdataclass_fromtext(&rdclass, &tr);
	if (result == ISC_R_SUCCESS) 
		return (ISC_TRUE);
	else {
		printf("unknown query class: %s\n", typetext);
		return (ISC_FALSE);
	}
}

static void
safecpy(char *dest, char *src, int size) {
	strncpy(dest, src, size);
	dest[size-1]=0;
}
	

static void
setoption(char *opt) {
	if (strncasecmp(opt, "all", 4) == 0) {
		show_settings(ISC_TRUE, ISC_FALSE);
	} else if (strncasecmp(opt, "class=", 6) == 0) {
		if (testclass(&opt[6]))
			safecpy(defclass, &opt[6], MXRD);
	} else if (strncasecmp(opt, "cl=", 3) == 0) {
		if (testclass(&opt[3]))
			safecpy(defclass, &opt[3], MXRD);
	} else if (strncasecmp(opt, "type=", 5) == 0) {
		if (testtype(&opt[5]))
			safecpy(deftype, &opt[3], MXRD);
	} else if (strncasecmp(opt, "ty=", 3) == 0) {
		if (testtype(&opt[3]))
			safecpy(deftype, &opt[3], MXRD);
	} else if (strncasecmp(opt, "querytype=", 10) == 0) {
		if (testtype(&opt[10]))
			safecpy(deftype, &opt[10], MXRD);
	} else if (strncasecmp(opt, "query=", 6) == 0) {
		if (testtype(&opt[6]))
			safecpy(deftype, &opt[6], MXRD);
	} else if (strncasecmp(opt, "qu=", 3) == 0) {
		if (testtype(&opt[3]))
			safecpy(deftype, &opt[3], MXRD);
	} else if (strncasecmp(opt, "domain=", 7) == 0) {
		safecpy(fixeddomain, &opt[7], MXNAME);
		usesearch = ISC_TRUE;
	} else if (strncasecmp(opt, "do=", 3) == 0) {
		safecpy(fixeddomain, &opt[3], MXNAME);
		usesearch = ISC_TRUE;
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
 	} else if (strncasecmp(opt, "vc", 3) == 0) {
		tcpmode = ISC_TRUE;
	} else if (strncasecmp(opt, "novc", 5) == 0) {
		tcpmode = ISC_FALSE;
 	} else if (strncasecmp(opt, "deb", 3) == 0) {
		short_form = ISC_FALSE;
	} else if (strncasecmp(opt, "nodeb", 5) == 0) {
		short_form = ISC_TRUE;
 	} else if (strncasecmp(opt, "d2", 2) == 0) {
		debugging = ISC_TRUE;
	} else if (strncasecmp(opt, "nod2", 4) == 0) {
		debugging = ISC_FALSE;
	} else if (strncasecmp(opt, "search",3) == 0) {
		usesearch = ISC_TRUE;
	} else if (strncasecmp(opt, "nosearch",5) == 0) {
		usesearch = ISC_FALSE;
	} else if (strncasecmp(opt, "sil",3) == 0) {
		deprecation_msg = ISC_FALSE;
	} else {
		printf("*** Invalid option: %s\n", opt);	
	}
}

static dig_lookup_t*
addlookup(char *opt) {
	dig_lookup_t *lookup;
	isc_result_t result;
	isc_textregion_t tr;
	dns_rdatatype_t rdtype;
	dns_rdataclass_t rdclass;
	char store[MXNAME];

	debug("addlookup()");
	tr.base = deftype;
	tr.length = strlen(deftype);
	result = dns_rdatatype_fromtext(&rdtype, &tr);
	if (result != ISC_R_SUCCESS) {
		printf("unknown query type: %s\n", deftype);
		rdclass = dns_rdatatype_a;
	}
	tr.base = defclass;
	tr.length = strlen(defclass);
	result = dns_rdataclass_fromtext(&rdclass, &tr);
	if (result != ISC_R_SUCCESS) {
		printf("unknown query class: %s\n", defclass);
		rdclass = dns_rdataclass_in;
	}
	lookup = make_empty_lookup();
	if (get_reverse(store, opt, lookup->nibble) == ISC_R_SUCCESS) {
		safecpy(lookup->textname, store, sizeof(lookup->textname));
		lookup->rdtype = dns_rdatatype_ptr;
	} else {
		safecpy(lookup->textname, opt, sizeof(lookup->textname));
		lookup->rdtype = rdtype;
	}
	lookup->rdclass = rdclass;
	lookup->trace = ISC_TF(trace || ns_search_only);
	lookup->trace_root = trace;
	lookup->ns_search_only = ns_search_only;
	lookup->identify = identify;
	lookup->recurse = recurse;
	lookup->aaonly = aaonly;
	lookup->retries = tries;
	lookup->udpsize = bufsize;
	lookup->comments = comments;
	lookup->tcp_mode = tcpmode;
	lookup->stats = stats;
	lookup->section_question = section_question;
	lookup->section_answer = section_answer;
	lookup->section_authority = section_authority;
	lookup->section_additional = section_additional;
	lookup->new_search = ISC_TRUE;
	ISC_LIST_INIT(lookup->q);
	ISC_LINK_INIT(lookup, link);
	ISC_LIST_APPEND(lookup_list, lookup, link);
	lookup->origin = NULL;
	ISC_LIST_INIT(lookup->my_server_list);
	debug("looking up %s", lookup->textname);
	return (lookup);
}

static void
flush_server_list(void) {
	dig_server_t *s, *ps;

	debug("flush_server_list()");
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

	if (opt == NULL) {
		return;
	}
	flush_server_list();
	srv=isc_mem_allocate(mctx, sizeof(struct dig_server));
	if (srv == NULL)
		fatal("Memory allocation failure.");
	safecpy(srv->servername, opt, MXNAME-1);
	ISC_LIST_APPENDUNSAFE(server_list, srv, link);
}

static void
get_next_command(void) {
	char *buf;
	char *ptr, *arg;
	char *input;

	buf = isc_mem_allocate(mctx, COMMSIZE);
	if (buf == NULL)
		fatal("Memory allocation failure.");
	fputs("> ", stderr);
	is_blocking = ISC_TRUE;
	ptr = fgets(buf, COMMSIZE, stdin);
	is_blocking = ISC_FALSE;
	if (ptr == NULL) {
		in_use = ISC_FALSE;
		goto cleanup;
	}
	input = buf;
	ptr = next_token(&input, " \t\r\n");
	if (ptr == NULL)
		goto cleanup;
	arg = next_token(&input, " \t\r\n");
	if ((strcasecmp(ptr, "set") == 0) &&
	    (arg != NULL))
		setoption(arg);
	else if ((strcasecmp(ptr, "server") == 0) ||
		 (strcasecmp(ptr, "lserver") == 0)) {
		setsrv(arg);
		show_settings(ISC_TRUE, ISC_TRUE);
	} else if (strcasecmp(ptr, "exit") == 0) {
		in_use = ISC_FALSE;
		goto cleanup;
	} else if (strcasecmp(ptr, "help") == 0 ||
		   strcasecmp(ptr, "?") == 0)
	{
		printf("The '%s' command is not yet implemented.\n", ptr);
		goto cleanup;
	} else if (strcasecmp(ptr, "finger") == 0 ||
		   strcasecmp(ptr, "root") == 0 ||
		   strcasecmp(ptr, "ls") == 0 ||
		   strcasecmp(ptr, "view") == 0)
	{
		printf("The '%s' command is not implemented.\n", ptr);
		goto cleanup;
	} else
		addlookup(ptr);
 cleanup:
	isc_mem_free(mctx, buf);
}

static void
parse_args(int argc, char **argv) {
	dig_lookup_t *lookup = NULL;
	isc_boolean_t have_lookup = ISC_FALSE;

	for (argc--, argv++; argc > 0; argc--, argv++) {
		debug("main parsing %s", argv[0]);
		if (argv[0][0] == '-') {
			if ((argv[0][1] == 'h') &&
			    (argv[0][2] == 0)) {
				show_usage();
				exit (1);
			}
			if (argv[0][1] != 0)
				setoption(&argv[0][1]);
			else
				have_lookup = ISC_TRUE;
		} else {
			if (!have_lookup) {
				have_lookup = ISC_TRUE;
				in_use = ISC_TRUE;
				lookup = addlookup(argv[0]);
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
		s = ISC_LIST_HEAD(l->my_server_list);
		while (s != NULL) {
			sp = s;
			s = ISC_LIST_NEXT(s, link);
			ISC_LIST_DEQUEUE(l->my_server_list, sp, link);
			isc_mem_free(mctx, sp);

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

static void
getinput(isc_task_t *task, isc_event_t *event) {
	UNUSED(task);
	if (global_event == NULL)
		global_event = event;
	while (in_use) {
		get_next_command();
		if (ISC_LIST_HEAD(lookup_list) != NULL) {
			start_lookup();
			return;
		}
	}
	isc_app_shutdown();
}

int
main(int argc, char **argv) {
	isc_result_t result;

	ISC_LIST_INIT(lookup_list);
	ISC_LIST_INIT(server_list);
	ISC_LIST_INIT(search_list);

	result = isc_app_start();
	check_result(result, "isc_app_start");

	setup_libs();
	progname = argv[0];

	parse_args(argc, argv);

	if (deprecation_msg) {
		fputs(
"Note:  nslookup is deprecated and may be removed from future releases.\n"
"Consider using the `dig' or `host' programs instead.  Run nslookup with\n"
"the `-sil[ent]' option to prevent this message from appearing.\n", stderr);
	}
	setup_system();

	if (in_use)
		result = isc_app_onrun(mctx, global_task, onrun_callback,
				       NULL);
	else
		result = isc_app_onrun(mctx, global_task, getinput, NULL);
	check_result(result, "isc_app_onrun");
	in_use = ISC_TF(!in_use);

	(void)isc_app_run();

	puts("");
	debug("done, and starting to shut down");
	if (global_event != NULL)
		isc_event_free(&global_event);
	destroy_libs();
	isc_app_finish();

	return (0);
}
