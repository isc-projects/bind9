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

/* $Id: dighost.c,v 1.58.2.5 2000/07/12 00:52:57 gson Exp $ */

/*
 * Notice to programmers:  Do not use this code as an example of how to
 * use the ISC library to perform DNS lookups.  Dig and Host both operate
 * on the request level, since they allow fine-tuning of output and are
 * intended as debugging tools.  As a result, they perform many of the
 * functions which could be better handled using the dns_resolver
 * functions in most applications.
 */

#include <config.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <limits.h>
#if (!(defined(HAVE_ADDRINFO) && defined(HAVE_GETADDRINFO)))
extern int h_errno;
#endif

#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/tsig.h>
#include <dst/dst.h>

#include <isc/app.h>
#include <isc/base64.h>
#include <isc/entropy.h>
#include <isc/lang.h>
#include <isc/lex.h>
#include <isc/netdb.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dig/dig.h>

ISC_LIST(dig_lookup_t) lookup_list;
ISC_LIST(dig_server_t) server_list;
ISC_LIST(dig_searchlist_t) search_list;

isc_boolean_t
	have_ipv6 = ISC_FALSE,
	specified_source = ISC_FALSE,
	free_now = ISC_FALSE,
	show_details = ISC_FALSE,
	usesearch = ISC_FALSE,
	qr = ISC_FALSE,
	is_dst_up = ISC_FALSE;

in_port_t port = 53;
unsigned int timeout = 0;
isc_mem_t *mctx = NULL;
isc_taskmgr_t *taskmgr = NULL;
isc_task_t *global_task = NULL;
isc_timermgr_t *timermgr = NULL;
isc_socketmgr_t *socketmgr = NULL;
isc_sockaddr_t bind_address;
isc_sockaddr_t bind_any;
char *rootspace[BUFSIZE];
isc_buffer_t rootbuf;
int sendcount = 0;
int sockcount = 0;
int ndots = -1;
int tries = 3;
int lookup_counter = 0;
char fixeddomain[MXNAME] = "";
int exitcode = 9;
char keynametext[MXNAME];
char keysecret[MXNAME] = "";
dns_name_t keyname;
dns_tsig_keyring_t *keyring = NULL;
isc_buffer_t *namebuf = NULL;
dns_tsigkey_t *key = NULL;
isc_boolean_t validated = ISC_TRUE;
isc_entropy_t *entp = NULL;

extern isc_boolean_t isc_mem_debugging;
isc_boolean_t debugging = ISC_FALSE;
char *progname = NULL;

static isc_boolean_t
cancel_lookup(dig_lookup_t *lookup);

static int
count_dots(char *string) {
	char *s;
	int i = 0;

	s = string;
	while (*s != '\0') {
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
	for (len = 0; len < r.length; len++) {
		printf("%02x ", r.base[len]);
		if (len != 0 && len % 16 == 0)
			printf("\n");
	}
	if (len % 16 != 0)
		printf("\n");
}


void
fatal(const char *format, ...) {
	va_list args;

	fprintf (stderr, "%s: ", progname);
	va_start(args, format);	
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	if (exitcode == 0)
		exitcode = 8;
#ifdef NEVER
	dighost_shutdown();
	free_lists(exitcode);
	if (mctx != NULL) {
		if (isc_mem_debugging)
			isc_mem_stats(mctx, stderr);
		isc_mem_destroy(&mctx);
	}
#endif
	exit(exitcode);
}

void
debug(const char *format, ...) {
	va_list args;

	if (debugging) {
		va_start(args, format);	
		vfprintf(stderr, format, args);
		va_end(args);
		fprintf(stderr, "\n");
	}
}

void
check_result(isc_result_t result, const char *msg) {
	if (result != ISC_R_SUCCESS) {
		exitcode = 1;
		fatal("%s: %s", msg, isc_result_totext(result));
	}
}

isc_boolean_t
isclass(char *text) {
	/*
	 * Tests if a field is a class, without needing isc libs
	 * initialized.  This list will have to be manually kept in 
	 * sync with what the libs support.
	 */
	const char *classlist[] = { "in", "hs", "chaos" };
	const int numclasses = 3;
	int i;

	for (i = 0; i < numclasses; i++)
		if (strcasecmp(text, classlist[i]) == 0)
			return (ISC_TRUE);

	return (ISC_FALSE);
}

isc_boolean_t
istype(char *text) {
	/*
	 * Tests if a field is a type, without needing isc libs
	 * initialized.  This list will have to be manually kept in 
	 * sync with what the libs support.
	 */
	const char *typelist[] = {"a", "ns", "md", "mf", "cname",
				  "soa", "mb", "mg", "mr", "null",
				  "wks", "ptr", "hinfo", "minfo",
				  "mx", "txt", "rp", "afsdb",
				  "x25", "isdn", "rt", "nsap",
				  "nsap_ptr", "sig", "key", "px",
				  "gpos", "aaaa", "loc", "nxt",
				  "srv", "naptr", "kx", "cert",
				  "a6", "dname", "opt", "unspec",
				  "tkey", "tsig", "axfr", "any"};
	const int numtypes = 42;
	int i;

	for (i = 0; i < numtypes; i++) {
		if (strcasecmp(text, typelist[i]) == 0)
			return (ISC_TRUE);
	}
	return (ISC_FALSE);
}

dig_lookup_t *
requeue_lookup(dig_lookup_t *lookold, isc_boolean_t servers) {
	dig_lookup_t *looknew;
	dig_server_t *s, *srv;

	debug("requeue_lookup()");

	if (free_now)
		return(ISC_R_SUCCESS);

	lookup_counter++;
	if (lookup_counter > LOOKUP_LIMIT)
		fatal("Too many lookups");
	looknew = isc_mem_allocate(mctx, sizeof(struct dig_lookup));
	if (looknew == NULL)
		fatal("Memory allocation failure in %s:%d",
		       __FILE__, __LINE__);
	looknew->pending = ISC_FALSE;
	strncpy(looknew->textname, lookold-> textname, MXNAME);
	strncpy(looknew->rttext, lookold-> rttext, 32);
	strncpy(looknew->rctext, lookold-> rctext, 32);
	looknew->namespace[0] = 0;
	looknew->sendspace[0] = 0;
	looknew->sendmsg = NULL;
	looknew->name = NULL;
	looknew->oname = NULL;
	looknew->timer = NULL;
	looknew->xfr_q = NULL;
	looknew->doing_xfr = lookold->doing_xfr;
	looknew->ixfr_serial = lookold->ixfr_serial;
	looknew->defname = lookold->defname;
	looknew->trace = lookold->trace;
	looknew->trace_root = lookold->trace_root;
	looknew->identify = lookold->identify;
	looknew->udpsize = lookold->udpsize;
	looknew->recurse = lookold->recurse;
	looknew->aaonly = lookold->aaonly;
	looknew->adflag = lookold->adflag;
	looknew->cdflag = lookold->cdflag;
	looknew->ns_search_only = lookold->ns_search_only;
	looknew->origin = NULL;
	looknew->querysig = NULL;
	looknew->retries = tries;
	looknew->nsfound = 0;
	looknew->tcp_mode = lookold->tcp_mode;
	looknew->comments = lookold->comments;
	looknew->stats = lookold->stats;
	looknew->section_question = lookold->section_question;
	looknew->section_answer = lookold->section_answer;
	looknew->section_authority = lookold->section_authority;
	looknew->section_additional = lookold->section_additional;
	looknew->new_search = ISC_FALSE;
	ISC_LIST_INIT(looknew->my_server_list);
	ISC_LIST_INIT(looknew->q);

	looknew->use_my_server_list = ISC_FALSE;
	if (servers) {
		looknew->use_my_server_list = lookold->use_my_server_list;
		if (looknew->use_my_server_list) {
			s = ISC_LIST_HEAD(lookold->my_server_list);
			while (s != NULL) {
				srv = isc_mem_allocate(mctx,
						sizeof(struct dig_server));
				if (srv == NULL)
					fatal("Memory allocation failure "
					      "in %s:%d", __FILE__, __LINE__);
				strncpy(srv->servername, s->servername,
					MXNAME);
				ISC_LIST_ENQUEUE(looknew->my_server_list, srv,
						 link);
				s = ISC_LIST_NEXT(s, link);
			}
		}
	}
	debug("before insertion, init@%p "
	       "-> %p, new@%p -> %p",
	      lookold, lookold->link.next, looknew, looknew->link.next);
	ISC_LIST_INSERTAFTER(lookup_list, lookold, looknew, link);
	debug("after insertion, init -> "
	      "%p, new = %p, new -> %p", 
	      lookold, looknew, looknew->link.next);
	return (looknew);
}	

void
setup_system(void) {
	char rcinput[MXNAME];
	FILE *fp;
	char *ptr;
	dig_server_t *srv;
	dig_searchlist_t *search;
	dig_lookup_t *l;
	isc_boolean_t get_servers;
	isc_result_t result;
	isc_buffer_t secretsrc;
	isc_buffer_t secretbuf;
	int secretsize;
	unsigned char *secretstore;
	isc_lex_t *lex = NULL;
	isc_stdtime_t now;
	
	debug("setup_system()");

	if (fixeddomain[0] != 0) {
		debug("using fixed domain %s", fixeddomain);
		search = isc_mem_allocate(mctx, sizeof(struct dig_server));
		if (search == NULL)
			fatal("Memory allocation failure in %s:%d",
			      __FILE__, __LINE__);
		strncpy(search->origin, fixeddomain, MXNAME - 1);
		ISC_LIST_PREPEND(search_list, search, link);
	}

	free_now = ISC_FALSE;
	get_servers = ISC_TF(server_list.head == NULL);
	fp = fopen(RESOLVCONF, "r");
	if (fp != NULL) {
		while (fgets(rcinput, MXNAME, fp) != 0) {
			ptr = strtok(rcinput, " \t\r\n");
			if (ptr != NULL) {
				if (get_servers &&
				    strcasecmp(ptr, "nameserver") == 0) {
					debug("got a nameserver line");
					ptr = strtok(NULL, " \t\r\n");
					if (ptr != NULL) {
						srv = isc_mem_allocate(mctx,
						   sizeof(struct dig_server));
						if (srv == NULL)
							fatal("Memory "
							      "allocation "
							      "failure in "
							      "%s:%d",
							      __FILE__,
							      __LINE__);
							strncpy((char *)srv->
								servername,
								ptr,
								MXNAME - 1);
							ISC_LIST_APPEND
								(server_list,
								 srv, link);
					}
				} else if (strcasecmp(ptr, "options") == 0) {
					ptr = strtok(NULL, " \t\r\n");
					if (ptr != NULL) {
						if((strncasecmp(ptr, "ndots:",
							    6) == 0) &&
						    (ndots == -1)) {
							ndots = atoi(
							      &ptr[6]);
							debug("ndots is "
							       "%d.",
							       ndots);
						}
					}
				} else if ((strcasecmp(ptr, "search") == 0)
					   && usesearch){
					while ((ptr = strtok(NULL, " \t\r\n"))
					       != NULL) {
						search = isc_mem_allocate(
						   mctx, sizeof(struct
								dig_server));
						if (search == NULL)
							fatal("Memory "
							      "allocation "
							      "failure in %s:"
							      "%d", __FILE__, 
							      __LINE__);
						strncpy(search->
							origin,
							ptr,
							MXNAME - 1);
						ISC_LIST_APPEND
							(search_list,
							 search,
							 link);
					}
				} else if ((strcasecmp(ptr, "domain") == 0) &&
					   (fixeddomain[0] == 0 )){
					while ((ptr = strtok(NULL, " \t\r\n"))
					       != NULL) {
						search = isc_mem_allocate(
						   mctx, sizeof(struct
								dig_server));
						if (search == NULL)
							fatal("Memory "
							      "allocation "
							      "failure in %s:"
							      "%d", __FILE__, 
							      __LINE__);
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
		fclose(fp);
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

	if (keysecret[0] != 0) {
		debug("keyring");
		result = dns_tsigkeyring_create(mctx, &keyring);
		check_result(result, "dns_tsigkeyring_create");
		debug("buffer");
		result = isc_buffer_allocate(mctx, &namebuf, MXNAME);
		check_result(result, "isc_buffer_allocate");
		debug("name");
		dns_name_init(&keyname, NULL);
		check_result(result, "dns_name_init");
		isc_buffer_putstr(namebuf, keynametext);
		secretsize = strlen(keysecret) * 3 / 4;
		debug("secretstore");
		secretstore = isc_mem_get(mctx, secretsize);
		if (secretstore == NULL)
			fatal("Memory allocation failure in %s:%d",
			      __FILE__, __LINE__);
		isc_buffer_init(&secretsrc, keysecret, strlen(keysecret));
		isc_buffer_add(&secretsrc, strlen(keysecret));
		isc_buffer_init(&secretbuf, secretstore, secretsize);
		debug("lex");
		result = isc_lex_create(mctx, strlen(keysecret), &lex);
		check_result(result, "isc_lex_create");
		result = isc_lex_openbuffer(lex, &secretsrc);
		check_result(result, "isc_lex_openbuffer");
		result = isc_base64_tobuffer(lex, &secretbuf, -1);
		if (result != ISC_R_SUCCESS) {
			printf(";; Couldn't create key %s: %s\n",
			       keynametext, isc_result_totext(result));
			isc_lex_close(lex);
			isc_lex_destroy(&lex);
			goto SYSSETUP_FAIL;
		}
		secretsize = isc_buffer_usedlength(&secretbuf);
		debug("close");
		isc_lex_close(lex);
		isc_lex_destroy(&lex);
		isc_stdtime_get(&now);
		
		debug("namefromtext");
		result = dns_name_fromtext(&keyname, namebuf,
					   dns_rootname, ISC_FALSE,
					   namebuf);
		if (result != ISC_R_SUCCESS) {
			printf (";; Couldn't create key %s: %s\n",
				keynametext, dns_result_totext(result));
			goto SYSSETUP_FAIL;
		}
		debug("tsigkey");
		result = dns_tsigkey_create(&keyname, dns_tsig_hmacmd5_name,
					    secretstore, secretsize,
					    ISC_TRUE, NULL, now, now, mctx,
					    keyring, &key);
		if (result != ISC_R_SUCCESS) {
			printf(";; Couldn't create key %s: %s\n",
			       keynametext, dns_result_totext(result));
		}
		isc_mem_put(mctx, secretstore, secretsize);
		dns_name_invalidate(&keyname);
		isc_buffer_free(&namebuf);
		return;
	SYSSETUP_FAIL:
		isc_mem_put(mctx, secretstore, secretsize);
		dns_name_invalidate(&keyname);
		isc_buffer_free(&namebuf);
		dns_tsigkeyring_destroy(&keyring);
		return;
	}
}
	
void
setup_libs(void) {
	isc_result_t result;

	debug("setup_libs()");

	/*
	 * Warning: This is not particularly good randomness.  We'll
	 * just use random() now for getting id values, but doing so
	 * does NOT insure that id's cann't be guessed.
	 */
	srandom(getpid() + (int)&setup_libs);

	result = isc_app_start();
	check_result(result, "isc_app_start");

	result = isc_net_probeipv4();
	check_result(result, "isc_net_probeipv4");

	result = isc_net_probeipv6();
	if (result == ISC_R_SUCCESS)
		have_ipv6 = ISC_TRUE;

	result = isc_mem_create(0, 0, &mctx);
	check_result(result, "isc_mem_create");

	result = isc_taskmgr_create(mctx, 1, 0, &taskmgr);
	check_result(result, "isc_taskmgr_create");

	result = isc_task_create(taskmgr, 0, &global_task);
	check_result(result, "isc_task_create");

	result = isc_timermgr_create(mctx, &timermgr);
	check_result(result, "isc_timermgr_create");

	result = isc_socketmgr_create(mctx, &socketmgr);
	check_result(result, "isc_socketmgr_create");

	result = isc_entropy_create(mctx, &entp);
	check_result(result, "isc_entropy_create");

	result = dst_lib_init(mctx, entp, 0);
	check_result(result, "dst_lib_init");
	is_dst_up = ISC_TRUE;
}

static void
add_opt(dns_message_t *msg, isc_uint16_t udpsize) {
	dns_rdataset_t *rdataset = NULL;
	dns_rdatalist_t *rdatalist = NULL;
	dns_rdata_t *rdata = NULL;
	isc_result_t result;

	debug("add_opt()");
	result = dns_message_gettemprdataset(msg, &rdataset);
	check_result(result, "dns_message_gettemprdataset");
	dns_rdataset_init(rdataset);
	result = dns_message_gettemprdatalist(msg, &rdatalist);
	check_result(result, "dns_message_gettemprdatalist");
	result = dns_message_gettemprdata(msg, &rdata);
	check_result(result, "dns_message_gettemprdata");
	
	debug("setting udp size of %d", udpsize);
	rdatalist->type = dns_rdatatype_opt;
	rdatalist->covers = 0;
	rdatalist->rdclass = udpsize;
	rdatalist->ttl = 0;
	rdata->data = NULL;
	rdata->length = 0;
	ISC_LIST_INIT(rdatalist->rdata);
	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
	dns_rdatalist_tordataset(rdatalist, rdataset);
	result = dns_message_setopt(msg, rdataset);
	check_result(result, "dns_message_setopt");
}

static void
add_question(dns_message_t *message, dns_name_t *name,
	     dns_rdataclass_t rdclass, dns_rdatatype_t rdtype)
{
	dns_rdataset_t *rdataset;
	isc_result_t result;

	debug("add_question()"); 
	rdataset = NULL;
	result = dns_message_gettemprdataset(message, &rdataset);
	check_result(result, "dns_message_gettemprdataset()");
	dns_rdataset_init(rdataset);
	dns_rdataset_makequestion(rdataset, rdclass, rdtype);
	ISC_LIST_APPEND(name->list, rdataset, link);
}

/*
 * Return ISC_TRUE if we're in the process of shutting down on the
 * return.
 */
static isc_boolean_t
check_next_lookup(dig_lookup_t *lookup) {
	dig_lookup_t *next;
	dig_query_t *query;
	isc_boolean_t still_working=ISC_FALSE;
	
	if (free_now)
		return (ISC_TRUE);

	debug("check_next_lookup(%p)", lookup);
	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		if (query->working) {
			debug("still have a worker", stderr);
			still_working=ISC_TRUE;
		}
	}
	if (still_working)
		return (ISC_FALSE);

	debug("have %d retries left for %s",
	       lookup->retries-1, lookup->textname);
	debug("lookup %s pending", lookup->pending ? "is" : "is not");

	next = ISC_LIST_NEXT(lookup, link);
	
	if (lookup->tcp_mode) {
		if (next == NULL) {
			debug("shutting down", stderr);
			dighost_shutdown();
			return (ISC_TRUE);
		}
		if (next->sendmsg == NULL) {
			debug("setting up for TCP");
			setup_lookup(next);
			do_lookup(next);
		}
	} else {
		if (!lookup->pending) {
			if (next == NULL) {
				debug("shutting down", stderr);
				dighost_shutdown();
				return (ISC_TRUE);
			}
			if (next->sendmsg == NULL) {
				debug("setting up for UDP");
				setup_lookup(next);
				do_lookup(next);
			}
		} else {
			if (lookup->retries > 1) {
				debug("retrying");
				lookup->retries --;
				if (lookup->timer != NULL)
					isc_timer_detach(&lookup->timer);
				send_udp(lookup);
			} else {
				debug("cancelling");
				return(cancel_lookup(lookup));
			}
		}
	}
	return (ISC_FALSE);
}


static void
followup_lookup(dns_message_t *msg, dig_query_t *query,
		dns_section_t section) {
	dig_lookup_t *lookup = NULL;
	dig_server_t *srv = NULL;
	dns_rdataset_t *rdataset = NULL;
	dns_rdata_t rdata;
	dns_name_t *name = NULL;
	isc_result_t result, loopresult;
	isc_buffer_t *b = NULL;
	isc_region_t r;
	isc_boolean_t success = ISC_FALSE;
	int len;

	debug("followup_lookup()"); 
	if (free_now)
		return;
	result = dns_message_firstname(msg,section);
	if (result != ISC_R_SUCCESS) {
		debug("firstname returned %s",
			isc_result_totext(result));
		if ((section == DNS_SECTION_ANSWER) &&
		    (query->lookup->trace || query->lookup->ns_search_only))
			followup_lookup (msg, query, DNS_SECTION_AUTHORITY);
                return;
	}

	debug("following up %s", query->lookup->textname);

	for (;;) {
		name = NULL;
		dns_message_currentname(msg, section, &name);
		for (rdataset = ISC_LIST_HEAD(name->list);
		     rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link)) {
			loopresult = dns_rdataset_first(rdataset);
			while (loopresult == ISC_R_SUCCESS) {
				dns_rdataset_current(rdataset, &rdata);
				debug("got rdata with type %d",
				       rdata.type);
				if ((rdata.type == dns_rdatatype_ns) &&
				    (!query->lookup->trace_root ||
				     (query->lookup->nsfound < ROOTNS)))
				{
					query->lookup->nsfound++;
					result = isc_buffer_allocate(mctx, &b,
								     BUFSIZE);
					check_result(result,
						      "isc_buffer_allocate");
					result = dns_rdata_totext(&rdata,
								  NULL,
								  b);
					check_result(result,
						      "dns_rdata_totext");
					isc_buffer_usedregion(b, &r);
					len = r.length-1;
					if (len >= MXNAME)
						len = MXNAME-1;
				/* Initialize lookup if we've not yet */
					debug("found NS %d %.*s",
						 (int)r.length, (int)r.length,
						 (char *)r.base);
					if (!success) {
						success = ISC_TRUE;
						lookup_counter++;
						lookup = requeue_lookup
							(query->lookup,
							 ISC_FALSE);
						lookup->doing_xfr = ISC_FALSE;
						lookup->defname = ISC_FALSE;
						lookup->use_my_server_list = 
							ISC_TRUE;
						if (section ==
						    DNS_SECTION_ANSWER) {
						      lookup->trace =
								ISC_FALSE;
						      lookup->ns_search_only =
								ISC_FALSE;
						}
						else {
						      lookup->trace =
								query->
								lookup->trace;
						      lookup->ns_search_only =
							query->
							lookup->ns_search_only;
						}
						lookup->trace_root = ISC_FALSE;
						ISC_LIST_INIT(lookup->
							      my_server_list);
					}
					srv = isc_mem_allocate(mctx,
						       sizeof(struct dig_server));
					if (srv == NULL)
						fatal("Memory allocation "
						      "failure in %s:%d",
						      __FILE__, __LINE__);
					strncpy(srv->servername, 
						(char *)r.base, len);
					srv->servername[len] = 0;
					debug("adding server %s",
					       srv->servername);
					ISC_LIST_APPEND
						(lookup->my_server_list,
						 srv, link);
					isc_buffer_free(&b);
				}
				loopresult = dns_rdataset_next(rdataset);
			}
		}
		result = dns_message_nextname (msg, section);
		if (result != ISC_R_SUCCESS)
			break;
	}
	if ((lookup == NULL) && (section == DNS_SECTION_ANSWER) &&
	    (query->lookup->trace || query->lookup->ns_search_only))
		followup_lookup(msg, query, DNS_SECTION_AUTHORITY);
}

static void
next_origin(dns_message_t *msg, dig_query_t *query) {
	dig_lookup_t *lookup;

	UNUSED(msg);

	debug("next_origin()"); 
	if (free_now)
		return;
	debug("following up %s", query->lookup->textname);

	if (query->lookup->origin == NULL) {
		/*
		 * Then we just did rootorg; there's nothing left.
		 */
		debug("made it to the root with nowhere to go");
		return;
	}
	lookup = requeue_lookup(query->lookup, ISC_TRUE);
	lookup->defname = ISC_FALSE;
	lookup->origin = ISC_LIST_NEXT(query->lookup->origin, link);
}


static void
insert_soa(dig_lookup_t *lookup) {
	isc_result_t result;
	dns_rdata_soa_t soa;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdatalist = NULL;
	dns_rdataset_t *rdataset = NULL;
	dns_name_t *soaname = NULL;
	
	debug("insert_soa()");
	soa.mctx = mctx;
	soa.serial = lookup->ixfr_serial;
	soa.refresh = 1;
	soa.retry = 1;
	soa.expire = 1;
	soa.minimum = 1;
	soa.common.rdclass = dns_rdataclass_in;
	soa.common.rdtype = dns_rdatatype_soa;

	dns_name_init(&soa.origin, NULL);
	dns_name_init(&soa.mname, NULL);

	dns_name_clone(lookup->name, &soa.origin);
	dns_name_clone(lookup->name, &soa.mname);
	
	isc_buffer_init(&lookup->rdatabuf, lookup->rdatastore,
			MXNAME);

	result = dns_message_gettemprdata(lookup->sendmsg, &rdata);
	check_result(result, "dns_message_gettemprdata");
	result = dns_rdata_fromstruct(rdata, dns_rdataclass_in,
				      dns_rdatatype_soa, &soa,
				      &lookup->rdatabuf);
	check_result(result, "isc_rdata_fromstruct");

	result = dns_message_gettemprdatalist(lookup->sendmsg, &rdatalist);
	check_result(result, "dns_message_gettemprdatalist");
	
	result = dns_message_gettemprdataset(lookup->sendmsg, &rdataset);
	check_result(result, "dns_message_gettemprdataset");

	dns_rdatalist_init(rdatalist);
	rdatalist->type = dns_rdatatype_soa;
	rdatalist->rdclass = dns_rdataclass_in;
	rdatalist->covers = dns_rdatatype_soa;
	rdatalist->ttl = 1;
	ISC_LIST_INIT(rdatalist->rdata);
	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);

	dns_rdataset_init(rdataset);
	dns_rdatalist_tordataset(rdatalist, rdataset);

	result = dns_message_gettempname(lookup->sendmsg, &soaname);
	check_result(result, "dns_message_gettempname");
	dns_name_init(soaname, NULL);
	dns_name_clone(lookup->name, soaname);
	ISC_LIST_INIT(soaname->list);
	ISC_LIST_APPEND(soaname->list, rdataset, link);
	dns_message_addname(lookup->sendmsg, soaname, DNS_SECTION_AUTHORITY);
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
	isc_constregion_t tr;
	isc_buffer_t b;
	char store[MXNAME];
	
	REQUIRE(lookup != NULL);

	debug("setup_lookup(%p)",lookup);

	if (free_now)
		return;

	debug("setting up for looking up %s @%p->%p", 
		lookup->textname, lookup,
		lookup->link.next);

	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER,
				    &lookup->sendmsg);
	check_result(result, "dns_message_create");

	if (lookup->new_search) {
		debug("resetting lookup counter.");
		lookup_counter = 0;
	}

	result = dns_message_gettempname(lookup->sendmsg, &lookup->name);
	check_result(result, "dns_message_gettempname");
	dns_name_init(lookup->name, NULL);

	isc_buffer_init(&lookup->namebuf, lookup->namespace,
			sizeof(lookup->namespace));
	isc_buffer_init(&lookup->onamebuf, lookup->onamespace,
			sizeof(lookup->onamespace));

	if ((count_dots(lookup->textname) >= ndots) || lookup->defname)
		lookup->origin = NULL; /* Force root lookup */
	debug("lookup->origin = %p", lookup->origin);
	if (lookup->origin != NULL) {
		debug("trying origin %s", lookup->origin->origin);
		result = dns_message_gettempname(lookup->sendmsg,
						 &lookup->oname);
		check_result(result, "dns_message_gettempname");
		dns_name_init(lookup->oname, NULL);
		len = strlen(lookup->origin->origin);
		isc_buffer_init(&b, lookup->origin->origin, len);
		isc_buffer_add(&b, len);
		result = dns_name_fromtext(lookup->oname, &b, dns_rootname,
					   ISC_FALSE, &lookup->onamebuf);
		if (result != ISC_R_SUCCESS) {
			dns_message_puttempname(lookup->sendmsg,
						&lookup->name);
			dns_message_puttempname(lookup->sendmsg,
						&lookup->oname);
			fatal("%s is not a legal name syntax (%s)",
			      lookup->origin->origin,
			      dns_result_totext(result));
		}
		if (!lookup->trace_root) {
			len = strlen(lookup->textname);
			isc_buffer_init(&b, lookup->textname, len);
			isc_buffer_add(&b, len);
			result = dns_name_fromtext(lookup->name, &b,
						   lookup->oname, ISC_FALSE, 
						   &lookup->namebuf);
		} else {
			dns_name_clone(dns_rootname, lookup->name);
		}			
		if (result != ISC_R_SUCCESS) {
			dns_message_puttempname(lookup->sendmsg,
						&lookup->name);
			dns_message_puttempname(lookup->sendmsg,
						&lookup->oname);
			fatal("%s is not a legal name syntax (%s)",
			      lookup->textname, dns_result_totext(result));
		}
		dns_message_puttempname(lookup->sendmsg, &lookup->oname);
	} else {
		debug("using root origin");
		if (!lookup->trace_root) {
			len = strlen(lookup->textname);
			isc_buffer_init(&b, lookup->textname, len);
			isc_buffer_add(&b, len);
			result = dns_name_fromtext(lookup->name, &b,
						   dns_rootname,
						   ISC_FALSE,
						   &lookup->namebuf);
		} else {
			dns_name_clone(dns_rootname, lookup->name);
		}
		if (result != ISC_R_SUCCESS) {
			dns_message_puttempname(lookup->sendmsg,
						&lookup->name);
			isc_buffer_init(&b, store, MXNAME);
			res2 = dns_name_totext(dns_rootname, ISC_FALSE, &b);
			check_result(res2, "dns_name_totext");
			isc_buffer_usedregion(&b, &r);
			fatal("%s/%.*s is not a legal name syntax "
			      "(%s)", lookup->textname, (int)r.length,
			      (char *)r.base, dns_result_totext(result));
		}
	}		
	isc_buffer_init(&b, store, MXNAME);
	dns_name_totext(lookup->name, ISC_FALSE, &b);
	isc_buffer_usedregion(&b, &r);
	trying((int)r.length, (char *)r.base, lookup);
	ENSURE(dns_name_isabsolute(lookup->name));
	if (lookup->rctext[0] == 0)
		strcpy(lookup->rctext, "IN");
	if (lookup->rttext[0] == 0)
		strcpy(lookup->rttext, "A");

	lookup->sendmsg->id = (unsigned short)(random() & 0xFFFF);
	lookup->sendmsg->opcode = dns_opcode_query;
	lookup->msgcounter = 0;
	/*
	 * If this is a trace request, completely disallow recursion, since
	 * it's meaningless for traces.
	 */
	if (lookup->recurse && !lookup->trace && !lookup->ns_search_only) {
		debug("recursive query");
		lookup->sendmsg->flags |= DNS_MESSAGEFLAG_RD;
	}

	if (lookup->aaonly) {
		debug("AA query");
		lookup->sendmsg->flags |= DNS_MESSAGEFLAG_AA;
	}

	if (lookup->adflag) {
		debug("AD query");
		lookup->sendmsg->flags |= DNS_MESSAGEFLAG_AD;
	}

	if (lookup->cdflag) {
		debug("CD query");
		lookup->sendmsg->flags |= DNS_MESSAGEFLAG_CD;
	}

	dns_message_addname(lookup->sendmsg, lookup->name,
			    DNS_SECTION_QUESTION);

	if (lookup->trace_root) {
		debug("doing trace_root");
		tr.base = "SOA";
		tr.length = 3;
	} else {
		tr.base = lookup->rttext;
		tr.length = strlen(lookup->rttext);
	}
	debug("data type is %s", lookup->rttext);
	result = dns_rdatatype_fromtext(&rdtype, (isc_textregion_t *)&tr);
	check_result(result, "dns_rdatatype_fromtext");
	if ((rdtype == dns_rdatatype_axfr) ||
	    (rdtype == dns_rdatatype_ixfr)) {
		lookup->doing_xfr = ISC_TRUE;
		/*
		 * Force TCP mode if we're doing an xfr.
		 */
		lookup->tcp_mode = ISC_TRUE;
	}
	if (lookup->trace_root) {
		tr.base = "IN";
		tr.length = 2;
	} else {
		tr.base = lookup->rctext;
		tr.length = strlen(lookup->rctext);
	}
	result = dns_rdataclass_fromtext(&rdclass, (isc_textregion_t *)&tr);
	check_result(result, "dns_rdataclass_fromtext");
	add_question(lookup->sendmsg, lookup->name, rdclass, rdtype);

	if (rdtype == dns_rdatatype_ixfr)
		insert_soa(lookup);

	if (key != NULL) {
		debug("initializing keys");
		result = dns_message_settsigkey(lookup->sendmsg, key);
		check_result(result, "dns_message_settsigkey");
		lookup->tsigctx = NULL;
		lookup->querysig = NULL;
	}

	debug("starting to render the message");
	isc_buffer_init(&lookup->sendbuf, lookup->sendspace, COMMSIZE);
	result = dns_message_renderbegin(lookup->sendmsg, &lookup->sendbuf);
	check_result(result, "dns_message_renderbegin");
	if (lookup->udpsize > 0) {
		add_opt(lookup->sendmsg, lookup->udpsize);
	}
	result = dns_message_rendersection(lookup->sendmsg,
					   DNS_SECTION_QUESTION, 0);
	check_result(result, "dns_message_rendersection");
	result = dns_message_rendersection(lookup->sendmsg,
					   DNS_SECTION_AUTHORITY, 0);
	check_result(result, "dns_message_rendersection");
	result = dns_message_renderend(lookup->sendmsg);
	check_result(result, "dns_message_renderend");
	debug("done rendering");

	lookup->pending = ISC_FALSE;

	if (lookup->use_my_server_list)
		serv = ISC_LIST_HEAD(lookup->my_server_list);
	else
		serv = ISC_LIST_HEAD(server_list);
	for (; serv != NULL;
	     serv = ISC_LIST_NEXT(serv, link)) {
		query = isc_mem_allocate(mctx, sizeof(dig_query_t));
		if (query == NULL)
			fatal("Memory allocation failure in %s:%d",
			      __FILE__, __LINE__);
		debug("create query %p linked to lookup %p",
		       query, lookup);
		query->lookup = lookup;
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		query->first_pass = ISC_TRUE;
		query->first_soa_rcvd = ISC_FALSE;
		query->second_rr_rcvd = ISC_FALSE;
		query->second_rr_serial = 0;
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
	if (!ISC_LIST_EMPTY(lookup->q) && qr) {
		printmessage(ISC_LIST_HEAD(lookup->q), lookup->sendmsg,
			     ISC_TRUE);
	}
}	

static void
send_done(isc_task_t *task, isc_event_t *event) {
	UNUSED(task);

	isc_event_free(&event);

	debug("send_done()");
}

/*
 * Return ISC_TRUE if we're in the process of shutting down
 */
static isc_boolean_t
cancel_lookup(dig_lookup_t *lookup) {
	dig_query_t *query = NULL;

	debug("cancel_lookup()");
	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		if (query->working) {
			debug("cancelling a worker");
		}
		if (query->sock != NULL) {
			isc_socket_cancel(query->sock, global_task,
					  ISC_SOCKCANCEL_ALL);
			isc_socket_detach(&query->sock);
			sockcount--;
			debug("socket = %d", sockcount);
		}
	}
	lookup->pending = ISC_FALSE;
	lookup->retries = 0;
	return(check_next_lookup(lookup));
}

static void
recv_done(isc_task_t *task, isc_event_t *event);

static void
connect_timeout(isc_task_t *task, isc_event_t *event);

void
send_udp(dig_lookup_t *lookup) {
	dig_query_t *query;
	isc_result_t result;
	unsigned int local_timeout;

	debug("send_udp()");

	if (timeout != INT_MAX) {
		if (timeout == 0) {
			if (lookup->tcp_mode)
				local_timeout = TCP_TIMEOUT;
			else
				local_timeout = UDP_TIMEOUT;
		} else
			local_timeout = timeout;
		debug ("have local timeout of %d", local_timeout);
		isc_interval_set(&lookup->interval, local_timeout, 0);
		result = isc_timer_create(timermgr, isc_timertype_once, NULL,
					  &lookup->interval, global_task,
					  connect_timeout, lookup,
					  &lookup->timer);
		check_result(result, "isc_timer_create");
	}
for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		debug("working on lookup %p, query %p",
		       query->lookup, query);
		ISC_LIST_ENQUEUE(query->recvlist, &query->recvbuf, link);
		query->working = ISC_TRUE;
		debug("recving with lookup=%p, query=%p, sock=%p",
		       query->lookup, query,
		       query->sock);
		result = isc_socket_recvv(query->sock, &query->recvlist, 1,
					  global_task, recv_done, query);
		check_result(result, "isc_socket_recvv");
		sendcount++;
		debug("sent count number %d", sendcount);
		ISC_LIST_ENQUEUE(query->sendlist, &lookup->sendbuf, link);
		debug("sending a request");
		result = isc_time_now(&query->time_sent);
		check_result(result, "isc_time_now");
		ENSURE(query->sock != NULL);
		result = isc_socket_sendtov(query->sock, &query->sendlist,
					    global_task, send_done, query,
					    &query->sockaddr, NULL);
		check_result(result, "isc_socket_sendtov");
	}
}

/*
 * connect_timeout is used for both UDP recieves and TCP connects.
 */
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

	isc_event_free(&event);

	debug("buffer allocate connect_timeout");
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
				if ((q->lookup->retries > 1) &&
				    (!q->lookup->tcp_mode))
					printf(";; Connection to server %.*s "
					       "for %s timed out.  "
					       "Retrying %d.\n",
					       (int)r.length, r.base,
					       q->lookup->textname,
					       q->lookup->retries-1);
				else {
					printf(";; Connection to "
					       "server %.*s "
					       "for %s timed out.  "
					       "Giving up.\n",
					       (int)r.length, r.base,
					       q->lookup->textname);
				}
			}
			isc_socket_cancel(q->sock, task,
					  ISC_SOCKCANCEL_ALL);
		}
	}
	ENSURE(lookup->timer != NULL);
	isc_timer_detach(&lookup->timer);
	isc_buffer_free(&b);
	debug("done with connect_timeout()");
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

	if (free_now) {
		isc_event_free(&event);
		return;
	}

	sevent = (isc_socketevent_t *)event;	

	query = event->ev_arg;

	if (sevent->result == ISC_R_CANCELED) {
		query->working = ISC_FALSE;
		isc_event_free(&event);
		check_next_lookup(query->lookup);
		return;
	}
	if (sevent->result != ISC_R_SUCCESS) {
		debug("buffer allocate connect_timeout");
		result = isc_buffer_allocate(mctx, &b, 256);
		check_result(result, "isc_buffer_allocate");
		result = isc_sockaddr_totext(&query->sockaddr, b);
		check_result(result, "isc_sockaddr_totext");
		isc_buffer_usedregion(b, &r);
		printf("%.*s: %s\n", (int)r.length, r.base,
		       isc_result_totext(sevent->result));
		isc_buffer_free(&b);
		query->working = ISC_FALSE;
		sockcount--;
		debug("socket = %d",sockcount);
		isc_socket_detach(&query->sock);
		isc_event_free(&event);
		check_next_lookup(query->lookup);
		return;
	}
	b = ISC_LIST_HEAD(sevent->bufferlist);
	ISC_LIST_DEQUEUE(sevent->bufferlist, &query->lengthbuf, link);
	length = isc_buffer_getuint16(b);
	if (length > COMMSIZE) {
		isc_event_free(&event);
		fatal("Length of %X was longer than I can handle!",
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
	debug("recving with lookup=%p, query=%p",
	       query->lookup, query);
	result = isc_socket_recvv(query->sock, &query->recvlist, length, task,
				  recv_done, query);
	check_result(result, "isc_socket_recvv");
	debug("resubmitted recv request with length %d", length);
	isc_event_free(&event);
}

static void
launch_next_query(dig_query_t *query, isc_boolean_t include_question) {
	isc_result_t result;

	debug("launch_next_query()");

	if (free_now)
		return;

	if (!query->lookup->pending) {
		debug("ignoring launch_next_query because !pending");
		sockcount--;
		debug("socket = %d", sockcount);
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
		ISC_LIST_ENQUEUE(query->sendlist, &query->lookup->sendbuf,
				 link);
	}
	ISC_LIST_ENQUEUE(query->lengthlist, &query->lengthbuf, link);

	result = isc_socket_recvv(query->sock, &query->lengthlist, 0,
				  global_task, tcp_length_done, query);
	check_result(result, "isc_socket_recvv");
	sendcount++;
	if (!query->first_soa_rcvd) {
		debug("sending a request");
		result = isc_time_now(&query->time_sent);
		check_result(result, "isc_time_now");
		result = isc_socket_sendv(query->sock, &query->sendlist,
					  global_task, send_done, query);
		check_result(result, "isc_socket_recvv");
	}
	query->waiting_connect = ISC_FALSE;
	check_next_lookup(query->lookup);
	return;
}
	
static void
connect_done(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	isc_socketevent_t *sevent = NULL;
	dig_query_t *query = NULL;
	isc_buffer_t *b = NULL;
	isc_region_t r;

	UNUSED(task);

	REQUIRE(event->ev_type == ISC_SOCKEVENT_CONNECT);

	debug("connect_done()");

	if (free_now) {
		isc_event_free(&event);
		return;
	}

	sevent = (isc_socketevent_t *)event;
	query = sevent->ev_arg;

	REQUIRE(query->waiting_connect);

	query->waiting_connect = ISC_FALSE;

	if (sevent->result != ISC_R_SUCCESS) {
		debug("buffer allocate connect_timeout");
		result = isc_buffer_allocate(mctx, &b, 256);
		check_result(result, "isc_buffer_allocate");
		result = isc_sockaddr_totext(&query->sockaddr, b);
		check_result(result, "isc_sockaddr_totext");
		isc_buffer_usedregion(b, &r);
		printf(";; Connection to server %.*s for %s failed: %s.\n",
		       (int)r.length, r.base, query->lookup->textname,
		       isc_result_totext(sevent->result));
		if (exitcode < 9)
			exitcode = 9;
		isc_buffer_free(&b);
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		isc_event_free(&event);
		check_next_lookup(query->lookup);
		return;
	}
	launch_next_query(query, ISC_TRUE);
	isc_event_free(&event);
}


#if 0
static isc_boolean_t
msg_contains_soa(dns_message_t *msg, dig_query_t *query) {
	isc_result_t result;
	dns_name_t *name=NULL;
	
	debug("msg_contains_soa()");
	
	result = dns_message_findname(msg, DNS_SECTION_ANSWER,
				      query->lookup->name, dns_rdatatype_soa,
				      0, &name, NULL);
	if (result == ISC_R_SUCCESS) {
		debug("found SOA", stderr);
		return (ISC_TRUE);
	} else {
		debug("didn't find SOA, result=%d:%s",
		      result, dns_result_totext(result));
		return (ISC_FALSE);
	}
	
}
#endif

/*
 * Returns true if we should call cancel_lookup().  This is a hack.
 */
static isc_boolean_t
check_for_more_data(dig_query_t *query, dns_message_t *msg,
		    isc_socketevent_t *sevent)
{
	dns_rdataset_t *rdataset = NULL;
	dns_rdata_t rdata;
	dns_rdata_soa_t soa;
	isc_result_t result;
	isc_buffer_t b;
	isc_region_t r;
	char *abspace[MXNAME];

	debug("check_for_more_data()");

	/*
	 * By the time we're in this routine, we know we're doing
	 * either an AXFR or IXFR.  If there's no second_rr_type,
	 * then we don't yet know which kind of answer we got back
	 * from the server.  Here, we're going to walk through the
	 * rr's in the message, acting as necessary whenever we hit
	 * an SOA rr.
	 */
	
	result = dns_message_firstname(msg, DNS_SECTION_ANSWER);
	if (result != ISC_R_SUCCESS) {
		puts("; Transfer failed.");
		query->working = ISC_FALSE;
		return (ISC_TRUE);
	}
#ifdef NEVER
	check_result(result, "dns_message_firstname");
#endif
	do {
		dns_name_t *name = NULL;
		dns_message_currentname(msg, DNS_SECTION_ANSWER,
					&name);
		for (rdataset = ISC_LIST_HEAD(name->list);
		     rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link)) {
			result = dns_rdataset_first(rdataset);
			if (result != ISC_R_SUCCESS)
				continue;
			do {
				dns_rdataset_current(rdataset, &rdata);
				/*
				 * If this is the first rr, make sure
				 * it's an SOA
				 */
				if ((!query->first_soa_rcvd) &&
				    (rdata.type != dns_rdatatype_soa)) {
					puts("; Transfer failed.  "
					     "Didn't start with "
					     "SOA answer.");
					query->working = ISC_FALSE;
					return (ISC_TRUE);
				}
				if ((!query->second_rr_rcvd) &&
				    (rdata.type != dns_rdatatype_soa)) {
					query->second_rr_rcvd = ISC_TRUE;
					query->second_rr_serial = 0;
					debug("got the second rr as nonsoa");
					continue;
				}

				/*
				 * If the record is anything except an SOA
				 * now, just continue on...
				 */
				if (rdata.type != dns_rdatatype_soa)
					goto next_rdata;
				/* Now we have an SOA.  Work with it. */
				debug("got an SOA");
				result = dns_rdata_tostruct(&rdata,
							    &soa,
							    mctx);
				check_result(result,
					     "dns_rdata_tostruct");
				if (!query->first_soa_rcvd) {
					query->first_soa_rcvd =
						ISC_TRUE;
					query->first_rr_serial =
						soa.serial;
					debug("this is the first %d",
					       query->lookup->ixfr_serial);
					if (query->lookup->ixfr_serial >=
					    soa.serial) {
						dns_rdata_freestruct(&soa);
						goto xfr_done;
					}
					dns_rdata_freestruct(&soa);
					goto next_rdata;
				}
				if (!query->second_rr_rcvd) {
					debug("this is the second %d",
					       query->lookup->ixfr_serial);
					query->second_rr_rcvd = ISC_TRUE;
					query->second_rr_serial =
						soa.serial;
					dns_rdata_freestruct(&soa);
					goto next_rdata;
				}
				if (query->second_rr_serial == 0) {
					/*
					 * If the second RR was a non-SOA
					 * record, and we're getting any
					 * other SOA, then this is an
					 * AXFR, and we're done.
					 */
					debug("done, since axfr");
				xfr_done:
					isc_buffer_init(&b, abspace, MXNAME);
					result = isc_sockaddr_totext(&sevent->
								     address,
								     &b);
					check_result(result,
						     "isc_sockaddr_totext");
					isc_buffer_usedregion(&b, &r);
					received(b.used, r.length,
						 (char *)r.base, query);
					query->working = ISC_FALSE;
					dns_rdata_freestruct(&soa);
					return (ISC_TRUE);
				}
				/*
				 * If we get to this point, we're doing an
				 * IXFR and have to start really looking
				 * at serial numbers.
				 */
				if (query->first_rr_serial == soa.serial) {
					debug("got a match for ixfr");
					if (!query->first_repeat_rcvd) {
						query->first_repeat_rcvd =
							ISC_TRUE;
						dns_rdata_freestruct(&soa);
						goto next_rdata;
					}
					debug("done with ixfr");
					dns_rdata_freestruct(&soa);
					goto xfr_done;
				}
				debug("meaningless soa %d",
				       soa.serial);
				dns_rdata_freestruct(&soa);
			next_rdata:
				result = dns_rdataset_next(rdataset);
			} while (result == ISC_R_SUCCESS);
		}
		result = dns_message_nextname(msg, DNS_SECTION_ANSWER);
	} while (result == ISC_R_SUCCESS);
	launch_next_query(query, ISC_FALSE);
	return (ISC_FALSE);
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
	dig_lookup_t *n;
	isc_boolean_t docancel = ISC_FALSE;
	isc_boolean_t result_bool;
	unsigned int local_timeout;
	
	UNUSED(task);

	debug("recv_done()");

	if (free_now) {
		isc_event_free(&event);
		return;
	}

	query = event->ev_arg;
	debug("lookup=%p, query=%p", query->lookup, query);

	if (free_now) {
		debug("bailing out, since freeing now");
		isc_event_free(&event);
		return;
	}

	sendcount--;
	debug("in recv_done, counter down to %d", sendcount);
	REQUIRE(event->ev_type == ISC_SOCKEVENT_RECVDONE);
	sevent = (isc_socketevent_t *)event;

	if ((query->lookup->tcp_mode) &&
	    (query->lookup->timer != NULL))
		isc_timer_touch(query->lookup->timer);
	if (!query->lookup->pending && !query->lookup->ns_search_only) {

		debug("no longer pending.  Got %s",
			isc_result_totext(sevent->result));
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		
		isc_event_free(&event);
		/*
		 * In this case, we don't actually use result_bool
		 */
		result_bool = cancel_lookup(query->lookup);
		return;
	}

	if (sevent->result == ISC_R_SUCCESS) {
		b = ISC_LIST_HEAD(sevent->bufferlist);
		ISC_LIST_DEQUEUE(sevent->bufferlist, &query->recvbuf, link);
		result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE,
					    &msg);
		check_result(result, "dns_message_create");
		
		if (key != NULL) {
			debug("querysig 1 is %p", query->lookup->querysig);
			if (query->lookup->querysig == NULL) {
				debug("getting initial querysig");
				result = dns_message_getquerytsig(
					     query->lookup->sendmsg,
					     mctx, &query->lookup->querysig);
				check_result(result,
					     "dns_message_getquerytsig");
			}
			result = dns_message_setquerytsig(msg,
						 query->lookup->querysig);
			check_result(result, "dns_message_setquerytsig");
			result = dns_message_settsigkey(msg, key);
			check_result(result, "dns_message_settsigkey");
			msg->tsigctx = query->lookup->tsigctx;
			if (query->lookup->msgcounter != 0) 
				msg->tcp_continuation = 1;
			query->lookup->msgcounter++;
		}
		debug("before parse starts");
		result = dns_message_parse(msg, b, ISC_TRUE);
		if (result != ISC_R_SUCCESS) {
			printf(";; Got bad UDP packet:\n");
			hex_dump(b);
			query->working = ISC_FALSE;
			query->waiting_connect = ISC_FALSE;
			if (!query->lookup->tcp_mode) {
				printf(";; Retrying in TCP mode.\n");
				n = requeue_lookup(query->lookup, ISC_TRUE);
				n->tcp_mode = ISC_TRUE;
			}
			dns_message_destroy(&msg);
			isc_event_free(&event);
			result_bool = cancel_lookup(query->lookup);
			return;
		}
		if (key != NULL) {
			debug("querysig 2 is %p", query->lookup->querysig);
			debug("before verify");
			result = dns_tsig_verify(&query->recvbuf, msg,
						 NULL, keyring);
			debug("after verify");
			if (result != ISC_R_SUCCESS) {
				printf(";; Couldn't verify signature: %s\n",
				       dns_result_totext(result));
				validated = ISC_FALSE;
			}
			query->lookup->tsigctx = msg->tsigctx;
			if (query->lookup->querysig != NULL) {
				debug("freeing querysig buffer %p",
				       query->lookup->querysig);
				isc_buffer_free(&query->lookup->querysig);
			}
			result = dns_message_getquerytsig(msg, mctx,
						     &query->lookup->querysig);
			check_result(result,"dns_message_getquerytsig");
			debug("querysig 3 is %p", query->lookup->querysig);
		}
		debug("after parse");
		if (query->lookup->xfr_q == NULL) {
			query->lookup->xfr_q = query;
			/*
			 * Once we are in the XFR message, increase
			 * the timeout to much longer, so brief network
			 * outages won't cause the XFR to abort
			 */
			if ((timeout != INT_MAX) &&
			    (query->lookup->timer != NULL)) {
				if (timeout == 0) {
					if (query->lookup->tcp_mode)
						local_timeout = TCP_TIMEOUT;
					else
						local_timeout = UDP_TIMEOUT;
				} else {
					if (timeout < (INT_MAX / 4))
						local_timeout = timeout * 4;
					else
						local_timeout = INT_MAX;
				}
				debug ("have local timeout of %d",
				       local_timeout);		
				isc_interval_set(&query->lookup->interval,
						 local_timeout, 0);
				result = isc_timer_reset(query->lookup->timer,
						      isc_timertype_once,
						      NULL,
						      &query->lookup->interval,
						      ISC_FALSE);
				check_result(result, "isc_timer_reset");
			}
		}
		if (query->lookup->xfr_q == query) {
			if ((query->lookup->trace)||
			    (query->lookup->ns_search_only)) {
				debug("in TRACE code");
				if (show_details ||
				    (((dns_message_firstname(msg,
							 DNS_SECTION_ANSWER)
				       == ISC_R_SUCCESS)) &&
				     !query->lookup->trace_root)) {
					printmessage(query, msg, ISC_TRUE);
				}
				if ((msg->rcode != 0) &&
				    (query->lookup->origin != NULL)) {
					next_origin(msg, query);
				} else {
					result = dns_message_firstname
						(msg,DNS_SECTION_ANSWER);
					if ((result != ISC_R_SUCCESS) ||
					    query->lookup->trace_root)
						followup_lookup(msg, query,
							DNS_SECTION_AUTHORITY);
				}
			} else if ((msg->rcode != 0) &&
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
		} else if ((dns_message_firstname(msg, DNS_SECTION_ANSWER)
			    == ISC_R_SUCCESS) &&
			   query->lookup->ns_search_only &&
			   !query->lookup->trace_root ) {
			printmessage(query, msg, ISC_TRUE);
		}
		
		if (query->lookup->pending)
			debug("still pending.");
		if (query->lookup->doing_xfr) {
			if (query != query->lookup->xfr_q) {
				dns_message_destroy(&msg);
				isc_event_free (&event);
				query->working = ISC_FALSE;
				query->waiting_connect = ISC_FALSE;
				return;
			}
			docancel = check_for_more_data(query, msg, sevent);
			if (docancel) {
				dns_message_destroy(&msg);
				result_bool = cancel_lookup(query->lookup);
			}
			if (msg != NULL)
				dns_message_destroy(&msg);
			isc_event_free(&event);
		}
		else {
			if ((msg->rcode == 0) ||
			    (query->lookup->origin == NULL)) {
				isc_buffer_init(&ab, abspace, MXNAME);
				result = isc_sockaddr_totext(&sevent->address,
							     &ab);
				check_result(result, "isc_sockaddr_totext");
				isc_buffer_usedregion(&ab, &r);
				if ((dns_message_firstname(msg,
							   DNS_SECTION_ANSWER)
				      == ISC_R_SUCCESS) ||
				    query->lookup->trace ) {
					received(b->used, r.length,
						 (char *)r.base,
						 query);
				}
			}
			query->working = ISC_FALSE;
			query->lookup->pending = ISC_FALSE;
			result_bool = ISC_FALSE;
			if (!query->lookup->ns_search_only ||
			    query->lookup->trace_root) {
				dns_message_destroy(&msg);
				result_bool = cancel_lookup(query->lookup);
			}
			if (msg != NULL)
				dns_message_destroy(&msg);
			isc_event_free(&event);
			if ((!free_now) && (!result_bool))
				check_next_lookup(query->lookup);
		}
		return;
	}
	/*
	 * In truth, we should never get into the CANCELED routine, since
	 * the cancel_lookup() routine clears the pending flag.
	 */
	if (sevent->result == ISC_R_CANCELED) {
		debug("in cancel handler");
		query->working = ISC_FALSE;
		query->waiting_connect = ISC_FALSE;
		isc_event_free(&event);
		check_next_lookup(query->lookup);
		return;
	}
	fatal("recv_done got result %s",
	      isc_result_totext(sevent->result));
}

void
get_address(char *host, in_port_t port, isc_sockaddr_t *sockaddr) {
	struct in_addr in4;
	struct in6_addr in6;
#if defined(HAVE_ADDRINFO) && defined(HAVE_GETADDRINFO)
	struct addrinfo *res = NULL;
	int result;
#else
	struct hostent *he;
#endif

	debug("get_address()");

	if (have_ipv6 && inet_pton(AF_INET6, host, &in6) == 1)
		isc_sockaddr_fromin6(sockaddr, &in6, port);
	else if (inet_pton(AF_INET, host, &in4) == 1)
		isc_sockaddr_fromin(sockaddr, &in4, port);
	else {
#if defined(HAVE_ADDRINFO) && defined(HAVE_GETADDRINFO)
		result = getaddrinfo(host, NULL, NULL, &res);
		if (result != 0) {
			fatal("Couldn't find server '%s': %s",
			      host, gai_strerror(result));
		}
		memcpy(&sockaddr->type.sa,res->ai_addr, res->ai_addrlen);
		sockaddr->length = res->ai_addrlen;
		isc_sockaddr_setport(sockaddr, port);
		freeaddrinfo(res);
#else
		he = gethostbyname(host);
		if (he == NULL)
		     fatal("Couldn't find server '%s' (h_errno=%d)",
			   host, h_errno);
		INSIST(he->h_addrtype == AF_INET);
		isc_sockaddr_fromin(sockaddr,
				    (struct in_addr *)(he->h_addr_list[0]),
				    port);
#endif
	}
}

static void
do_lookup_tcp(dig_lookup_t *lookup) {
	dig_query_t *query;
	isc_result_t result;
	unsigned int local_timeout;

	debug("do_lookup_tcp()");
	lookup->pending = ISC_TRUE;
	if (timeout != INT_MAX) {
		if (timeout == 0) {
			if (lookup->tcp_mode)
				local_timeout = TCP_TIMEOUT;
			else
				local_timeout = UDP_TIMEOUT;
		} else
			local_timeout = timeout;
		debug ("have local timeout of %d", local_timeout);
		isc_interval_set(&lookup->interval, local_timeout, 0);
		result = isc_timer_create(timermgr, isc_timertype_once, NULL,
					  &lookup->interval, global_task,
					  connect_timeout, lookup,
					  &lookup->timer);
		check_result(result, "isc_timer_create");
	}

	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		query->working = ISC_TRUE;
		query->waiting_connect = ISC_TRUE;
		get_address(query->servname, port, &query->sockaddr);

		sockcount++;
		debug("socket = %d",sockcount);
		ENSURE(query->sock == NULL);
		result = isc_socket_create(socketmgr,
					   isc_sockaddr_pf(&query->sockaddr),
					   isc_sockettype_tcp, &query->sock) ;
		check_result(result, "isc_socket_create");
		if (specified_source)
			result = isc_socket_bind(query->sock, &bind_address);
		else {
			if (isc_sockaddr_pf(&query->sockaddr) == AF_INET)
				isc_sockaddr_any(&bind_any);
			else
				isc_sockaddr_any6(&bind_any);
			result = isc_socket_bind(query->sock, &bind_any);
		}
		check_result(result, "isc_socket_bind");
		result = isc_socket_connect(query->sock, &query->sockaddr,
					    global_task, connect_done, query);
		check_result(result, "isc_socket_connect");
	}
}

static void
do_lookup_udp(dig_lookup_t *lookup) {
	dig_query_t *query;
	isc_result_t result;

	debug("do_lookup_udp()");
	ENSURE(!lookup->tcp_mode);
	lookup->pending = ISC_TRUE;

	for (query = ISC_LIST_HEAD(lookup->q);
	     query != NULL;
	     query = ISC_LIST_NEXT(query, link)) {
		query->working = ISC_TRUE;
		query->waiting_connect = ISC_FALSE;
		get_address(query->servname, port, &query->sockaddr);

		sockcount++;
		debug("socket = %d", sockcount);
		result = isc_socket_create(socketmgr,
					   isc_sockaddr_pf(&query->sockaddr),
					   isc_sockettype_udp, &query->sock);
		check_result(result, "isc_socket_create");
		if (specified_source)
			result = isc_socket_bind(query->sock, &bind_address);
		else {
			if (isc_sockaddr_pf(&query->sockaddr) == AF_INET)
				isc_sockaddr_any(&bind_any);
			else
				isc_sockaddr_any6(&bind_any);
			result = isc_socket_bind(query->sock, &bind_any);
		}
		check_result(result, "isc_socket_bind");
	}

	send_udp(lookup);
}

void
do_lookup(dig_lookup_t *lookup) {

	REQUIRE(lookup != NULL);

	debug("do_lookup()");
	if (lookup->tcp_mode)
		do_lookup_tcp(lookup);
	else
		do_lookup_udp(lookup);
}

void
start_lookup(void) {
	dig_lookup_t *lookup;

	debug("start_lookup()");

	if (free_now)
		return;

	lookup = ISC_LIST_HEAD(lookup_list);
	if (lookup != NULL) {
		setup_lookup(lookup);
		do_lookup(lookup);
	}
}

void
onrun_callback(isc_task_t *task, isc_event_t *event) {
	UNUSED(task);
	isc_event_free(&event);
	start_lookup();
}

void
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
		if (l->timer != NULL)
			isc_timer_detach(&l->timer);
		q = ISC_LIST_HEAD(l->q);
		while (q != NULL) {
			debug("cancelling query %p, belonging to %p",
			       q, l);
			if (q->sock != NULL) {
				isc_socket_cancel(q->sock, NULL,
						  ISC_SOCKCANCEL_ALL);
				isc_socket_detach(&q->sock);
				sockcount--;
				debug("socket = %d",sockcount);
			}
			q = ISC_LIST_NEXT(q, link);
		}
		l = ISC_LIST_NEXT(l, link);
	}
	s = ISC_LIST_HEAD(server_list);
	while (s != NULL) {
		debug("freeing global server %p", s);
		ptr = s;
		s = ISC_LIST_NEXT(s, link);
		debug("ptr is now %p", ptr);
		isc_mem_free(mctx, ptr);
	}
	o = ISC_LIST_HEAD(search_list);
	while (o != NULL) {
		debug("freeing search %p", o);
		ptr = o;
		o = ISC_LIST_NEXT(o, link);
		isc_mem_free(mctx, ptr);
	}
	if (socketmgr != NULL) {
		debug("freeing socketmgr");
		isc_socketmgr_destroy(&socketmgr);
	}
	if (timermgr != NULL) {
		debug("freeing timermgr");
		isc_timermgr_destroy(&timermgr);
	}
	if (global_task != NULL) {
		debug("freeing task");
		isc_task_detach(&global_task);
	}
	if (key != NULL) {
		debug("freeing key %p", key);
		dns_tsigkey_setdeleted(key);
		dns_tsigkey_detach(&key);
	}
	if (namebuf != NULL)
		isc_buffer_free(&namebuf);

	l = ISC_LIST_HEAD(lookup_list);
	while (l != NULL) {
		q = ISC_LIST_HEAD(l->q);
		while (q != NULL) {
			debug("freeing query %p, belonging to %p",
			       q, l);
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
				debug("freeing server %p belonging to %p",
				       s, l);
				ptr = s;
				s = ISC_LIST_NEXT(s, link);
				isc_mem_free(mctx, ptr);

			}
		}
		if (l->sendmsg != NULL)
			dns_message_destroy(&l->sendmsg);
		if (l->querysig != NULL) {
			debug("freeing buffer %p", l->querysig);
			isc_buffer_free(&l->querysig);
		}

		ptr = l;
		l = ISC_LIST_NEXT(l, link);
		isc_mem_free(mctx, ptr);
	}

	if (keyring != NULL) {
		debug("freeing keyring %p", keyring);
		dns_tsigkeyring_destroy(&keyring);
	}
	if (is_dst_up) {
		debug("destroy DST lib");
		dst_lib_destroy();
		is_dst_up = ISC_FALSE;
	}
	if (entp != NULL) {
		debug("detach from entropy");
		isc_entropy_detach(&entp);
	}
}
