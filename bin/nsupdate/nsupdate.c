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

/* $Id: nsupdate.c,v 1.1 2000/06/10 00:50:36 mws Exp $ */

#include <config.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>

#include <isc/app.h>
#include <isc/mutex.h>
#include <isc/condition.h>
#include <isc/mem.h>
#include <isc/socket.h>
#include <isc/sockaddr.h>
#include <isc/buffer.h>
#include <isc/region.h>
#include <isc/task.h>
#include <isc/util.h>
#include <isc/string.h>
#include <isc/lex.h>
#include <isc/timer.h>

#include <dns/dispatch.h>
#include <dns/request.h>
#include <dns/message.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatalist.h>
#include <dns/rdatatype.h>
#include <dns/callbacks.h>
#include <dns/rdatastruct.h>
#include <dns/events.h>
#include <dns/name.h>

#define MXNAME 256
#define MAXCMD 256
#define NAMEBUF 512
#define NAMEHINT 64
#define PACKETSIZE 2048
#define MSGTEXT 4069
#define FIND_TIMEOUT 5

#define VALID_NAME(n)	ISC_MAGIC_VALID(n, DNS_NAME_MAGIC)

#define RESOLV_CONF "/etc/resolv.conf"

isc_boolean_t busy= ISC_FALSE, debugging = ISC_FALSE, have_ipv6 = ISC_FALSE,
	valid_zonename = ISC_FALSE;
isc_mutex_t lock;
isc_condition_t cond;

isc_taskmgr_t *taskmgr = NULL;
isc_task_t *global_task = NULL;
isc_mem_t *mctx = NULL;
dns_dispatchmgr_t *dispatchmgr = NULL;
dns_requestmgr_t *requestmgr = NULL;
isc_socketmgr_t *socketmgr = NULL;
isc_timermgr_t *timermgr = NULL;
isc_socket_t *sock = NULL;
dns_message_t *updatemsg = NULL, *findmsg = NULL;
dns_name_t domainname;
isc_buffer_t domainname_buf;
char domainname_store[NAMEBUF];
dns_name_t zonename, actualzone, master;

int exitcode = 0;
char server[MXNAME];
char nameservername[3][MXNAME];
int nameservers;
int ns_inuse = 0;
int ndots = 1;
char domain[MXNAME];

#define STATUS_MORE 0
#define STATUS_SEND 1
#define STATUS_QUIT 2
#define STATUS_FAIL 3

static void
fatal(const char *format, ...) {
	va_list args;

	va_start(args, format);	
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	if (exitcode == 0)
		exitcode = 8;
	exit(exitcode);
}

static void
debug(const char *format, ...) {
	va_list args;

	if (debugging) {
		va_start(args, format);	
		vfprintf(stderr, format, args);
		va_end(args);
		fprintf(stderr, "\n");
	}
}

static void
check_result(isc_result_t result, const char *msg) {
	if (result != ISC_R_SUCCESS) {
		exitcode = 1;
		fatal("%s: %s", msg, isc_result_totext(result));
	}
}

static void
load_resolv_conf() {
	FILE *fp;
	char rcinput[MXNAME];
	char *ptr;

	fp = fopen (RESOLV_CONF, "r");
	if (fp != NULL) {
		while (fgets(rcinput, MXNAME, fp) != 0) {
			ptr = strtok (rcinput, " \t\r\n");
			if (ptr != NULL) {
				if (strcasecmp(ptr, "nameserver") == 0) {
					debug ("Got a nameserver line");
					ptr = strtok (NULL, " \t\r\n");
					if (ptr != NULL) {
						if (nameservers < 3) {
							strncpy(nameservername
							       [nameservers],
								ptr,MXNAME);
							nameservers++;
						}
					}
				} else if (strcasecmp(ptr, "options") == 0) {
					ptr = strtok(NULL, " \t\r\n");
					if (ptr != NULL) {
						if (strncasecmp(ptr, "ndots:",
								 6) == 0) {
							ndots = atoi(&ptr[6]);
							debug ("ndots is "
							       "%d.",
							       ndots);
						}
					}
				/* XXXMWS Searchlist not supported! */
				} else if ((strcasecmp(ptr, "domain") == 0) &&
					   (domain[0] == 0 )){
					while ((ptr = strtok(NULL, " \t\r\n"))
					       != NULL) {
						strncpy(domain, ptr, MXNAME);
					}
				}
						
			}
		}
		fclose (fp);
	}
}	

static void
reset_system() {
	isc_result_t result;

	/* If the update message is still around, destroy it */
	if (updatemsg != NULL)
		dns_message_destroy(&updatemsg);
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER,
				    &updatemsg);
	check_result (result, "dns_message_create");
	updatemsg->opcode = dns_opcode_update;

	valid_zonename = ISC_FALSE;
	if (VALID_NAME(&zonename))
		dns_name_invalidate(&zonename);
	if (VALID_NAME(&actualzone))
		dns_name_invalidate(&actualzone);
	if (VALID_NAME(&master))
		dns_name_invalidate(&master);
}

static void
setup_system() {
	isc_result_t result;
	isc_buffer_t buf;
	isc_sockaddr_t bind_any;

	debug("Setup System");

	/*
	 * Warning: This is not particularly good randomness.  We'll
	 * just use random() now for getting id values, but doing so
	 * does NOT insure that id's cann't be guessed.
	 */
	srandom (getpid() + (int)&setup_system);

	load_resolv_conf();

	result = isc_app_start();
	check_result(result, "isc_app_start");

	result = isc_net_probeipv4();
	check_result(result, "isc_net_probeipv4");

	/* XXXMWS There isn't any actual V6 support in the code yet */
	result = isc_net_probeipv6();
	if (result == ISC_R_SUCCESS)
		have_ipv6=ISC_TRUE;

	result = isc_mem_create(0, 0, &mctx);
	check_result(result, "isc_mem_create");

	result = isc_taskmgr_create (mctx, 1, 0, &taskmgr);
	check_result(result, "isc_taskmgr_create");

	result = isc_task_create (taskmgr, 0, &global_task);
	check_result(result, "isc_task_create");

	result = dns_dispatchmgr_create(mctx, &dispatchmgr);
	check_result(result, "dns_dispatchmgr_create");

	result = isc_socketmgr_create(mctx, &socketmgr);
	check_result(result, "dns_socketmgr_create");

	result = isc_timermgr_create(mctx, &timermgr);
	check_result(result, "dns_timermgr_create");

	result = isc_socket_create(socketmgr, PF_INET, isc_sockettype_udp,
				   &sock);
	check_result(result, "dns_socket_create");

	isc_sockaddr_any(&bind_any);
	result = isc_socket_bind(sock, &bind_any);
	check_result(result, "isc_socket_bind");

	result = dns_requestmgr_create(mctx, timermgr,
				       socketmgr, taskmgr, dispatchmgr,
				       NULL, NULL, &requestmgr);
	check_result(result, "dns_requestmgr_create");

	if (domain[0] != 0) {
		dns_name_init(&domainname, NULL);
		isc_buffer_init(&domainname_buf, domainname_store, NAMEBUF);
		dns_name_setbuffer(&domainname, &domainname_buf);
		isc_buffer_init(&buf, domain, strlen(domain));
		isc_buffer_add(&buf, strlen(domain));
		result = dns_name_fromtext(&domainname, &buf, dns_rootname,
					   ISC_FALSE, NULL);
		check_result(result, "dns_name_fromtext");
	}
	else {
		dns_name_clone(dns_rootname, &domainname);
	}

}
	
static void
parse_args() {
}

static void
check_and_add_zone(dns_name_t *namein) {
	if (valid_zonename)
		return;
	dns_name_init(&zonename, NULL);
	dns_name_clone(namein, &zonename);
	valid_zonename = ISC_TRUE;
}

static isc_uint16_t
make_rrset_prereq(dns_rdataclass_t rdclass) {
	isc_result_t result;
	char *nameptr, *typeptr;
	dns_name_t *name = NULL;
	isc_buffer_t *buf = NULL;
	isc_buffer_t source;
	isc_textregion_t typeregion;
	dns_rdataset_t *rdataset = NULL;
	dns_rdatatype_t rdatatype;
	
	nameptr = strtok(NULL, " \t\r\n");
	if (nameptr == NULL) {
		puts ("failed to read owner name");
		return STATUS_FAIL;
	}

	typeptr = strtok(NULL, " \t\r\n");
	if (typeptr == NULL) {
		puts ("failed to read owner type");
		return STATUS_FAIL;
	}

	result = dns_message_gettempname(updatemsg, &name);
	check_result(result, "dns_message_gettempname");
	result = isc_buffer_allocate(mctx, &buf, NAMEBUF);
	check_result(result, "isc_buffer_allocate");
	dns_name_init(name, NULL);
	dns_name_setbuffer(name, buf);
	isc_buffer_init(&source, nameptr, strlen(nameptr));
	isc_buffer_add(&source, strlen(nameptr));
	result = dns_name_fromtext(name, &source, &domainname,
				   ISC_FALSE, NULL);
	check_result(result, "dns_name_fromtext");

	check_and_add_zone(name);

	typeregion.base = typeptr;
	typeregion.length = strlen(typeptr);
	result = dns_rdatatype_fromtext(&rdatatype, &typeregion);
	check_result (result, "dns_rdatatype_fromtext");

	dns_rdataset_makequestion(rdataset, rdclass, rdatatype);
	ISC_LIST_INIT(name->list);
	ISC_LIST_APPEND(name->list, rdataset, link);
	dns_message_addname(updatemsg, name, DNS_SECTION_PREREQUISITE);
	return STATUS_MORE;
}


static isc_uint16_t
make_domain_prereq(dns_rdataclass_t rdclass) {
	isc_result_t result;
	char *ptr;
	dns_name_t *name;
	isc_buffer_t *buf;
	isc_buffer_t source;
	dns_rdataset_t *rdataset;
	
	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read owner name");
		return STATUS_FAIL;
	}

	result = dns_message_gettempname(updatemsg, &name);
	check_result(result, "dns_message_gettempname");
	result = isc_buffer_allocate(mctx, &buf, NAMEBUF);
	check_result(result, "isc_buffer_allocate");
	dns_name_init(name, NULL);
	dns_name_setbuffer(name, buf);
	isc_buffer_init(&source, ptr, strlen(ptr));
	isc_buffer_add(&source, strlen(ptr));
	result = dns_name_fromtext(name, &source, &domainname,
				   ISC_FALSE, NULL);
	check_result(result, "dns_name_fromtext");

	check_and_add_zone(name);

	result = dns_message_gettemprdataset(updatemsg, &rdataset);
	check_result(result, "dns_message_gettemprdataset");

	dns_rdataset_makequestion(rdataset, rdclass, dns_rdatatype_any);
	ISC_LIST_INIT(name->list);
	ISC_LIST_APPEND(name->list, rdataset, link);
	dns_message_addname(updatemsg, name, DNS_SECTION_PREREQUISITE);
	return STATUS_MORE;
}
	
static isc_uint16_t
evaluate_prereq() {
	char *ptr;

	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read operation code");
		return STATUS_FAIL;
	}
	if (strcasecmp(ptr,"nxdomain") == 0)
		return(make_domain_prereq(dns_rdataclass_none));
	if (strcasecmp(ptr,"yxdomain") == 0)
		return(make_domain_prereq(dns_rdataclass_any));
	if (strcasecmp(ptr,"nxrrset") == 0)
		return(make_rrset_prereq(dns_rdataclass_none));
	if (strcasecmp(ptr,"yxrrset") == 0)
		return(make_rrset_prereq(dns_rdataclass_any));
	printf ("incorrect operation code: %s\n",ptr);
	return(STATUS_FAIL);
}

static isc_uint16_t
evaluate_server() {
	char *ptr;

	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read server name");
		return STATUS_FAIL;
	}
	strncpy(server, ptr, MXNAME);
	return STATUS_MORE;
}

static isc_uint16_t
update_add() {
	isc_result_t result;
	isc_lex_t *lex = NULL;
	isc_buffer_t *buf = NULL;
	isc_buffer_t *namebuf = NULL;
	isc_buffer_t source;
	dns_name_t *name = NULL;
	isc_uint16_t ttl;
	char *ptr, *type, *data;
	dns_rdatatype_t rdatatype;
	dns_rdatacallbacks_t callbacks;
	dns_rdata_t *rdata;
	dns_rdatalist_t *rdatalist = NULL;
	dns_rdataset_t *rdataset = NULL;
	isc_textregion_t region;

	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read owner name");
		return STATUS_FAIL;
	}

	result = dns_message_gettempname(updatemsg, &name);
	check_result(result, "dns_message_gettempname");
	result = isc_buffer_allocate(mctx, &namebuf, NAMEBUF);
	check_result(result, "isc_buffer_allocate");
	dns_name_init(name, NULL);
	dns_name_setbuffer(name, namebuf);
	isc_buffer_init(&source, ptr, strlen(ptr));
	isc_buffer_add(&source, strlen(ptr));
	result = dns_name_fromtext(name, &source, &domainname,
				   ISC_FALSE, NULL);
	check_result(result, "dns_name_fromtext");

	check_and_add_zone(name);

	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read owner ttl");
		return STATUS_FAIL;
	}
	ttl = atoi(ptr);

	type = strtok(NULL, " \t\r\n");
	if (type == NULL) {
		puts ("failed to read owner type");
		return STATUS_FAIL;
	}

	data = strtok(NULL, " \t\r\n");
	if (data == NULL) {
		puts ("failed to read owner data");
		return STATUS_FAIL;
	}

	result = isc_lex_create(mctx, NAMEHINT, &lex);
	check_result(result, "isc_lex_create");	
	region.base = type;
	region.length = strlen(type);
	result = dns_rdatatype_fromtext(&rdatatype, &region);
	check_result(result, "dns_rdatatype_fromtext");
	isc_buffer_invalidate(&source);

	isc_buffer_init(&source, data, strlen(data));
	isc_buffer_add(&source, strlen(data));
	result = isc_lex_openbuffer(lex, &source);
	check_result(result, "isc_lex_openbuffer");

	result = isc_buffer_allocate(mctx, &buf, MXNAME);
	check_result(result, "isc_buffer_allocate");
	result = dns_message_gettemprdata(updatemsg, &rdata);
	check_result(result, "dns_message_gettemprdata");
	dns_rdatacallbacks_init_stdio(&callbacks);
	result = dns_rdata_fromtext(rdata, dns_rdataclass_in, rdatatype,
				    lex, &domainname, ISC_FALSE, buf,
				    &callbacks);
	check_result(result, "dns_rdata_fromtext");

	check_and_add_zone(name);

	result = dns_message_gettemprdatalist(updatemsg, &rdatalist);
	check_result(result, "dns_message_gettemprdatalist");
	result = dns_message_gettemprdataset(updatemsg, &rdataset);
	check_result(result, "dns_message_gettemprdataset");
	dns_rdatalist_init(rdatalist);
	rdatalist->type = rdatatype;
	rdatalist->rdclass = dns_rdataclass_in;
	rdatalist->covers = rdatatype;
	rdatalist->ttl = ttl;
	ISC_LIST_INIT(rdatalist->rdata);
	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
	dns_rdataset_init(rdataset);
	dns_rdatalist_tordataset(rdatalist, rdataset);
	ISC_LIST_INIT(name->list);
	ISC_LIST_APPEND(name->list, rdataset, link);
	dns_message_addname(updatemsg, name, DNS_SECTION_UPDATE);
	return STATUS_MORE;
}

/* XXXMWS add and delete share so much code, they should be collapsed. */
static isc_uint16_t
update_delete() {
	isc_result_t result;
	isc_lex_t *lex = NULL;
	isc_buffer_t *buf = NULL;
	isc_buffer_t source;
	dns_name_t *name;
	char *ptr, *typeptr, *dataptr = NULL;
	dns_rdatatype_t rdatatype;
	dns_rdatacallbacks_t callbacks;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdatalist = NULL;
	dns_rdataset_t *rdataset = NULL;
	isc_textregion_t typeregion;

	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read owner name");
		return STATUS_FAIL;
	}

	result = dns_message_gettempname(updatemsg, &name);
	check_result(result, "dns_message_gettempname");
	result = isc_buffer_allocate(mctx, &buf, NAMEBUF);
	check_result(result, "isc_buffer_allocate");
	dns_name_init(name, NULL);
	dns_name_setbuffer(name, buf);
	isc_buffer_init(&source, ptr, strlen(ptr));
	isc_buffer_add(&source, strlen(ptr));
	result = dns_name_fromtext(name, &source, &domainname,
				   ISC_FALSE, NULL);
	check_result(result, "dns_name_fromtext");

	check_and_add_zone(name);

	typeptr = strtok(NULL, " \t\r\n");
	if (typeptr != NULL) {
		dataptr = strtok(NULL, " \t\r\n");
	}

	result = isc_lex_create(mctx, NAMEHINT, &lex);
	check_result(result, "isc_lex_create");

	if (typeptr != NULL) {
		typeregion.base = typeptr;
		typeregion.length = strlen(typeptr);
		result = dns_rdatatype_fromtext(&rdatatype, &typeregion);
		check_result(result, "dns_rdatatype_fromtext");
		isc_buffer_invalidate(&source);
	}
	else {
		rdatatype = dns_rdatatype_any;
	}

	if (dataptr != NULL) {
		isc_buffer_init(&source, dataptr, strlen(dataptr));
		isc_buffer_add(&source, strlen(dataptr));
		result = isc_lex_openbuffer(lex, &source);
		check_result(result, "isc_lex_openbuffer");
		
		result = isc_buffer_allocate(mctx, &buf, MXNAME);
		check_result(result, "isc_buffer_allocate");
		result = dns_message_gettemprdata(updatemsg, &rdata);
		check_result(result, "dns_message_gettemprdata");
		dns_rdatacallbacks_init_stdio(&callbacks);
		result = dns_rdata_fromtext(rdata, dns_rdataclass_in,
					    rdatatype, lex, &domainname,
					    ISC_FALSE, buf, &callbacks);
		check_result(result, "dns_rdata_fromtext");

		result = dns_message_gettemprdatalist(updatemsg, &rdatalist);
		check_result(result, "dns_message_gettemprdatalist");
		result = dns_message_gettemprdataset(updatemsg, &rdataset);
		check_result(result, "dns_message_gettemprdataset");
		dns_rdatalist_init(rdatalist);
		rdatalist->type = rdatatype;
		rdatalist->rdclass = dns_rdataclass_none;
		rdatalist->covers = rdatatype;
		rdatalist->ttl = 0;
		ISC_LIST_INIT(rdatalist->rdata);
		ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
		dns_rdataset_init(rdataset);
		dns_rdatalist_tordataset(rdatalist, rdataset);
	}
	else {
		result = dns_message_gettemprdataset(updatemsg, &rdataset);
		check_result(result, "dns_message_gettemprdataset");
		dns_rdataset_makequestion(rdataset, dns_rdataclass_any,
					  rdatatype);
	}		
	ISC_LIST_INIT(name->list);
	ISC_LIST_APPEND(name->list, rdataset, link);
	dns_message_addname(updatemsg, name, DNS_SECTION_UPDATE);
	return STATUS_MORE;
}
				    

static isc_uint16_t
evaluate_update() {
	char *ptr;

	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read operation code");
		return STATUS_FAIL;
	}
	if (strcasecmp(ptr,"delete") == 0)
		return(update_delete());
	if (strcasecmp(ptr,"add") == 0)
		return(update_add());
	printf ("incorrect operation code: %s\n",ptr);
	return(STATUS_FAIL);
}

static void
show_message() {
	isc_result_t result;
	char store[MSGTEXT];
	isc_buffer_t buf;

	isc_buffer_init(&buf, store, MSGTEXT);
	result = dns_message_totext(updatemsg, 0, &buf);
	check_result(result, "dns_message_totext");
	printf ("%.*s", (int)isc_buffer_usedlength(&buf),
		(char*)isc_buffer_base(&buf));
}
	

static isc_uint16_t
get_next_command() {
	char cmdline[MAXCMD];
	char *ptr;

	fputs ("> ", stderr);
	fgets (cmdline, MAXCMD, stdin);
	ptr = strtok(cmdline, " \t\r\n");
	if (ptr == NULL) {
		if (!feof(stdin))
			return(STATUS_SEND);
		else
			return(STATUS_QUIT);
	}
	if (strcasecmp(ptr,"quit") == 0)
		return(STATUS_QUIT);
	if (strcasecmp(ptr,"prereq") == 0)
		return(evaluate_prereq());
	if (strcasecmp(ptr,"update") == 0)
		return(evaluate_update());
	if (strcasecmp(ptr,"server") == 0)
		return(evaluate_server());
	if (strcasecmp(ptr,"send") == 0)
		return(STATUS_SEND);
	if (strcasecmp(ptr,"show") == 0) {
		show_message();
		return(STATUS_MORE);
	}
	printf ("incorrect section name: %s\n",ptr);
	return(STATUS_FAIL);
}

static isc_boolean_t
user_interaction() {
	isc_uint16_t result = STATUS_MORE;

	while (result == STATUS_MORE) {
		result = get_next_command();
	}
	if (result == STATUS_SEND)
		return ISC_TRUE;
	if (result == STATUS_FAIL)
		exitcode = 1;
	return ISC_FALSE;

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

static void
update_completed(isc_task_t *task, isc_event_t *event) {
	UNUSED (task);
}

static void
send_update() {
	isc_result_t result;
	isc_sockaddr_t sockaddr;
	dns_request_t *request = NULL;
	char servername[MXNAME];
	isc_buffer_t buf;
	dns_name_t *name = NULL;
	dns_rdataset_t *rdataset;

	result = dns_message_gettempname(updatemsg, &name);
	check_result(result, "dns_message_gettempname");
	dns_name_init(name, NULL);
	result = dns_name_dup(&actualzone, mctx, name);
	check_result(result, "dns_name_dup");
	result = dns_message_gettemprdataset(findmsg, &rdataset);
	check_result(result, "dns_message_gettemprdataset");
	dns_rdataset_makequestion(rdataset, dns_rdataclass_in,
				  dns_rdatatype_soa);
	ISC_LIST_INIT(name->list);
	ISC_LIST_APPEND(name->list, rdataset, link);
	dns_message_addname(updatemsg, name, DNS_SECTION_ZONE);

	isc_buffer_init(&buf, servername, MXNAME);
	result = dns_name_totext(&master, ISC_TRUE, &buf);
	check_result(result, "dns_name_totext");
	servername[isc_buffer_usedlength(&buf)] = 0;
	
	get_address(servername, 53, &sockaddr);
	result = dns_request_create(requestmgr, updatemsg, &sockaddr,
				    DNS_REQUESTOPT_TCP, NULL,
				    FIND_TIMEOUT, global_task,
				    update_completed, NULL, &request);
	check_result(result, "dns_request_create");
}	
	

static void
find_completed(isc_task_t *task, isc_event_t *event) {
	dns_requestevent_t *reqev = NULL;
	isc_sockaddr_t sockaddr;
	dns_request_t *request = NULL;
	isc_result_t result;
	dns_message_t *rcvmsg = NULL;
	dns_section_t section;
	dns_name_t *name = NULL;
	dns_rdataset_t *rdataset = NULL;
	dns_rdata_soa_t soa;
	dns_rdata_t rdata;

	UNUSED(task);

	REQUIRE(event->ev_type == DNS_EVENT_REQUESTDONE);
	reqev = (dns_requestevent_t *)event;
	if (reqev->result != ISC_R_SUCCESS) {
		ns_inuse++;
		if (ns_inuse >= nameservers) {
			fatal ("Couldn't talk to any default nameserver.");
		}
		get_address(nameservername[ns_inuse], 53, &sockaddr);
		dns_request_destroy(&reqev->request);
		isc_event_free(&event);
		result = dns_request_create(requestmgr, findmsg, &sockaddr,
					    DNS_REQUESTOPT_TCP, NULL,
					    FIND_TIMEOUT, global_task,
					    find_completed, NULL, &request);
		check_result(result, "dns_result_create");
		return;
	}
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &rcvmsg);
	check_result(result, "dns_message_create");
	result = dns_request_getresponse(reqev->request, rcvmsg, ISC_TRUE);
	check_result(result, "dns_request_getresponse");
	section = DNS_SECTION_ANSWER;
	result = dns_message_findname(rcvmsg, section, &zonename,
				      dns_rdatatype_soa, dns_rdatatype_soa,
				      &name, &rdataset);
	if (result != ISC_R_SUCCESS) {
		section = DNS_SECTION_AUTHORITY;
		result = dns_message_findname(rcvmsg, section, &zonename,
					      dns_rdatatype_soa,
					      dns_rdatatype_soa,
					      &name, &rdataset);
		check_result(result, "dns_message_findname");
	}
	dns_name_init(&actualzone, NULL);
	result = dns_name_dup(name, mctx, &actualzone);
	check_result(result, "dns_name_dup");

	result = dns_rdataset_first(rdataset);
	check_result(result, "dns_rdataset_first");
	dns_rdataset_current(rdataset, &rdata);
	result = dns_rdata_tostruct(&rdata, &soa, mctx);
	check_result(result, "dns_rdata_tostruct");
	dns_name_init(&master, NULL);
	result = dns_name_dup(&soa.origin, mctx, &master);
	check_result(result, "dns_name_dup");
	
	dns_request_destroy(&reqev->request);
	isc_event_free(&event);
	send_update();
}

static void
start_update() {
	isc_result_t result;
	dns_rdataset_t *rdataset = NULL;
	dns_name_t *name = NULL;
	isc_sockaddr_t sockaddr;
	dns_request_t *request = NULL;

	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER,
				    &findmsg);
	check_result(result, "dns_message_create");

	result = dns_message_gettempname(findmsg, &name);
	check_result(result, "dns_message_gettempname");

	result = dns_message_gettemprdataset(findmsg, &rdataset);
	check_result(result, "dns_message_gettemprdataset");

	dns_rdataset_makequestion(rdataset, dns_rdataclass_in,
				  dns_rdatatype_soa);

	dns_name_init(name, NULL);
	result = dns_name_dup(&zonename, mctx, name);
	check_result(result, "dns_name_dup");

	ISC_LIST_INIT(name->list);
	ISC_LIST_APPEND(name->list, rdataset, link);
	dns_message_addname(findmsg, name, DNS_SECTION_QUESTION);

	ns_inuse = 0;
	get_address(nameservername[0], 53, &sockaddr);
	result = dns_request_create(requestmgr, findmsg, &sockaddr,
				    DNS_REQUESTOPT_TCP, NULL,
				    FIND_TIMEOUT, global_task,
				    find_completed, NULL, &request);
	check_result(result, "dns_request_create");
}


static void
free_lists() {
	exit(0);
}

int
main(int argc, char **argv) {
        isc_result_t result;
	

        setup_system();
        result = isc_mutex_init(&lock);
        check_result(result, "isc_mutex_init");
        result = isc_condition_init(&cond);
        check_result(result, "isc_condition_init");
        result = isc_mutex_trylock(&lock);
        check_result(result, "isc_mutex_trylock");

        parse_args(argc, argv);

        while (ISC_TRUE) {
		reset_system();
                if (!user_interaction())
			break;
		busy = ISC_TRUE;
		start_update();
		while (busy) {
			result = isc_condition_wait(&cond, &lock);
			check_result(result, "isc_condition_wait");
		}
        }

        puts ("");
        debug ("Fell through app_run");
        free_lists(0);
        isc_mutex_destroy(&lock);
        isc_condition_destroy(&cond);

        return (0);
}

