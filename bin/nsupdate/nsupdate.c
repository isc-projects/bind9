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

/* $Id: nsupdate.c,v 1.8.2.2 2000/06/29 03:00:57 gson Exp $ */

#include <config.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <dns/callbacks.h>
#include <dns/dispatch.h>
#include <dns/events.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/request.h>
#include <dns/result.h>
#include <dns/tsig.h>
#include <dst/dst.h>
#include <isc/app.h>
#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/entropy.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/region.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>
#include <isc/stdtime.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/types.h>
#include <isc/util.h>

#define MXNAME 256
#define MAXCMD 256
#define NAMEBUF 512
#define NAMEHINT 64
#define PACKETSIZE 2048
#define MSGTEXT 4069
#define FIND_TIMEOUT 5

#define VALID_NAME(n)	ISC_MAGIC_VALID(n, DNS_NAME_MAGIC)

#define RESOLV_CONF "/etc/resolv.conf"

extern isc_boolean_t isc_mem_debugging;

isc_boolean_t busy= ISC_FALSE, debugging = ISC_FALSE, ddebugging = ISC_FALSE,
	have_ipv6 = ISC_FALSE, valid_zonename = ISC_FALSE,
	forced_master = ISC_FALSE, is_dst_up = ISC_FALSE;
isc_mutex_t lock;
isc_condition_t cond;

isc_taskmgr_t *taskmgr = NULL;
isc_task_t *global_task = NULL;
isc_mem_t *mctx = NULL;
dns_dispatchmgr_t *dispatchmgr = NULL;
dns_requestmgr_t *requestmgr = NULL;
isc_socketmgr_t *socketmgr = NULL;
isc_timermgr_t *timermgr = NULL;
dns_dispatch_t *dispatchv4 = NULL;
dns_message_t *updatemsg = NULL, *findmsg = NULL;
dns_name_t zonename; /* From ZONE command */
dns_name_t actualzone; /* From SOA query reply */
dns_name_t resolvdomain; /* From resolv.conf's domain line, if exists */
dns_name_t *current_zone; /* Points to one of above, or dns_rootname */
isc_buffer_t resolvbuf;
char resolvstore[MXNAME];
dns_name_t master; /* Master nameserver, from SOA query */
dns_tsigkey_t *key = NULL;
dns_tsig_keyring_t *keyring = NULL;

int exitcode = 0;
char server[MXNAME];
char userzone[MXNAME];
char nameservername[3][MXNAME];
int nameservers;
int ns_inuse = 0;
int ndots = 1;
char domain[MXNAME];
char keynametext[MXNAME]="";
char keysecret[MXNAME]="";
dns_name_t keyname;
isc_buffer_t *keynamebuf = NULL;
isc_entropy_t *entp = NULL;

#define STATUS_MORE 0
#define STATUS_SEND 1
#define STATUS_QUIT 2
#define STATUS_FAIL 3
#define STATUS_SYNTAX 4

static int
count_dots(char *string) {
	char *s;
	int i=0;

	s = string;
	while (*s != 0) {
		if (*s == '.')
			i++;
		s++;
	}
	return (i);
}

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
ddebug(const char *format, ...) {
	va_list args;

	if (ddebugging) {
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

	ddebug ("load_resolv_conf()");
	fp = fopen (RESOLV_CONF, "r");
	if (fp != NULL) {
		while (fgets(rcinput, MXNAME, fp) != 0) {
			ptr = strtok (rcinput, " \t\r\n");
			if (ptr != NULL) {
				if (strcasecmp(ptr, "nameserver") == 0) {
					ddebug ("Got a nameserver line");
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
							ddebug ("ndots is "
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

	ddebug ("reset_system()");
	/* If the update message is still around, destroy it */
	if (updatemsg != NULL)
		dns_message_destroy(&updatemsg);
	if (findmsg != NULL)
		dns_message_destroy(&findmsg);
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER,
				    &updatemsg);
	check_result (result, "dns_message_create");
	updatemsg->opcode = dns_opcode_update;

	valid_zonename = ISC_FALSE;
	if (VALID_NAME(&zonename))
		dns_name_free(&zonename, mctx);
	if (VALID_NAME(&actualzone))
		dns_name_free(&actualzone, mctx);
	if (VALID_NAME(&master))
		dns_name_free(&master, mctx);
	if (domain[0] != 0) 
		current_zone = &resolvdomain;
	else
		current_zone = dns_rootname;
}

static void
setup_system(){
	isc_result_t result;
	isc_sockaddr_t bind_any;
	isc_buffer_t buf;
	int secretsize;
	unsigned char *secretstore;
	isc_buffer_t secretsrc;
	isc_buffer_t secretbuf;
	isc_lex_t *lex = NULL;
	isc_stdtime_t now;

	ddebug("setup_system()");

	/*
	 * Warning: This is not particularly good randomness.  We'll
	 * just use random() now for getting id values, but doing so
	 * does NOT insure that id's can't be guessed.
	 */
	srandom (getpid() + (int)&setup_system);

	isc_mem_debugging = ISC_FALSE;

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

	result = dns_dispatchmgr_create(mctx, NULL, &dispatchmgr);
	check_result(result, "dns_dispatchmgr_create");

	result = isc_socketmgr_create(mctx, &socketmgr);
	check_result(result, "dns_socketmgr_create");

	result = isc_timermgr_create(mctx, &timermgr);
	check_result(result, "dns_timermgr_create");

	result = isc_taskmgr_create (mctx, 1, 0, &taskmgr);
	check_result(result, "isc_taskmgr_create");

	result = isc_task_create (taskmgr, 0, &global_task);
	check_result(result, "isc_task_create");

	result = isc_entropy_create (mctx, &entp);
	check_result(result, "isc_entropy_create");

	result = dst_lib_init (mctx, entp, 0);
	check_result(result, "dst_lib_init");
	is_dst_up = ISC_TRUE;

	isc_sockaddr_any(&bind_any);

	result = dns_dispatch_getudp(dispatchmgr, socketmgr, taskmgr,
				     &bind_any, PACKETSIZE, 4, 2, 3, 5,
				     DNS_DISPATCHATTR_UDP |
				     DNS_DISPATCHATTR_IPV4 |
				     DNS_DISPATCHATTR_MAKEQUERY, 0,
				     &dispatchv4);
	check_result(result, "dns_dispatch_getudp");

	result = dns_requestmgr_create(mctx, timermgr,
				       socketmgr, taskmgr, dispatchmgr,
				       dispatchv4, NULL, &requestmgr);
	check_result(result, "dns_requestmgr_create");

	if (domain[0] != 0) {
		dns_name_init(&resolvdomain, NULL);
		isc_buffer_init(&resolvbuf, resolvstore, NAMEBUF);
		dns_name_setbuffer(&resolvdomain, &resolvbuf);
		isc_buffer_init(&buf, domain, strlen(domain));
		isc_buffer_add(&buf, strlen(domain));
		result = dns_name_fromtext(&resolvdomain, &buf, dns_rootname,
					   ISC_FALSE, NULL);
		check_result(result, "dns_name_fromtext");
		current_zone = &resolvdomain;
	}
	else {
		current_zone = dns_rootname;
	}

	if (keysecret[0] != 0) {
		debug("Creating key...");
		result = dns_tsigkeyring_create(mctx, &keyring);
		check_result(result, "dns_tsigkeyringcreate");
		result = isc_buffer_allocate(mctx, &keynamebuf, MXNAME);
		check_result(result, "isc_buffer_allocate");
		dns_name_init(&keyname, NULL);
		check_result(result, "dns_name_init");
		isc_buffer_putstr(keynamebuf, keynametext);
		secretsize = strlen(keysecret) * 3 / 4;
		secretstore = isc_mem_get(mctx, secretsize);
		ENSURE (secretstore != NULL);
		isc_buffer_init(&secretsrc, keysecret, strlen(keysecret));
		isc_buffer_add(&secretsrc, strlen(keysecret));
		isc_buffer_init(&secretbuf, secretstore, secretsize);
		result = isc_lex_create(mctx, strlen(keysecret), &lex);
		check_result(result, "isc_lex_create");
		result = isc_lex_openbuffer(lex, &secretsrc);
		check_result(result, "isc_lex_openbuffer");
		result = isc_base64_tobuffer(lex, &secretbuf, -1);
		if (result != ISC_R_SUCCESS) {
			printf (";; Couldn't create key %s: %s\n",
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
		result = dns_name_fromtext(&keyname, keynamebuf,
					   dns_rootname, ISC_FALSE,
					   keynamebuf);
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
			printf (";; Couldn't create key %s: %s\n",
				keynametext, dns_result_totext(result));
		}
		isc_mem_put(mctx, secretstore, secretsize);
		dns_name_invalidate(&keyname);
		isc_buffer_free(&keynamebuf);
		return;
	SYSSETUP_FAIL:
		isc_mem_put(mctx, secretstore, secretsize);
		dns_name_invalidate(&keyname);
		isc_buffer_free(&keynamebuf);
		dns_tsigkeyring_destroy(&keyring);
	}
}

static void
set_key(char *key) {
	char *nameptr;
	char *secptr;

	debug("set_key");
	nameptr = strtok(key, ": \t\r\n");
	if (nameptr == NULL) {
		fputs ("Need a key entry\n", stderr);
		return;
	}
	secptr = strtok(NULL, " \t\r\n");
	if (secptr == NULL) {
		fputs ("Need a key entry\n", stderr);
		return;
	}
	strncpy (keynametext, nameptr, MXNAME);
	strncpy (keysecret, secptr, MXNAME);
}

static void
parse_args(int argc, char **argv) {
	int rc;
	char **rv;

	debug("parse_args");
	rc = argc;
	rv = argv;
	for (rc--, rv++; rc > 0; rc--, rv++) {
		if (strcasecmp(rv[0], "-d") == 0)
			debugging = ISC_TRUE;
		else if (strcasecmp(rv[0], "-dd") == 0) {
			ddebugging = ISC_TRUE;
			debug ("Just turned on debugging");
		} else if (strcasecmp(rv[0], "-dm") == 0) {
			ddebugging = ISC_TRUE;
			isc_mem_debugging = ISC_TRUE;
		} else if (strncasecmp(rv[0],"-y", 2) == 0) {
			debug ("In -y test");
			if (rv[0][2] != 0)
				set_key(&rv[0][2]);
			else {
				rc--;
				rv++;
				if (rc == 0) {
					fputs ("Need a key entry\n", stderr);
					return;
				}
				set_key(rv[0]);
			}
		} else if (strcasecmp(rv[0], "-v") == 0)
			fputs ("Virtual Circuit mode not currently "
			       "implemented.\n", stderr);
		else if (strcasecmp(rv[0], "-k") == 0)
			fputs ("TSIG not currently implemented.",
			       stderr);
	}
}

static void
check_and_add_zone(dns_name_t *namein) {

	ddebug ("check_and_add_zone()");

	if (valid_zonename)
		return;
	dns_name_init(&zonename, NULL);
	dns_name_dup(namein, mctx, &zonename);
	current_zone = &zonename;
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
	dns_rdatalist_t *rdatalist = NULL;
	dns_rdatatype_t rdatatype;
	dns_rdata_t *rdata = NULL;
	dns_name_t *rn = current_zone;

	ddebug ("make_rrset_prereq()");
	nameptr = strtok(NULL, " \t\r\n");
	if (nameptr == NULL) {
		puts ("failed to read owner name");
		return STATUS_SYNTAX;
	}

	typeptr = strtok(NULL, " \t\r\n");
	if (typeptr == NULL) {
		puts ("failed to read owner type");
		return STATUS_SYNTAX;
	}

	result = dns_message_gettempname(updatemsg, &name);
	check_result(result, "dns_message_gettempname");
	result = isc_buffer_allocate(mctx, &buf, NAMEBUF);
	check_result(result, "isc_buffer_allocate");
	dns_name_init(name, NULL);
	dns_name_setbuffer(name, buf);
	dns_message_takebuffer(updatemsg, &buf);
	isc_buffer_init(&source, nameptr, strlen(nameptr));
	isc_buffer_add(&source, strlen(nameptr));
	if (count_dots(nameptr) > ndots)
		rn = dns_rootname;
	result = dns_name_fromtext(name, &source, rn,
				   ISC_FALSE, NULL);
	check_result(result, "dns_name_fromtext");

	check_and_add_zone(name);

	typeregion.base = typeptr;
	typeregion.length = strlen(typeptr);
	result = dns_rdatatype_fromtext(&rdatatype, &typeregion);
	check_result (result, "dns_rdatatype_fromtext");

	result = dns_message_gettemprdatalist(updatemsg, &rdatalist);
	check_result(result, "dns_message_gettemprdatalist");
	result = dns_message_gettemprdataset(updatemsg, &rdataset);
	check_result(result, "dns_message_gettemprdataset");
	dns_rdatalist_init(rdatalist);
	rdatalist->type = rdatatype;
	rdatalist->rdclass = rdclass;
	rdatalist->covers = 0;
	rdatalist->ttl = 0;
	result = dns_message_gettemprdata(updatemsg, &rdata);
	check_result(result, "dns_message_gettemprdata");
	rdata->data = NULL;
	rdata->length = 0;
	rdata->rdclass = rdclass;
	rdata->type = rdatatype;
	ISC_LIST_INIT(rdatalist->rdata);
	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
	dns_rdataset_init(rdataset);
	dns_rdatalist_tordataset(rdatalist, rdataset);		
	ISC_LIST_INIT(name->list);
	ISC_LIST_APPEND(name->list, rdataset, link);
	dns_message_addname(updatemsg, name, DNS_SECTION_PREREQUISITE);
	return STATUS_MORE;
}


static isc_uint16_t
make_domain_prereq(dns_rdataclass_t rdclass) {
	isc_result_t result;
	char *ptr;
	dns_name_t *name = NULL;
	isc_buffer_t *buf = NULL;
	isc_buffer_t source;
	dns_rdataset_t *rdataset = NULL;
	dns_rdatalist_t *rdatalist = NULL;
	dns_rdata_t *rdata = NULL;
	dns_name_t *rn = current_zone;

	ddebug ("make_domain_prereq()");
	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read owner name");
		return STATUS_SYNTAX;
	}

	result = dns_message_gettempname(updatemsg, &name);
	check_result(result, "dns_message_gettempname");
	result = isc_buffer_allocate(mctx, &buf, NAMEBUF);
	check_result(result, "isc_buffer_allocate");
	dns_name_init(name, NULL);
	dns_name_setbuffer(name, buf);
	dns_message_takebuffer(updatemsg, &buf);
	isc_buffer_init(&source, ptr, strlen(ptr));
	isc_buffer_add(&source, strlen(ptr));
	if (count_dots(ptr) > ndots)
		rn = dns_rootname;
	result = dns_name_fromtext(name, &source, rn,
				   ISC_FALSE, NULL);
	check_result(result, "dns_name_fromtext");

	check_and_add_zone(name);

	result = dns_message_gettemprdatalist(updatemsg, &rdatalist);
	check_result(result, "dns_message_gettemprdatalist");
	result = dns_message_gettemprdataset(updatemsg, &rdataset);
	check_result(result, "dns_message_gettemprdataset");
	dns_rdatalist_init(rdatalist);
	rdatalist->type = dns_rdatatype_any;
	rdatalist->rdclass = rdclass;
	rdatalist->covers = 0;
	rdatalist->ttl = 0;
	result = dns_message_gettemprdata(updatemsg, &rdata);
	check_result(result, "dns_message_gettemprdata");
	rdata->data = NULL;
	rdata->length = 0;
	rdata->rdclass = rdclass;
	rdata->type = dns_rdatatype_any;
	ISC_LIST_INIT(rdatalist->rdata);
	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
	dns_rdataset_init(rdataset);
	dns_rdatalist_tordataset(rdatalist, rdataset);		

	ISC_LIST_INIT(name->list);
	ISC_LIST_APPEND(name->list, rdataset, link);
	dns_message_addname(updatemsg, name, DNS_SECTION_PREREQUISITE);
	return STATUS_MORE;
}
	
static isc_uint16_t
evaluate_prereq() {
	char *ptr;

	ddebug ("evaluate_prereq()");
	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read operation code");
		return STATUS_SYNTAX;
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
	return(STATUS_SYNTAX);
}

static isc_uint16_t
evaluate_server() {
	char *ptr;

	ddebug ("evaluate_server()");
	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read server name");
		return STATUS_SYNTAX;
	}
	strncpy(server, ptr, MXNAME);
	return STATUS_MORE;
}

static isc_uint16_t
evaluate_zone() {
	char *ptr;
	dns_name_t name;
	isc_buffer_t source, *buf = NULL;
	isc_result_t result;

	ddebug ("evaluate_zone()");
	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read zone name");
		return STATUS_SYNTAX;
	}
	strncpy(userzone, ptr, MXNAME);

	result = isc_buffer_allocate(mctx, &buf, NAMEBUF);
	check_result(result, "isc_buffer_allocate");
	dns_name_init(&name, NULL);
	dns_name_setbuffer(&name, buf);
	isc_buffer_init(&source, ptr, strlen(ptr));
	isc_buffer_add(&source, strlen(ptr));
	result = dns_name_fromtext(&name, &source, dns_rootname,
				   ISC_FALSE, NULL);
	check_result(result, "dns_name_fromtext");

	check_and_add_zone(&name);

	isc_buffer_free(&buf);

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
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdatalist = NULL;
	dns_rdataset_t *rdataset = NULL;
	isc_textregion_t region;
	dns_name_t *rn = current_zone;

	ddebug ("update_add()");
	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read owner name");
		return STATUS_SYNTAX;
	}

	result = dns_message_gettempname(updatemsg, &name);
	check_result(result, "dns_message_gettempname");
	result = isc_buffer_allocate(mctx, &namebuf, NAMEBUF);
	check_result(result, "isc_buffer_allocate");
	dns_name_init(name, NULL);
	dns_name_setbuffer(name, namebuf);
	dns_message_takebuffer(updatemsg, &namebuf);
	isc_buffer_init(&source, ptr, strlen(ptr));
	isc_buffer_add(&source, strlen(ptr));
	if (count_dots(ptr) > ndots)
		rn = dns_rootname;
	result = dns_name_fromtext(name, &source, rn,
				   ISC_FALSE, NULL);
	check_result(result, "dns_name_fromtext");

	check_and_add_zone(name);

	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read owner ttl");
		dns_message_puttempname(updatemsg, &name);
		return STATUS_SYNTAX;
	}
	ttl = atoi(ptr);

	type = strtok(NULL, " \t\r\n");
	if (type == NULL) {
		puts ("failed to read owner type");
		dns_message_puttempname(updatemsg, &name);
		return STATUS_SYNTAX;
	}

	data = strtok(NULL, " \t\r\n");
	if (data == NULL) {
		puts ("failed to read owner data");
		dns_message_puttempname(updatemsg, &name);
		return STATUS_SYNTAX;
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
				    lex, current_zone, ISC_FALSE, buf,
				    &callbacks);
	check_result(result, "dns_rdata_fromtext");
	isc_lex_destroy(&lex);

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
	dns_message_takebuffer(updatemsg, &buf);
	return STATUS_MORE;
}

/* XXXMWS add and delete share so much code, they should be collapsed. */
static isc_uint16_t
update_delete() {
	isc_result_t result;
	isc_lex_t *lex = NULL;
	isc_buffer_t *namebuf = NULL;
	isc_buffer_t *buf = NULL;
	isc_buffer_t source;
	dns_name_t *name = NULL;
	char *ptr, *typeptr, *dataptr = NULL;
	dns_rdatatype_t rdatatype;
	dns_rdatacallbacks_t callbacks;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdatalist = NULL;
	dns_rdataset_t *rdataset = NULL;
	isc_textregion_t typeregion;
	dns_name_t *rn = current_zone;

	ddebug ("update_delete()");
	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read owner name");
		return STATUS_SYNTAX;
	}

	result = dns_message_gettempname(updatemsg, &name);
	check_result(result, "dns_message_gettempname");
	result = isc_buffer_allocate(mctx, &namebuf, NAMEBUF);
	check_result(result, "isc_buffer_allocate");
	dns_name_init(name, NULL);
	dns_name_setbuffer(name, namebuf);
	dns_message_takebuffer(updatemsg, &namebuf);
	isc_buffer_init(&source, ptr, strlen(ptr));
	isc_buffer_add(&source, strlen(ptr));
	if (count_dots(ptr) > ndots)
		rn = dns_rootname;
	result = dns_name_fromtext(name, &source, rn,
				   ISC_FALSE, NULL);
	check_result(result, "dns_name_fromtext");

	check_and_add_zone(name);

	typeptr = strtok(NULL, " \t\r\n");
	if (typeptr != NULL) {
		dataptr = strtok(NULL, " \t\r\n");
	}

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
		result = isc_lex_create(mctx, NAMEHINT, &lex);
		check_result(result, "isc_lex_create");

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
					    rdatatype, lex, current_zone,
					    ISC_FALSE, buf, &callbacks);
		check_result(result, "dns_rdata_fromtext");
		isc_lex_destroy(&lex);
		
		result = dns_message_gettemprdatalist(updatemsg, &rdatalist);
		check_result(result, "dns_message_gettemprdatalist");
		result = dns_message_gettemprdataset(updatemsg, &rdataset);
		check_result(result, "dns_message_gettemprdataset");
		dns_rdatalist_init(rdatalist);
		rdatalist->type = rdatatype;
		rdatalist->rdclass = dns_rdataclass_none;
		rdatalist->covers = 0;
		rdatalist->ttl = 0;
		ISC_LIST_INIT(rdatalist->rdata);
		ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
		dns_rdataset_init(rdataset);
		dns_rdatalist_tordataset(rdatalist, rdataset);
		isc_buffer_free(&buf);
	}
	else {
		result = dns_message_gettemprdatalist(updatemsg, &rdatalist);
		check_result(result, "dns_message_gettemprdatalist");
		result = dns_message_gettemprdataset(updatemsg, &rdataset);
		check_result(result, "dns_message_gettemprdataset");
		dns_rdatalist_init(rdatalist);
		rdatalist->type = rdatatype;
		rdatalist->rdclass = dns_rdataclass_any;
		rdatalist->covers = 0;
		rdatalist->ttl = 0;
		result = dns_message_gettemprdata(updatemsg, &rdata);
		check_result(result, "dns_message_gettemprdata");
		rdata->data = NULL;
		rdata->length = 0;
		rdata->rdclass = dns_rdataclass_any;
		rdata->type = rdatatype;
		ISC_LIST_INIT(rdatalist->rdata);
		ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
		dns_rdataset_init(rdataset);
		dns_rdatalist_tordataset(rdatalist, rdataset);		
	}
	ISC_LIST_INIT(name->list);
	ISC_LIST_APPEND(name->list, rdataset, link);
	dns_message_addname(updatemsg, name, DNS_SECTION_UPDATE);
	return STATUS_MORE;
}
				    

static isc_uint16_t
evaluate_update() {
	char *ptr;

	ddebug ("evaluate_update()");
	ptr = strtok(NULL, " \t\r\n");
	if (ptr == NULL) {
		puts ("failed to read operation code");
		return STATUS_SYNTAX;
	}
	if (strcasecmp(ptr,"delete") == 0)
		return(update_delete());
	if (strcasecmp(ptr,"add") == 0)
		return(update_add());
	printf ("incorrect operation code: %s\n",ptr);
	return(STATUS_SYNTAX);
}

static void
show_message() {
	isc_result_t result;
	char store[MSGTEXT];
	isc_buffer_t buf;

	ddebug ("show_message()");
	isc_buffer_init(&buf, store, MSGTEXT);
	result = dns_message_totext(updatemsg, 0, &buf);
	check_result(result, "dns_message_totext");
	printf ("Outgoing update query:\n%.*s",
		(int)isc_buffer_usedlength(&buf),
		(char*)isc_buffer_base(&buf));
}
	

static isc_uint16_t
get_next_command() {
	char cmdline[MAXCMD];
	char *ptr;

	ddebug ("get_next_command()");
	fputs ("> ", stderr);
	fgets (cmdline, MAXCMD, stdin);
	ptr = strtok(cmdline, " \t\r\n");

	if (feof(stdin))
		return(STATUS_QUIT);
	if (ptr == NULL)
		return(STATUS_SEND);
	if (strcasecmp(ptr,"quit") == 0)
		return(STATUS_QUIT);
	if (strcasecmp(ptr,"prereq") == 0)
		return(evaluate_prereq());
	if (strcasecmp(ptr,"update") == 0)
		return(evaluate_update());
	if (strcasecmp(ptr,"server") == 0)
		return(evaluate_server());
	if (strcasecmp(ptr,"zone") == 0)
		return(evaluate_zone());
	if (strcasecmp(ptr,"send") == 0)
		return(STATUS_SEND);
	if (strcasecmp(ptr,"show") == 0) {
		show_message();
		return(STATUS_MORE);
	}
	printf ("incorrect section name: %s\n",ptr);
	return(STATUS_SYNTAX);
}

static isc_boolean_t
user_interaction() {
	isc_uint16_t result = STATUS_MORE;

	ddebug ("user_interaction()");
	while ((result == STATUS_MORE) || (result == STATUS_SYNTAX)) {
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

        ddebug("get_address()");
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
	dns_requestevent_t *reqev = NULL;
	isc_result_t result;
	isc_buffer_t buf;
	dns_message_t *rcvmsg = NULL;
	char bufstore[MSGTEXT];
	
	UNUSED (task);

	ddebug ("updated_completed()");
	REQUIRE(event->ev_type == DNS_EVENT_REQUESTDONE);
	reqev = (dns_requestevent_t *)event;
	if (reqev->result != ISC_R_SUCCESS) {
		printf ("; Communication with server failed: %d-%s\n",
			reqev->result, isc_result_totext(reqev->result));
		goto done;
	}

	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &rcvmsg);
	check_result(result, "dns_message_create");
	result = dns_request_getresponse(reqev->request, rcvmsg, ISC_TRUE);
	check_result(result, "dns_request_getresponse");
	if (debugging) {
		isc_buffer_init(&buf, bufstore, MSGTEXT);
		result = dns_message_totext(rcvmsg, 0, &buf);
		check_result(result, "dns_message_totext");
		printf ("\nReply from update query:\n%.*s\n",
			(int)isc_buffer_usedlength(&buf),
			(char*)isc_buffer_base(&buf));
	}
	dns_message_destroy(&rcvmsg);
 done:
	dns_request_destroy(&reqev->request);
	isc_event_free(&event);
	isc_mutex_lock(&lock);
	busy = ISC_FALSE;
	isc_condition_signal(&cond);
	isc_mutex_unlock(&lock);
}

static void
send_update() {
	isc_result_t result;
	isc_sockaddr_t sockaddr;
	dns_request_t *request = NULL;
	char servername[MXNAME];
	isc_buffer_t buf;
	dns_name_t *name = NULL;
	dns_rdataset_t *rdataset = NULL;

	ddebug ("send_update()");

	result = dns_message_gettempname(updatemsg, &name);
	check_result(result, "dns_message_gettempname");
	dns_name_init(name, NULL);
	dns_name_clone(&actualzone, name);
	result = dns_message_gettemprdataset(updatemsg, &rdataset);
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
				    0, key,
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
	isc_buffer_t buf;
	char bufstore[MSGTEXT];

	UNUSED(task);

	ddebug ("find_completed()");
	REQUIRE(event->ev_type == DNS_EVENT_REQUESTDONE);
	reqev = (dns_requestevent_t *)event;
	if (reqev->result != ISC_R_SUCCESS) {
		printf ("; Communication with %s failed: %d-%s\n",
			nameservername[ns_inuse], reqev->result, 
			isc_result_totext(reqev->result));
		ns_inuse++;
		if (ns_inuse >= nameservers) {
			fatal ("Couldn't talk to any default nameserver.");
		}
		get_address(nameservername[ns_inuse], 53, &sockaddr);
		ddebug("Destroying %lx[%lx]", &reqev->request, 
		      reqev->request);
		dns_request_destroy(&reqev->request);
		isc_event_free(&event);
		result = dns_request_create(requestmgr, findmsg, &sockaddr,
					    0, NULL,
					    FIND_TIMEOUT, global_task,
					    find_completed, NULL, &request);
		check_result(result, "dns_result_create");
		return;
	}
	ddebug ("About to create rcvmsg");
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &rcvmsg);
	check_result(result, "dns_message_create");
	result = dns_request_getresponse(reqev->request, rcvmsg, ISC_TRUE);
	check_result(result, "dns_request_getresponse");
	section = DNS_SECTION_ANSWER;
	if (debugging) {
		isc_buffer_init(&buf, bufstore, MSGTEXT);
		result = dns_message_totext(rcvmsg, 0, &buf);
		check_result(result, "dns_message_totext");
		printf ("Reply from SOA query:\n%.*s\n",
			(int)isc_buffer_usedlength(&buf),
			(char*)isc_buffer_base(&buf));
	}

	/* XXXMWS Really shouldn't use firstname here */
	section = DNS_SECTION_ANSWER;
	result = dns_message_firstname(rcvmsg, section);
	if (result != ISC_R_SUCCESS) {
		section = DNS_SECTION_AUTHORITY;
		result = dns_message_firstname(rcvmsg, section);
		check_result(result, "dns_message_firstname");
	}
	dns_message_currentname(rcvmsg, section, &name);
	dns_name_init(&actualzone, NULL);
	result = dns_name_dup(name, mctx, &actualzone);

	/* Name is just a reference, so this is safe. */
	name = NULL;

	if (debugging) {
		isc_buffer_clear(&buf);
		result = dns_name_totext(&actualzone, ISC_FALSE, &buf);
		check_result(result, "dns_name_totext");
		printf ("Found zone name: %.*s\n",
			(int)isc_buffer_usedlength(&buf),
			(char*)isc_buffer_base(&buf));
	}

	ddebug("Finding name");
	result = dns_message_findname(rcvmsg, section, &actualzone,
				      dns_rdatatype_soa, 0,
				      &name, &rdataset);
	check_result(result, "Couldn't find SOA in reply");

	result = dns_rdataset_first(rdataset);
	check_result(result, "dns_rdataset_first");
	dns_rdataset_current(rdataset, &rdata);
	ddebug("tostruct");
	result = dns_rdata_tostruct(&rdata, &soa, mctx);
	check_result(result, "dns_rdata_tostruct");
	dns_name_init(&master, NULL);
	ddebug("Duping master");
	result = dns_name_dup(&soa.origin, mctx, &master);
	check_result(result, "dns_name_dup");
	
	if (debugging) {
		isc_buffer_clear(&buf);
		result = dns_name_totext(&master, ISC_FALSE, &buf);
		check_result(result, "dns_name_totext");
		printf ("The master is: %.*s\n",
			(int)isc_buffer_usedlength(&buf),
			(char*)isc_buffer_base(&buf));
	}

	dns_rdata_freestruct(&soa);
	dns_message_destroy(&rcvmsg);
	dns_request_destroy(&reqev->request);
	isc_event_free(&event);
	ddebug ("Out of find_completed");
	send_update();
}

static void
start_update() {
	isc_result_t result;
	dns_rdataset_t *rdataset = NULL;
	dns_name_t *name = NULL;
	isc_sockaddr_t sockaddr;
	dns_request_t *request = NULL;

	ddebug ("start_update()");
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER,
				    &findmsg);
	check_result(result, "dns_message_create");

	findmsg->flags |= DNS_MESSAGEFLAG_RD;

	result = dns_message_gettempname(findmsg, &name);
	check_result(result, "dns_message_gettempname");

	result = dns_message_gettemprdataset(findmsg, &rdataset);
	check_result(result, "dns_message_gettemprdataset");

	dns_rdataset_makequestion(rdataset, dns_rdataclass_in,
				  dns_rdatatype_soa);

	dns_name_init(name, NULL);
	if (!valid_zonename) {
		fatal ("don't have a valid zone yet.");
	}
	dns_name_clone(&zonename, name);

	ISC_LIST_INIT(name->list);
	ISC_LIST_APPEND(name->list, rdataset, link);
	dns_message_addname(findmsg, name, DNS_SECTION_QUESTION);

	ns_inuse = 0;
	get_address(nameservername[0], 53, &sockaddr);
	result = dns_request_create(requestmgr, findmsg, &sockaddr,
				    0, NULL,
				    FIND_TIMEOUT, global_task,
				    find_completed, NULL, &request);
	check_result(result, "dns_request_create");
}


static void
free_lists() {
	ddebug ("free_lists()");

	if (key != NULL) {
		ddebug("Freeing key");
		dns_tsigkey_setdeleted(key);
		dns_tsigkey_detach(&key);
	}

	if (keynamebuf != NULL) {
		ddebug("Freeing keynamebuf");
		isc_buffer_free(&keynamebuf);
	}
	if (keyring != NULL) {
		debug ("Freeing keyring %lx", keyring);
		dns_tsigkeyring_destroy(&keyring);
	}

	if (updatemsg != NULL)
		dns_message_destroy(&updatemsg);
	if (findmsg != NULL)
		dns_message_destroy(&findmsg);

	if (VALID_NAME(&actualzone)) {
		ddebug("Freeing actualzone");
		dns_name_free(&actualzone, mctx);
	}
	if (VALID_NAME(&zonename)) {
		ddebug("Freeing zonename");
		dns_name_free(&zonename, mctx);
	}

	if (is_dst_up) {
		debug ("Destroy DST lib");
		dst_lib_destroy();
		is_dst_up = ISC_FALSE;
	}
	if (entp != NULL) {
		debug ("Detach from entropy");
		isc_entropy_detach(&entp);
	}
		
	ddebug("Shutting down request manager");
	dns_requestmgr_shutdown(requestmgr);
	dns_requestmgr_detach(&requestmgr);

	ddebug("Freeing the dispatcher");
	dns_dispatch_detach(&dispatchv4);

	ddebug("Shutting down dispatch manager");
	dns_dispatchmgr_destroy(&dispatchmgr);

	ddebug("Ending task");
	isc_task_detach(&global_task);

	ddebug("Shutting down task manager");
	isc_taskmgr_destroy(&taskmgr);

	ddebug("Shutting down socket manager");
	isc_socketmgr_destroy(&socketmgr);

	ddebug("Shutting down timer manager");
	isc_timermgr_destroy(&timermgr);

	ddebug("Destroying memory context");
	if (isc_mem_debugging)
		isc_mem_stats(mctx, stderr);
	isc_mem_destroy(&mctx);

	exit(0);
}

int
main(int argc, char **argv) {
        isc_result_t result;
	

        parse_args(argc, argv);

        setup_system();
        result = isc_mutex_init(&lock);
        check_result(result, "isc_mutex_init");
        result = isc_condition_init(&cond);
        check_result(result, "isc_condition_init");
        result = isc_mutex_trylock(&lock);
        check_result(result, "isc_mutex_trylock");

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
        ddebug ("Fell through app_run");
        isc_mutex_destroy(&lock);
        isc_condition_destroy(&cond);
        free_lists(0);

        return (0);
}

