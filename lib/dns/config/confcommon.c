/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

/* $Id: confcommon.c,v 1.28 2000/05/15 12:36:19 brister Exp $ */

#include <config.h>

#include <ctype.h>
#include <syslog.h>	/* XXXRTH */

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/socket.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/util.h>

#include <dns/confcommon.h>
#include <dns/name.h>
#include <dns/peer.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/ssu.h>

/***
 *** TYPES
 ***/
 
#define ordering_nametable_size \
	(sizeof (ordering_nametable) / sizeof (struct dns_c_pvt_ont))
static struct dns_c_pvt_ont {
	dns_c_ordering_t val;
	const char *strval;
} ordering_nametable[] = {
	{ dns_c_ordering_fixed,		"fixed" },
	{ dns_c_ordering_random,	"random" },
	{ dns_c_ordering_cyclic,	"cyclic" }
};


#define log_severity_nametable_size \
	(sizeof (log_severity_nametable) / sizeof (struct dns_c_pvt_lsnt))
static struct dns_c_pvt_lsnt {
	dns_c_logseverity_t val;
	const char *strval;
} log_severity_nametable[] = {
	{ dns_c_log_critical,		"critical" },
	{ dns_c_log_error,		"error" },
	{ dns_c_log_info,		"info" },
	{ dns_c_log_notice,		"notice" },
	{ dns_c_log_warn,		"warning" },
	{ dns_c_log_debug,		"debug" },
	{ dns_c_log_dynamic,		"dynamic" }
};

	
static struct dsn_c_pvt_sfnt {
	int val;
	const char *strval;
} syslog_facil_nametable[] = {
	{ LOG_KERN,			"kern" },
	{ LOG_USER,			"user" },
	{ LOG_MAIL,			"mail" },
	{ LOG_DAEMON,			"daemon" },
	{ LOG_AUTH,			"auth" },
	{ LOG_SYSLOG,			"syslog" },
	{ LOG_LPR,			"lpr" },
#ifdef LOG_NEWS
	{ LOG_NEWS,			"news" },
#endif
#ifdef LOG_UUCP
	{ LOG_UUCP,			"uucp" },
#endif
#ifdef LOG_CRON
	{ LOG_CRON,			"cron" },
#endif
#ifdef LOG_AUTHPRIV
	{ LOG_AUTHPRIV,			"authpriv" },
#endif
#ifdef LOG_FTP
	{ LOG_FTP,			"ftp" },
#endif
	{ LOG_LOCAL0,			"local0"}, 
	{ LOG_LOCAL1,			"local1"}, 
	{ LOG_LOCAL2,			"local2"}, 
	{ LOG_LOCAL3,			"local3"}, 
	{ LOG_LOCAL4,			"local4"}, 
	{ LOG_LOCAL5,			"local5"}, 
	{ LOG_LOCAL6,			"local6"}, 
	{ LOG_LOCAL7,			"local7"}, 
	{ 0,				NULL }
};


static const char *category_nametable[] = {
	"cname",
	"config",
	"control",
	"db",
	"default",
	"eventlib",
	"insist",
	"lame-servers",
	"load",
	"maintenance",
	"ncache",
	"notify",
	"os",
	"packet",
	"panic",
	"parser",
	"queries",
	"response-checks",
	"security",
	"statistics",
	"update",
	"xfer-in",
	"xfer-out",
	NULL
};



/***
 *** DATA
 ***/


/***
 *** FUNCTIONS
 ***/

#if 0					/* XXXJAB delete this code */
static void default_cfgerror(isc_result_t result, const char *fmt,
			     va_list args);
#endif



void
dns_c_printinunits(FILE *fp, isc_uint32_t val) {
	isc_uint32_t one_gig = (1024 * 1024 * 1024);
	isc_uint32_t one_meg = (1024 * 1024);
	isc_uint32_t one_k = 1024;

	if (val == DNS_C_SIZE_SPEC_DEFAULT)
		fprintf(fp, "default");
	else if (val == 0)
		fprintf(fp, "0");
	else if ((val % one_gig) == 0)
		fprintf(fp, "%luG", (unsigned long) val / one_gig);
	else if ((val % one_meg) == 0)
		fprintf(fp, "%luM", (unsigned long) val / one_meg);
	else if ((val % one_k) == 0)
		fprintf(fp, "%luK", (unsigned long) val / one_k);
	else if (val == DNS_C_SIZE_SPEC_UNLIM)
		fprintf(fp, "unlimited");
	else
		fprintf(fp, "%lu", (unsigned long) val);
}


void
dns_c_dataclass_tostream(FILE *fp, dns_rdataclass_t rclass) {
	char buffer[64];
	isc_buffer_t sourceb;

	isc_buffer_init(&sourceb, buffer, sizeof(buffer));
	
	if (dns_rdataclass_totext(rclass, &sourceb) == ISC_R_SUCCESS) {
		INSIST(sourceb.used + 1 < sizeof(buffer));
		buffer[sourceb.used] = '\0';
		fputs(buffer, fp);
	} else {
		fprintf(fp, "UNKNOWN-CLASS(%d)", (int)rclass);
	}
}


void
dns_c_datatype_tostream(FILE *fp, dns_rdatatype_t rtype) {
	char buffer[64];
	isc_buffer_t sourceb;

	isc_buffer_init(&sourceb, buffer, sizeof(buffer));

	if (dns_rdatatype_totext(rtype, &sourceb) == ISC_R_SUCCESS) {
		INSIST(sourceb.used + 1 < sizeof buffer);
		buffer[sourceb.used] = '\0';
		fputs(buffer, fp);
	} else {
		fprintf(fp, "UNKNOWN-RDATATYPE(%d)", (int)rtype);
	}
}


void
dns_c_printtabs(FILE *fp, int count) {

	while (count > 0) {
		fputc('\t', fp);
		count--;
	}
}



isc_result_t
dns_c_string2ordering(char *name, dns_c_ordering_t *ordering) {
	unsigned int i;
	isc_result_t rval = ISC_R_FAILURE;

	for (i = 0 ; i < ordering_nametable_size ; i++) {
		if (strcmp(ordering_nametable[i].strval, name) == 0) {
			*ordering = ordering_nametable[i].val;
			rval = ISC_R_SUCCESS;
			break;
		}
	}
	
	return (rval);
}


const char *
dns_c_ordering2string(dns_c_ordering_t ordering,
		      isc_boolean_t printable)
{
	unsigned int i;
	const char *rval = NULL;

	for (i = 0 ; i < ordering_nametable_size ; i++) {
		if (ordering_nametable[i].val == ordering) {
			rval = ordering_nametable[i].strval;
			break;
		}
	}

	return (rval == NULL && printable ? "UNKNOWN_ORDERING" : rval);
}


const char *
dns_c_logseverity2string(dns_c_logseverity_t severity,
			 isc_boolean_t printable)
{
	unsigned int i;
	const char *rval = NULL;

	for (i = 0 ; i < log_severity_nametable_size ; i++) {
		if (log_severity_nametable[i].val == severity) {
			rval = log_severity_nametable[i].strval;
			break;
		}
	}

	return (rval == NULL && printable ? "UNKNOWN_SEVERITY" : rval);
}


isc_result_t
dns_c_string2logseverity(const char *string,
			 dns_c_logseverity_t *result)
{
	unsigned int i;
	isc_result_t rval = ISC_R_FAILURE;

	REQUIRE(result != NULL);
	
	for (i = 0 ; i < log_severity_nametable_size ; i++) {
		if (strcmp(log_severity_nametable[i].strval, string) == 0) {
			*result = log_severity_nametable[i].val;
			rval = ISC_R_SUCCESS;
			break;
		}
	}

	return rval;
}


#if 0

const char *
dns_c_category2string(dns_c_category_t cat,
		      isc_boolean_t printable)
{
	unsigned int i;
	const char *rval = NULL;

	for (i = 0 ; i < category_nametable_size ; i++) {
		if (category_nametable[i].val == cat) {
			rval = category_nametable[i].strval;
			break;
		}
	}

	return (rval == NULL && printable ? "UNKNOWN_CATEGORY" : rval);
}


isc_result_t
dns_c_string2category(const char *string,
		      dns_c_category_t *category)
{
	unsigned int i;
	isc_result_t rval = ISC_R_FAILURE;

	REQUIRE (category != NULL);
	
	for (i = 0 ; i < category_nametable_size ; i++) {
		if (strcmp(category_nametable[i].strval, string) == 0) {
			*category = category_nametable[i].val;
			rval = ISC_R_SUCCESS;
			break;
		}
	}

	return (rval);
}

#endif


const char *
dns_c_facility2string(int facility, isc_boolean_t printable) {
	int i;
	const char *rval = NULL;

	for (i = 0 ; syslog_facil_nametable[i].strval != NULL ; i++) {
		if (syslog_facil_nametable[i].val == facility) {
			rval = syslog_facil_nametable[i].strval;
			break;
		}
	}
	
	return (rval == NULL && printable ? "UNKNOWN_FACILITY" : rval);
}


isc_result_t
dns_c_string2facility(const char *string, int *result) {
	int i;
	isc_result_t rval = ISC_R_FAILURE;

	for (i = 0 ; syslog_facil_nametable[i].strval != NULL ; i++) {
		if (strcmp(syslog_facil_nametable[i].strval, string) == 0) {
			*result = syslog_facil_nametable[i].val;
			rval = ISC_R_SUCCESS;
			break;
		}
	}

	return rval;
}


const char *
dns_c_transformat2string(dns_transfer_format_t tformat,
			 isc_boolean_t printable)
{
	const char *rval = NULL;

	switch (tformat) {
	case dns_one_answer:
		rval = "one-answer";
		break;

	case dns_many_answers:
		rval = "many-answers";
		break;
	}

	return (rval == NULL && printable ? "UNKNOWN_TRANSFER_FORMAT" : rval);
}




const char *
dns_c_transport2string(dns_c_trans_t transport,
		       isc_boolean_t printable)
{
	const char *rval = NULL;

	switch (transport) {
	case dns_trans_primary:
		rval = "master";
		break;
		
	case dns_trans_secondary:
		rval = "slave";
		break;

	case dns_trans_response:
		rval = "response";
		break;
	}

	return (rval == NULL && printable ? "UNKNOWN_TRANSPORT" : rval);
}


const char *
dns_c_nameseverity2string(dns_severity_t severity,
			  isc_boolean_t printable)
{
	const char *rval = NULL;

	switch (severity) {
	case dns_severity_ignore:
		rval = "ignore";
		break;

	case dns_severity_warn:
		rval = "warn";
		break;

	case dns_severity_fail:
		rval = "fail";
		break;
	}

	return (rval == NULL && printable ? "UNKNOWN_NAME_SEVERITY" : rval);
}


const char *
dns_c_forward2string(dns_c_forw_t forw,
		     isc_boolean_t printable)
{
	const char *rval = NULL;

	switch (forw) {
	case dns_c_forw_only:
		rval = "only";
		break;

	case dns_c_forw_first:
		rval = "first";
		break;

	case dns_c_forw_noanswer:
		rval = "if-no-answer";
		break;

	case dns_c_forw_nodomain:
		rval = "if-no-domain";
		break;
	}

	return (rval == NULL && printable ? "UNKNOWN_FORWARDING" : rval);
}



const char *
dns_c_addata2string(dns_c_addata_t addata,
		    isc_boolean_t printable)
{
	const char *rval = NULL;

	switch (addata) {
	case dns_c_ad_internal:
		rval = "internal";
		break;

	case dns_c_ad_minimal:
		rval = "minimal";
		break;

	case dns_c_ad_maximal:
		rval = "maximal";
		break;
	}

	return (rval == NULL && printable ? "UNKNOWN_ADDITIONAL_DATA" : rval);
}



int
dns_c_isanyaddr(isc_sockaddr_t *inaddr) {
	int result = 0;

	if (inaddr->type.sa.sa_family == AF_INET) {
		if (inaddr->type.sin.sin_addr.s_addr == htonl(INADDR_ANY)) {
			result = 1;
		}
	} else {
		if (memcmp(&inaddr->type.sin6.sin6_addr,
			   &in6addr_any, sizeof in6addr_any) == 0) {
			result = 1;
		}
	}

	return (result);
}
	

	
void
dns_c_print_ipaddr(FILE *fp, isc_sockaddr_t *inaddr) {
	const char *p;
	char tmpaddrstr[64];
	int family = inaddr->type.sa.sa_family;
	void *addr;

	if (dns_c_isanyaddr(inaddr)) {
		if (family == AF_INET) {
			fprintf(fp, "*");
		} else {
			fprintf(fp, "0::0");
		}
	} else {
		addr = (family == AF_INET ?
			(void *)&inaddr->type.sin.sin_addr :
			(void *)&inaddr->type.sin6.sin6_addr);
		
		p = inet_ntop(family, addr, tmpaddrstr, sizeof tmpaddrstr);
		if (p == NULL) {
			fprintf(fp, "BAD-IP-ADDRESS");
		} else {
			fprintf(fp, "%s", tmpaddrstr);
		}
	}
}


isc_boolean_t
dns_c_netaddrisanyaddr(isc_netaddr_t *inaddr) {
	isc_boolean_t result = ISC_FALSE;
	
	if (inaddr->family == AF_INET) {
		if (inaddr->type.in.s_addr == htonl(INADDR_ANY)) {
			result = ISC_TRUE;
		}
	} else {
		if (memcmp(&inaddr->type.in6,
			   &in6addr_any, sizeof in6addr_any) == 0) {
			result = ISC_TRUE;
		}
	}

	return (result);
}




void
dns_c_netaddrprint(FILE *fp, isc_netaddr_t *inaddr) {
	const char *p;
	char tmpaddrstr[64];
	int family = inaddr->family;
	void *addr;

	if (dns_c_netaddrisanyaddr(inaddr)) {
		if (family == AF_INET) {
			fprintf(fp, "*");
		} else {
			fprintf(fp, "0::0");
		}
	} else {
		addr = (family == AF_INET ?
			(void *)&inaddr->type.in :
			(void *)&inaddr->type.in6);
		
		p = inet_ntop(family, addr, tmpaddrstr, sizeof tmpaddrstr);
		if (p == NULL) {
			fprintf(fp, "BAD-IP-ADDRESS");
		} else {
			fprintf(fp, "%s", tmpaddrstr);
		}
	}
}



isc_boolean_t
dns_c_need_quote(const char *string) {
	isc_boolean_t rval = ISC_FALSE;

	while (string != NULL && *string != '\0') {
		if (!(isalnum(*string & 0xff) || *string == '_')) {
			rval = ISC_TRUE;
			break;
		}
		string++;
	}

	return rval;
}


		
void
dns_c_peerlist_print(FILE *fp, int indent,
		     dns_peerlist_t *servers)
{
	dns_peer_t *server;
	
	REQUIRE(fp != NULL);
	REQUIRE(DNS_PEERLIST_VALID(servers));
	
	server = ISC_LIST_HEAD(servers->elements);
	while (server != NULL) {
		dns_c_peer_print(fp, indent, server);
		server = ISC_LIST_NEXT(server, next);
		if (server != NULL) {
			fprintf(fp, "\n");
		}
	}
	
	return;
}


void
dns_c_peer_print(FILE *fp, int indent, dns_peer_t *peer) {
	isc_boolean_t bval;
	isc_result_t res;
	dns_transfer_format_t tval;
	isc_int32_t ival;
	dns_name_t *name = NULL;
	
	REQUIRE(DNS_PEER_VALID(peer));
	REQUIRE(fp != NULL);
	
	dns_c_printtabs(fp, indent);
	fprintf(fp, "server ");
	dns_c_netaddrprint(fp, &peer->address);
	fprintf(fp, " {\n");
	
	res = dns_peer_getbogus(peer, &bval);
	if (res == ISC_R_SUCCESS) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "bogus %s;\n", (bval ? "true" : "false"));
	}

	res = dns_peer_gettransferformat(peer, &tval);
	if (res == ISC_R_SUCCESS) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "transfer-format %s;\n",
			dns_c_transformat2string(tval, ISC_TRUE));
	}

	res = dns_peer_gettransfers(peer, &ival);
	if (res == ISC_R_SUCCESS) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "transfers %d;\n", ival);
	}

	res = dns_peer_getprovideixfr(peer, &bval);
	if (res == ISC_R_SUCCESS) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "provide-ixfr %s;\n", (bval ? "true" : "false"));
	}

	res = dns_peer_getrequestixfr(peer, &bval);
	if (res == ISC_R_SUCCESS) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "request-ixfr %s;\n", (bval ? "true" : "false"));
	}

	res = dns_peer_getkey(peer, &name);
	if (res == ISC_R_SUCCESS) {
		REQUIRE(name != NULL);
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "keys { \"");
		dns_name_print(peer->key, fp);
		fprintf(fp, "\"; };\n");
	}
	
	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");
}




isc_result_t
dns_c_charptoname(isc_mem_t *mem, const char *keyval, dns_name_t **name) {
	dns_name_t newkey;
	isc_buffer_t *b1 = NULL;
	isc_buffer_t b2;
	isc_result_t res;
	unsigned int len;

	REQUIRE(keyval != NULL);
	REQUIRE(*keyval != '\0');
	REQUIRE(name != NULL);

	len = strlen(keyval);
	
	dns_name_init(&newkey, NULL);
	res = isc_buffer_allocate(mem, &b1, len + 2);
	REQUIRE(res == ISC_R_SUCCESS);
	
	dns_name_setbuffer(&newkey, b1);
	
	isc_buffer_init(&b2, (char *)keyval, len);
	isc_buffer_add(&b2, len);
	
	res = dns_name_fromtext(&newkey, &b2, NULL, ISC_FALSE, NULL);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	*name = isc_mem_get(mem, sizeof (dns_name_t));
	REQUIRE(*name != NULL);
	dns_name_init(*name, NULL);
	
	dns_name_dup(&newkey, mem, *name);
	dns_name_invalidate(&newkey);
	isc_buffer_free(&b1);

	return (ISC_R_SUCCESS);
}

void
dns_c_ssutable_print(FILE *fp, int indent, dns_ssutable_t *ssutable) {
	dns_ssurule_t *rule = NULL;
	dns_ssurule_t *tmprule = NULL;
	isc_result_t res;
	dns_rdatatype_t *types;
	unsigned int i;
	unsigned int tcount;
	
	res = dns_ssutable_firstrule(ssutable, &rule);
	if (res != ISC_R_SUCCESS) {
		return;
	}

	fputc('\n', fp);
	dns_c_printtabs(fp, indent);
	fprintf(fp, "update-policy {\n");
	
	do {
		dns_c_printtabs(fp, indent + 1);

		fputs ((dns_ssurule_isgrant(rule) ? "grant" : "deny"), fp);
		fputc(' ', fp);
		
		dns_name_print(dns_ssurule_identity(rule), fp);
		fputc(' ', fp);

		switch(dns_ssurule_matchtype(rule)) {
		case DNS_SSUMATCHTYPE_NAME:
			fputs("name", fp);
			break;

		case DNS_SSUMATCHTYPE_SUBDOMAIN:
			fputs("subdomain", fp);
			break;

		case DNS_SSUMATCHTYPE_WILDCARD:
			fputs("wildcard", fp);
			break;

		case DNS_SSUMATCHTYPE_SELF:
			fputs("self", fp);
			break;

		default:
			REQUIRE(0);
			break;
		}
		fputc(' ', fp);

		dns_name_print(dns_ssurule_name(rule), fp);
		fputc(' ', fp);

		tcount = dns_ssurule_types(rule, &types);
		for(i = 0 ; i < tcount ; i++) {
			fputc('\"', fp);
			dns_c_datatype_tostream(fp, types[i]);
			fputc('\"', fp);
			fputc(' ', fp);
		}

		fputs(";\n", fp);
		tmprule = rule;
		rule = NULL;
	} while (dns_ssutable_nextrule(tmprule, &rule) == ISC_R_SUCCESS);
	fputc('\n', fp);
	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");
}


isc_result_t
dns_c_checkcategory(const char *name) {
	unsigned int i;

	REQUIRE (name != NULL);
	REQUIRE(*name != '\0');

	/*
	 * This function isn't called very often, so no need for fancy
	 * searches.
	 */
	for (i = 0 ; category_nametable[i] != NULL ; i++) {
		if (strcmp(category_nametable[i], name) == 0) {
			return (ISC_R_SUCCESS);
		}
	}

	return (ISC_R_FAILURE);
}
	
