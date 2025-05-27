/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <stdbool.h>

#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/dlz.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/ssu.h>

#include <dst/dst.h>
#include <dst/gssapi.h>

#define SSUTABLEMAGIC	      ISC_MAGIC('S', 'S', 'U', 'T')
#define VALID_SSUTABLE(table) ISC_MAGIC_VALID(table, SSUTABLEMAGIC)

#define SSURULEMAGIC	     ISC_MAGIC('S', 'S', 'U', 'R')
#define VALID_SSURULE(table) ISC_MAGIC_VALID(table, SSURULEMAGIC)

struct dns_ssurule {
	unsigned int magic;
	bool grant;		      /*%< is this a grant or a deny? */
	dns_ssumatchtype_t matchtype; /*%< which type of pattern match? */
	dns_name_t *identity;	      /*%< the identity to match */
	dns_name_t *name;	      /*%< the name being updated */
	unsigned int ntypes;	      /*%< number of data types covered */
	dns_ssuruletype_t *types;     /*%< the data types.  Can include */
				      /*   ANY. if NULL, defaults to all */
				      /*   types except SIG, SOA, and NS */
	char *debug;		      /*%< text version for debugging */
	ISC_LINK(dns_ssurule_t) link;
};

struct dns_ssutable {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_refcount_t references;
	dns_dlzdb_t *dlzdatabase;
	ISC_LIST(dns_ssurule_t) rules;
};

void
dns_ssutable_create(isc_mem_t *mctx, dns_ssutable_t **tablep) {
	dns_ssutable_t *table;

	REQUIRE(tablep != NULL && *tablep == NULL);
	REQUIRE(mctx != NULL);

	table = isc_mem_get(mctx, sizeof(*table));
	isc_refcount_init(&table->references, 1);
	table->mctx = NULL;
	isc_mem_attach(mctx, &table->mctx);
	ISC_LIST_INIT(table->rules);
	table->magic = SSUTABLEMAGIC;
	*tablep = table;
}

static void
destroy(dns_ssutable_t *table) {
	isc_mem_t *mctx;

	REQUIRE(VALID_SSUTABLE(table));

	mctx = table->mctx;
	ISC_LIST_FOREACH (table->rules, rule, link) {
		if (rule->identity != NULL) {
			dns_name_free(rule->identity, mctx);
			isc_mem_put(mctx, rule->identity,
				    sizeof(*rule->identity));
		}
		if (rule->name != NULL) {
			dns_name_free(rule->name, mctx);
			isc_mem_put(mctx, rule->name, sizeof(*rule->name));
		}
		if (rule->types != NULL) {
			isc_mem_cput(mctx, rule->types, rule->ntypes,
				     sizeof(*rule->types));
		}
		if (rule->debug != NULL) {
			isc_mem_free(mctx, rule->debug);
		}
		ISC_LIST_UNLINK(table->rules, rule, link);
		rule->magic = 0;
		isc_mem_put(mctx, rule, sizeof(dns_ssurule_t));
	}
	isc_refcount_destroy(&table->references);
	table->magic = 0;
	isc_mem_putanddetach(&table->mctx, table, sizeof(dns_ssutable_t));
}

void
dns_ssutable_attach(dns_ssutable_t *source, dns_ssutable_t **targetp) {
	REQUIRE(VALID_SSUTABLE(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);

	*targetp = source;
}

void
dns_ssutable_detach(dns_ssutable_t **tablep) {
	dns_ssutable_t *table;

	REQUIRE(tablep != NULL);
	table = *tablep;
	*tablep = NULL;
	REQUIRE(VALID_SSUTABLE(table));

	if (isc_refcount_decrement(&table->references) == 1) {
		destroy(table);
	}
}

static const char *
mtypetostring(dns_ssumatchtype_t matchtype) {
	switch (matchtype) {
	case dns_ssumatchtype_name:
		return "name";
	case dns_ssumatchtype_wildcard:
		return "wildcard";
	case dns_ssumatchtype_self:
		return "self";
	case dns_ssumatchtype_selfsub:
		return "selfsub";
	case dns_ssumatchtype_selfwild:
		return "selfwild";
	case dns_ssumatchtype_selfms:
		return "ms-self";
	case dns_ssumatchtype_selfsubms:
		return "ms-selfsub";
	case dns_ssumatchtype_selfkrb5:
		return "krb5-self";
	case dns_ssumatchtype_selfsubkrb5:
		return "krb5-selfsub";
	case dns_ssumatchtype_subdomainms:
		return "ms-subdomain";
	case dns_ssumatchtype_subdomainselfmsrhs:
		return "ms-subdomain-self-rhs";
	case dns_ssumatchtype_subdomainkrb5:
		return "krb5-subdomain";
	case dns_ssumatchtype_subdomainselfkrb5rhs:
		return "krb5-subdomain-self-rhs";
	case dns_ssumatchtype_tcpself:
		return "tcp-self";
	case dns_ssumatchtype_6to4self:
		return "6to4-self";
	case dns_ssumatchtype_subdomain:
		return "subdomain";
	case dns_ssumatchtype_external:
		return "external";
	case dns_ssumatchtype_local:
		return "local";
	case dns_ssumatchtype_dlz:
		return "dlz";
	}
	return "UnknownMatchType";
}

void
dns_ssutable_addrule(dns_ssutable_t *table, bool grant,
		     const dns_name_t *identity, dns_ssumatchtype_t matchtype,
		     const dns_name_t *name, unsigned int ntypes,
		     dns_ssuruletype_t *types, const char *debug) {
	dns_ssurule_t *rule;
	isc_mem_t *mctx;

	REQUIRE(VALID_SSUTABLE(table));
	REQUIRE(dns_name_isabsolute(identity));
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(matchtype <= dns_ssumatchtype_max);
	if (matchtype == dns_ssumatchtype_wildcard) {
		REQUIRE(dns_name_iswildcard(name));
	}
	if (ntypes > 0) {
		REQUIRE(types != NULL);
	}
	REQUIRE(debug != NULL);

	mctx = table->mctx;
	rule = isc_mem_get(mctx, sizeof(*rule));
	*rule = (dns_ssurule_t){
		.grant = grant,
		.matchtype = matchtype,
		.identity = isc_mem_get(mctx, sizeof(*rule->identity)),
		.name = isc_mem_get(mctx, sizeof(*rule->name)),
		.ntypes = ntypes,
		.types = ntypes == 0 ? NULL
				     : isc_mem_cget(mctx, ntypes,
						    sizeof(*rule->types)),
		.link = ISC_LINK_INITIALIZER,
		.magic = SSURULEMAGIC,
	};

	dns_name_init(rule->identity);
	dns_name_dup(identity, mctx, rule->identity);
	dns_name_init(rule->name);
	dns_name_dup(name, mctx, rule->name);

	if (ntypes > 0) {
		memmove(rule->types, types, ntypes * sizeof(*rule->types));
	}

	rule->debug = isc_mem_strdup(mctx, debug);

	ISC_LIST_INITANDAPPEND(table->rules, rule, link);
}

static bool
isusertype(dns_rdatatype_t type) {
	return type != dns_rdatatype_ns && type != dns_rdatatype_soa &&
	       type != dns_rdatatype_rrsig;
}

static void
reverse_from_address(dns_name_t *tcpself, const isc_netaddr_t *tcpaddr) {
	char buf[16 * 4 + sizeof("IP6.ARPA.")];
	isc_result_t result;
	const unsigned char *ap;
	isc_buffer_t b;
	unsigned long l;

	switch (tcpaddr->family) {
	case AF_INET:
		l = ntohl(tcpaddr->type.in.s_addr);
		result = snprintf(buf, sizeof(buf),
				  "%lu.%lu.%lu.%lu.IN-ADDR.ARPA.",
				  (l >> 0) & 0xff, (l >> 8) & 0xff,
				  (l >> 16) & 0xff, (l >> 24) & 0xff);
		RUNTIME_CHECK(result < sizeof(buf));
		break;
	case AF_INET6:
		ap = tcpaddr->type.in6.s6_addr;
		result = snprintf(
			buf, sizeof(buf),
			"%x.%x.%x.%x.%x.%x.%x.%x."
			"%x.%x.%x.%x.%x.%x.%x.%x."
			"%x.%x.%x.%x.%x.%x.%x.%x."
			"%x.%x.%x.%x.%x.%x.%x.%x."
			"IP6.ARPA.",
			ap[15] & 0x0f, (ap[15] >> 4) & 0x0f, ap[14] & 0x0f,
			(ap[14] >> 4) & 0x0f, ap[13] & 0x0f,
			(ap[13] >> 4) & 0x0f, ap[12] & 0x0f,
			(ap[12] >> 4) & 0x0f, ap[11] & 0x0f,
			(ap[11] >> 4) & 0x0f, ap[10] & 0x0f,
			(ap[10] >> 4) & 0x0f, ap[9] & 0x0f, (ap[9] >> 4) & 0x0f,
			ap[8] & 0x0f, (ap[8] >> 4) & 0x0f, ap[7] & 0x0f,
			(ap[7] >> 4) & 0x0f, ap[6] & 0x0f, (ap[6] >> 4) & 0x0f,
			ap[5] & 0x0f, (ap[5] >> 4) & 0x0f, ap[4] & 0x0f,
			(ap[4] >> 4) & 0x0f, ap[3] & 0x0f, (ap[3] >> 4) & 0x0f,
			ap[2] & 0x0f, (ap[2] >> 4) & 0x0f, ap[1] & 0x0f,
			(ap[1] >> 4) & 0x0f, ap[0] & 0x0f, (ap[0] >> 4) & 0x0f);
		RUNTIME_CHECK(result < sizeof(buf));
		break;
	default:
		UNREACHABLE();
	}
	isc_buffer_init(&b, buf, strlen(buf));
	isc_buffer_add(&b, strlen(buf));
	result = dns_name_fromtext(tcpself, &b, dns_rootname, 0);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
}

static void
stf_from_address(dns_name_t *stfself, const isc_netaddr_t *tcpaddr) {
	char buf[sizeof("X.X.X.X.Y.Y.Y.Y.2.0.0.2.IP6.ARPA.")];
	isc_result_t result;
	const unsigned char *ap;
	isc_buffer_t b;
	unsigned long l;

	switch (tcpaddr->family) {
	case AF_INET:
		l = ntohl(tcpaddr->type.in.s_addr);
		result = snprintf(
			buf, sizeof(buf),
			"%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.2.0.0.2.IP6.ARPA.",
			l & 0xf, (l >> 4) & 0xf, (l >> 8) & 0xf,
			(l >> 12) & 0xf, (l >> 16) & 0xf, (l >> 20) & 0xf,
			(l >> 24) & 0xf, (l >> 28) & 0xf);
		RUNTIME_CHECK(result < sizeof(buf));
		break;
	case AF_INET6:
		ap = tcpaddr->type.in6.s6_addr;
		result = snprintf(
			buf, sizeof(buf),
			"%x.%x.%x.%x.%x.%x.%x.%x."
			"%x.%x.%x.%x.IP6.ARPA.",
			ap[5] & 0x0f, (ap[5] >> 4) & 0x0f, ap[4] & 0x0f,
			(ap[4] >> 4) & 0x0f, ap[3] & 0x0f, (ap[3] >> 4) & 0x0f,
			ap[2] & 0x0f, (ap[2] >> 4) & 0x0f, ap[1] & 0x0f,
			(ap[1] >> 4) & 0x0f, ap[0] & 0x0f, (ap[0] >> 4) & 0x0f);
		RUNTIME_CHECK(result < sizeof(buf));
		break;
	default:
		UNREACHABLE();
	}
	isc_buffer_init(&b, buf, strlen(buf));
	isc_buffer_add(&b, strlen(buf));
	result = dns_name_fromtext(stfself, &b, dns_rootname, 0);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
}

bool
dns_ssutable_checkrules(dns_ssutable_t *table, const dns_name_t *signer,
			const dns_name_t *name, const isc_netaddr_t *addr,
			bool tcp, dns_aclenv_t *env, dns_rdatatype_t type,
			const dns_name_t *target, const dst_key_t *key,
			const dns_ssurule_t **rulep) {
	dns_fixedname_t fixed;
	dns_name_t *stfself;
	dns_name_t *tcpself;
	dns_name_t *wildcard;
	const dns_name_t *tname;
	int match;
	isc_result_t result;
	unsigned int i;
	bool logit = isc_log_wouldlog(99);

	REQUIRE(VALID_SSUTABLE(table));
	REQUIRE(signer == NULL || dns_name_isabsolute(signer));
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(addr == NULL || env != NULL);

	if (logit) {
		char signerbuf[DNS_NAME_FORMATSIZE] = { 0 };
		char namebuf[DNS_NAME_FORMATSIZE] = { 0 };
		char targetbuf[DNS_NAME_FORMATSIZE] = { 0 };
		char addrbuf[ISC_NETADDR_FORMATSIZE] = { 0 };
		char typebuf[DNS_RDATATYPE_FORMATSIZE] = { 0 };

		if (signer != NULL) {
			dns_name_format(signer, signerbuf, sizeof(signerbuf));
		}
		dns_name_format(name, namebuf, sizeof(namebuf));
		if (target != NULL) {
			dns_name_format(target, targetbuf, sizeof(targetbuf));
		}
		dns_rdatatype_format(type, typebuf, sizeof(typebuf));
		if (addr != NULL) {
			isc_netaddr_format(addr, addrbuf, sizeof(addrbuf));
		}

		isc_log_write(DNS_LOGCATEGORY_UPDATE_POLICY, DNS_LOGMODULE_SSU,
			      ISC_LOG_DEBUG(99),
			      "update-policy: using: signer=%s name=%s addr=%s "
			      "tcp=%u type=%s target=%s",
			      signerbuf, namebuf, addrbuf, tcp, typebuf,
			      targetbuf);
	}

	if (signer == NULL && addr == NULL) {
		return false;
	}

	ISC_LIST_FOREACH (table->rules, rule, link) {
		if (logit) {
			isc_log_write(DNS_LOGCATEGORY_UPDATE_POLICY,
				      DNS_LOGMODULE_SSU, ISC_LOG_DEBUG(99),
				      "update-policy: trying: %s",
				      rule->debug != NULL ? rule->debug
							  : "not available");

			if (tcp && addr != NULL) {
				char namebuf[DNS_NAME_FORMATSIZE] = { 0 };
				switch (rule->matchtype) {
				case dns_ssumatchtype_tcpself:
					tcpself =
						dns_fixedname_initname(&fixed);
					reverse_from_address(tcpself, addr);
					dns_name_format(tcpself, namebuf,
							sizeof(namebuf));
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: %s=%s",
						mtypetostring(rule->matchtype),
						namebuf);
					break;
				case dns_ssumatchtype_6to4self:
					stfself =
						dns_fixedname_initname(&fixed);
					stf_from_address(stfself, addr);
					dns_name_format(stfself, namebuf,
							sizeof(namebuf));
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: %s=%s",
						mtypetostring(rule->matchtype),
						namebuf);
					break;
				default:
					break;
				}
			}
		}
		switch (rule->matchtype) {
		case dns_ssumatchtype_local:
		case dns_ssumatchtype_name:
		case dns_ssumatchtype_self:
		case dns_ssumatchtype_selfsub:
		case dns_ssumatchtype_selfwild:
		case dns_ssumatchtype_subdomain:
		case dns_ssumatchtype_wildcard:
			if (signer == NULL) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: no signer");
				}
				continue;
			}
			if (dns_name_iswildcard(rule->identity)) {
				if (!dns_name_matcheswildcard(signer,
							      rule->identity))
				{
					if (logit) {
						isc_log_write(
							DNS_LOGCATEGORY_UPDATE_POLICY,
							DNS_LOGMODULE_SSU,
							ISC_LOG_DEBUG(99),
							"update-policy: next "
							"rule: signer does not "
							"match wildcard "
							"identity");
					}
					continue;
				}
			} else {
				if (!dns_name_equal(signer, rule->identity)) {
					if (logit) {
						isc_log_write(
							DNS_LOGCATEGORY_UPDATE_POLICY,
							DNS_LOGMODULE_SSU,
							ISC_LOG_DEBUG(99),
							"update-policy: next "
							"rule: signer does not "
							"match identity");
					}
					continue;
				}
			}
			break;
		case dns_ssumatchtype_selfkrb5:
		case dns_ssumatchtype_selfms:
		case dns_ssumatchtype_selfsubkrb5:
		case dns_ssumatchtype_selfsubms:
		case dns_ssumatchtype_subdomainkrb5:
		case dns_ssumatchtype_subdomainms:
		case dns_ssumatchtype_subdomainselfkrb5rhs:
		case dns_ssumatchtype_subdomainselfmsrhs:
			if (signer == NULL) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: no signer");
				}
				continue;
			}
			break;
		case dns_ssumatchtype_tcpself:
		case dns_ssumatchtype_6to4self:
			if (!tcp || addr == NULL) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next rule: %s",
						tcp ? "no address" : "not TCP");
				}
				continue;
			}
			break;
		case dns_ssumatchtype_external:
		case dns_ssumatchtype_dlz:
			break;
		}

		switch (rule->matchtype) {
		case dns_ssumatchtype_name:
			if (!dns_name_equal(name, rule->name)) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: name mismatch");
				}
				continue;
			}
			break;
		case dns_ssumatchtype_subdomain:
			if (!dns_name_issubdomain(name, rule->name)) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next rule: "
						"name/subdomain mismatch");
				}
				continue;
			}
			break;
		case dns_ssumatchtype_local:
			if (addr == NULL) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: no address");
				}
				continue;
			}
			if (!dns_name_issubdomain(name, rule->name)) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next rule: "
						"name/subdomain mismatch");
				}
				continue;
			}
			rcu_read_lock();
			dns_acl_t *localhost = rcu_dereference(env->localhost);
			dns_acl_match(addr, NULL, localhost, NULL, &match,
				      NULL);
			rcu_read_unlock();
			if (match == 0) {
				if (signer != NULL) {
					isc_log_write(DNS_LOGCATEGORY_GENERAL,
						      DNS_LOGMODULE_SSU,
						      ISC_LOG_WARNING,
						      "update-policy local: "
						      "match on session "
						      "key not from "
						      "localhost");
				}
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next rule: "
						"address not local");
				}
				continue;
			}
			break;
		case dns_ssumatchtype_wildcard:
			if (!dns_name_matcheswildcard(name, rule->name)) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: record name does "
						"not match wilcard name");
				}
				continue;
			}
			break;
		case dns_ssumatchtype_self:
			if (!dns_name_equal(signer, name)) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: record named not "
						"equal signer");
				}
				continue;
			}
			break;
		case dns_ssumatchtype_selfsub:
			if (!dns_name_issubdomain(name, signer)) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: record name not "
						"subdomain of signer");
				}
				continue;
			}
			break;
		case dns_ssumatchtype_selfwild:
			wildcard = dns_fixedname_initname(&fixed);
			result = dns_name_concatenate(dns_wildcardname, signer,
						      wildcard);
			if (result != ISC_R_SUCCESS) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: wilcard, signer "
						"concatenation failed");
				}
				continue;
			}
			if (!dns_name_matcheswildcard(name, wildcard)) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next rule: "
						"record name does not match "
						"wildcarded signer");
				}
				continue;
			}
			break;
		case dns_ssumatchtype_selfkrb5:
			if (dst_gssapi_identitymatchesrealmkrb5(
				    signer, name, rule->identity, false))
			{
				break;
			}
			if (logit) {
				isc_log_write(
					DNS_LOGCATEGORY_UPDATE_POLICY,
					DNS_LOGMODULE_SSU, ISC_LOG_DEBUG(99),
					"update-policy: next rule: krb5 signer "
					"doesn't map to record name");
			}
			continue;
		case dns_ssumatchtype_selfms:
			if (dst_gssapi_identitymatchesrealmms(
				    signer, name, rule->identity, false))
			{
				break;
			}
			if (logit) {
				isc_log_write(
					DNS_LOGCATEGORY_UPDATE_POLICY,
					DNS_LOGMODULE_SSU, ISC_LOG_DEBUG(99),
					"update-policy: next rule: MS Windows "
					"signer doesn't map to record name");
			}
			continue;
		case dns_ssumatchtype_selfsubkrb5:
			if (dst_gssapi_identitymatchesrealmkrb5(
				    signer, name, rule->identity, true))
			{
				break;
			}
			if (logit) {
				isc_log_write(DNS_LOGCATEGORY_UPDATE_POLICY,
					      DNS_LOGMODULE_SSU,
					      ISC_LOG_DEBUG(99),
					      "update-policy: next rule: "
					      "record name not a subdomain of "
					      "krb5 signer mapped name");
			}
			continue;
		case dns_ssumatchtype_selfsubms:
			if (dst_gssapi_identitymatchesrealmms(
				    signer, name, rule->identity, true))
			{
				break;
			}
			if (logit) {
				isc_log_write(DNS_LOGCATEGORY_UPDATE_POLICY,
					      DNS_LOGMODULE_SSU,
					      ISC_LOG_DEBUG(99),
					      "update-policy: next rule: "
					      "record name not a subdomain of "
					      "MS Windows signer mapped name");
			}
			continue;
		case dns_ssumatchtype_subdomainkrb5:
		case dns_ssumatchtype_subdomainselfkrb5rhs:
			if (!dns_name_issubdomain(name, rule->name)) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: record name not a "
						"subdomain of rule name");
				}
				continue;
			}
			tname = NULL;
			switch (rule->matchtype) {
			case dns_ssumatchtype_subdomainselfkrb5rhs:
				if (type == dns_rdatatype_ptr) {
					tname = target;
				}
				if (type == dns_rdatatype_srv) {
					tname = target;
				}
				break;
			default:
				break;
			}
			if (dst_gssapi_identitymatchesrealmkrb5(
				    signer, tname, rule->identity, false))
			{
				break;
			}
			if (logit) {
				isc_log_write(DNS_LOGCATEGORY_UPDATE_POLICY,
					      DNS_LOGMODULE_SSU,
					      ISC_LOG_DEBUG(99),
					      "update-policy: next rule: rdata "
					      "name does not match krb5 signer "
					      "mapped name");
			}
			continue;
		case dns_ssumatchtype_subdomainms:
		case dns_ssumatchtype_subdomainselfmsrhs:
			if (!dns_name_issubdomain(name, rule->name)) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: record name not a "
						"subdomain of rule name");
				}
				continue;
			}
			tname = NULL;
			switch (rule->matchtype) {
			case dns_ssumatchtype_subdomainselfmsrhs:
				if (type == dns_rdatatype_ptr) {
					tname = target;
				}
				if (type == dns_rdatatype_srv) {
					tname = target;
				}
				break;
			default:
				break;
			}
			if (dst_gssapi_identitymatchesrealmms(
				    signer, tname, rule->identity, false))
			{
				break;
			}
			if (logit) {
				isc_log_write(DNS_LOGCATEGORY_UPDATE_POLICY,
					      DNS_LOGMODULE_SSU,
					      ISC_LOG_DEBUG(99),
					      "update-policy: next rule: rdata "
					      "name does not match MS Windows "
					      "signer mapped name");
			}
			continue;
		case dns_ssumatchtype_tcpself:
			tcpself = dns_fixedname_initname(&fixed);
			reverse_from_address(tcpself, addr);
			if (dns_name_iswildcard(rule->identity)) {
				if (!dns_name_matcheswildcard(tcpself,
							      rule->identity))
				{
					if (logit) {
						isc_log_write(
							DNS_LOGCATEGORY_UPDATE_POLICY,
							DNS_LOGMODULE_SSU,
							ISC_LOG_DEBUG(99),
							"update-policy: next "
							"rule: tcp-self name "
							"does not match "
							"wildcard identity");
					}
					continue;
				}
			} else {
				if (!dns_name_equal(tcpself, rule->identity)) {
					if (logit) {
						isc_log_write(
							DNS_LOGCATEGORY_UPDATE_POLICY,
							DNS_LOGMODULE_SSU,
							ISC_LOG_DEBUG(99),
							"update-policy: next "
							"rule: tcp-self name "
							"does not match "
							"identity");
					}
					continue;
				}
			}
			if (!dns_name_equal(tcpself, name)) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next rule: "
						"tcp-self name does not match "
						"record name");
				}
				continue;
			}
			break;
		case dns_ssumatchtype_6to4self:
			stfself = dns_fixedname_initname(&fixed);
			stf_from_address(stfself, addr);
			if (dns_name_iswildcard(rule->identity)) {
				if (!dns_name_matcheswildcard(stfself,
							      rule->identity))
				{
					if (logit) {
						isc_log_write(
							DNS_LOGCATEGORY_UPDATE_POLICY,
							DNS_LOGMODULE_SSU,
							ISC_LOG_DEBUG(99),
							"update-policy: next "
							"rule: %s name "
							"does not match "
							"wildcard identity",
							mtypetostring(
								rule->matchtype));
					}
					continue;
				}
			} else {
				if (!dns_name_equal(stfself, rule->identity)) {
					if (logit) {
						isc_log_write(
							DNS_LOGCATEGORY_UPDATE_POLICY,
							DNS_LOGMODULE_SSU,
							ISC_LOG_DEBUG(99),
							"update-policy: next "
							"rule: %s name does "
							"not match identity",
							mtypetostring(
								rule->matchtype));
					}
					continue;
				}
			}
			if (!dns_name_equal(stfself, name)) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: %s name does not "
						"match record name",
						mtypetostring(rule->matchtype));
				}
				continue;
			}
			break;
		case dns_ssumatchtype_external:
			if (!dns_ssu_external_match(rule->identity, signer,
						    name, addr, type, key,
						    table->mctx))
			{
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next rule: "
						"external match failed");
				}
				continue;
			}
			break;
		case dns_ssumatchtype_dlz:
			if (!dns_dlz_ssumatch(table->dlzdatabase, signer, name,
					      addr, type, key))
			{
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: dlz match failed");
				}
				continue;
			}
			break;
		}

		if (rule->ntypes == 0) {
			/*
			 * If this is a DLZ rule, then the DLZ ssu
			 * checks will have already checked the type.
			 */
			if (rule->matchtype != dns_ssumatchtype_dlz &&
			    !isusertype(type))
			{
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next "
						"rule: not user type");
				}
				continue;
			}
		} else {
			for (i = 0; i < rule->ntypes; i++) {
				if (rule->types[i].type == dns_rdatatype_any ||
				    rule->types[i].type == type)
				{
					break;
				}
			}
			if (i == rule->ntypes) {
				if (logit) {
					isc_log_write(
						DNS_LOGCATEGORY_UPDATE_POLICY,
						DNS_LOGMODULE_SSU,
						ISC_LOG_DEBUG(99),
						"update-policy: next rule: "
						"type not in type list");
				}
				continue;
			}
		}
		if (rule->grant && rulep != NULL) {
			*rulep = rule;
		}
		if (logit) {
			isc_log_write(DNS_LOGCATEGORY_UPDATE_POLICY,
				      DNS_LOGMODULE_SSU, ISC_LOG_DEBUG(99),
				      "update-policy: matched: %s",
				      rule->debug != NULL ? rule->debug
							  : "not available");
		}
		return rule->grant;
	}
	if (logit) {
		isc_log_write(DNS_LOGCATEGORY_UPDATE_POLICY, DNS_LOGMODULE_SSU,
			      ISC_LOG_DEBUG(99),
			      "update-policy: no match found");
	}

	return false;
}

bool
dns_ssurule_isgrant(const dns_ssurule_t *rule) {
	REQUIRE(VALID_SSURULE(rule));
	return rule->grant;
}

dns_name_t *
dns_ssurule_identity(const dns_ssurule_t *rule) {
	REQUIRE(VALID_SSURULE(rule));
	return rule->identity;
}

unsigned int
dns_ssurule_matchtype(const dns_ssurule_t *rule) {
	REQUIRE(VALID_SSURULE(rule));
	return rule->matchtype;
}

dns_name_t *
dns_ssurule_name(const dns_ssurule_t *rule) {
	REQUIRE(VALID_SSURULE(rule));
	return rule->name;
}

unsigned int
dns_ssurule_types(const dns_ssurule_t *rule, dns_ssuruletype_t **types) {
	REQUIRE(VALID_SSURULE(rule));
	REQUIRE(types != NULL && *types != NULL);
	*types = rule->types;
	return rule->ntypes;
}

unsigned int
dns_ssurule_max(const dns_ssurule_t *rule, dns_rdatatype_t type) {
	unsigned int i;
	unsigned int max = 0;

	REQUIRE(VALID_SSURULE(rule));

	for (i = 0; i < rule->ntypes; i++) {
		if (rule->types[i].type == dns_rdatatype_any) {
			max = rule->types[i].max;
		}
		if (rule->types[i].type == type) {
			return rule->types[i].max;
		}
	}
	return max;
}

isc_result_t
dns_ssutable_firstrule(const dns_ssutable_t *table, dns_ssurule_t **rule) {
	REQUIRE(VALID_SSUTABLE(table));
	REQUIRE(rule != NULL && *rule == NULL);
	*rule = ISC_LIST_HEAD(table->rules);
	return *rule != NULL ? ISC_R_SUCCESS : ISC_R_NOMORE;
}

isc_result_t
dns_ssutable_nextrule(dns_ssurule_t *rule, dns_ssurule_t **nextrule) {
	REQUIRE(VALID_SSURULE(rule));
	REQUIRE(nextrule != NULL && *nextrule == NULL);
	*nextrule = ISC_LIST_NEXT(rule, link);
	return *nextrule != NULL ? ISC_R_SUCCESS : ISC_R_NOMORE;
}

/*
 * Create a specialised SSU table that points at an external DLZ database
 */
void
dns_ssutable_createdlz(isc_mem_t *mctx, dns_ssutable_t **tablep,
		       dns_dlzdb_t *dlzdatabase) {
	dns_ssurule_t *rule;
	dns_ssutable_t *table = NULL;

	REQUIRE(tablep != NULL && *tablep == NULL);

	dns_ssutable_create(mctx, &table);

	table->dlzdatabase = dlzdatabase;

	rule = isc_mem_get(table->mctx, sizeof(dns_ssurule_t));

	*rule = (dns_ssurule_t){
		.grant = true,
		.matchtype = dns_ssumatchtype_dlz,
		.magic = SSURULEMAGIC,
	};

	rule->debug = isc_mem_strdup(mctx, "grant dlz");

	ISC_LIST_INITANDAPPEND(table->rules, rule, link);
	*tablep = table;
}

isc_result_t
dns_ssu_mtypefromstring(const char *str, dns_ssumatchtype_t *mtype) {
	REQUIRE(str != NULL);
	REQUIRE(mtype != NULL);

	if (strcasecmp(str, "name") == 0) {
		*mtype = dns_ssumatchtype_name;
	} else if (strcasecmp(str, "subdomain") == 0) {
		*mtype = dns_ssumatchtype_subdomain;
	} else if (strcasecmp(str, "wildcard") == 0) {
		*mtype = dns_ssumatchtype_wildcard;
	} else if (strcasecmp(str, "self") == 0) {
		*mtype = dns_ssumatchtype_self;
	} else if (strcasecmp(str, "selfsub") == 0) {
		*mtype = dns_ssumatchtype_selfsub;
	} else if (strcasecmp(str, "selfwild") == 0) {
		*mtype = dns_ssumatchtype_selfwild;
	} else if (strcasecmp(str, "ms-self") == 0) {
		*mtype = dns_ssumatchtype_selfms;
	} else if (strcasecmp(str, "ms-selfsub") == 0) {
		*mtype = dns_ssumatchtype_selfsubms;
	} else if (strcasecmp(str, "krb5-self") == 0) {
		*mtype = dns_ssumatchtype_selfkrb5;
	} else if (strcasecmp(str, "krb5-selfsub") == 0) {
		*mtype = dns_ssumatchtype_selfsubkrb5;
	} else if (strcasecmp(str, "ms-subdomain") == 0) {
		*mtype = dns_ssumatchtype_subdomainms;
	} else if (strcasecmp(str, "ms-subdomain-self-rhs") == 0) {
		*mtype = dns_ssumatchtype_subdomainselfmsrhs;
	} else if (strcasecmp(str, "krb5-subdomain") == 0) {
		*mtype = dns_ssumatchtype_subdomainkrb5;
	} else if (strcasecmp(str, "krb5-subdomain-self-rhs") == 0) {
		*mtype = dns_ssumatchtype_subdomainselfkrb5rhs;
	} else if (strcasecmp(str, "tcp-self") == 0) {
		*mtype = dns_ssumatchtype_tcpself;
	} else if (strcasecmp(str, "6to4-self") == 0) {
		*mtype = dns_ssumatchtype_6to4self;
	} else if (strcasecmp(str, "zonesub") == 0) {
		*mtype = dns_ssumatchtype_subdomain;
	} else if (strcasecmp(str, "external") == 0) {
		*mtype = dns_ssumatchtype_external;
	} else {
		return ISC_R_NOTFOUND;
	}
	return ISC_R_SUCCESS;
}
