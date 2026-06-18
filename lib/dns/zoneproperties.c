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

#include <isc/async.h>	/* WMM: remove include */
#include <isc/random.h> /* WMM: remove include */

#include <dns/kasp.h>
#include <dns/peer.h>
#include <dns/request.h>
#include <dns/ssu.h>
#include <dns/stats.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/zoneproperties.h>

#include "zone_p.h"

static void
default_journal(dns_zone_t *zone);
static void
zone_namerd_tostr(dns_zone_t *zone, char *buf, size_t length);
static void
zone_name_tostr(dns_zone_t *zone, char *buf, size_t length);
static void
zone_rdclass_tostr(dns_zone_t *zone, char *buf, size_t length);

static void
free_rad_rcu(struct rcu_head *rcu_head) {
	dns_rad_t *rad = caa_container_of(rcu_head, dns_rad_t, rcu_head);
	dns_fixedname_invalidate(&rad->fname);

	isc_mem_putanddetach(&rad->mctx, rad, sizeof(*rad));
}

/*
 *	Single shot.
 */
void
dns_zone_setclass(dns_zone_t *zone, dns_rdataclass_t rdclass) {
	char namebuf[1024];

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(rdclass != dns_rdataclass_none);

	/*
	 * Test and set.
	 */
	LOCK_ZONE(zone);
	INSIST(zone != zone->raw);
	REQUIRE(zone->rdclass == dns_rdataclass_none ||
		zone->rdclass == rdclass);
	zone->rdclass = rdclass;

	if (zone->strnamerd != NULL) {
		isc_mem_free(zone->mctx, zone->strnamerd);
	}
	if (zone->strrdclass != NULL) {
		isc_mem_free(zone->mctx, zone->strrdclass);
	}

	zone_namerd_tostr(zone, namebuf, sizeof namebuf);
	zone->strnamerd = isc_mem_strdup(zone->mctx, namebuf);
	zone_rdclass_tostr(zone, namebuf, sizeof namebuf);
	zone->strrdclass = isc_mem_strdup(zone->mctx, namebuf);

	if (dns__zone_inline_secure(zone)) {
		dns_zone_setclass(zone->raw, rdclass);
	}
	UNLOCK_ZONE(zone);
}

dns_rdataclass_t
dns_zone_getclass(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->rdclass;
}

void
dns_zone_setnotifytype(dns_zone_t *zone, dns_rdatatype_t type,
		       dns_notifytype_t notifytype) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	switch (type) {
	case dns_rdatatype_soa:
		zone->notifysoa.notifytype = notifytype;
		break;
	case dns_rdatatype_cds:
		INSIST(notifytype == dns_notifytype_no ||
		       notifytype == dns_notifytype_yes);
		zone->notifycds.notifytype = notifytype;
		break;
	default:
		UNREACHABLE();
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_setcheckdstype(dns_zone_t *zone, dns_checkdstype_t checkdstype) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	zone->checkdstype = checkdstype;
	UNLOCK_ZONE(zone);
}

/*
 *	Single shot.
 */
void
dns_zone_settype(dns_zone_t *zone, dns_zonetype_t type) {
	char namebuf[1024];

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(type != dns_zone_none);

	/*
	 * Test and set.
	 */
	LOCK_ZONE(zone);
	REQUIRE(zone->type == dns_zone_none || zone->type == type);
	zone->type = type;

	if (zone->strnamerd != NULL) {
		isc_mem_free(zone->mctx, zone->strnamerd);
	}

	zone_namerd_tostr(zone, namebuf, sizeof namebuf);
	zone->strnamerd = isc_mem_strdup(zone->mctx, namebuf);
	UNLOCK_ZONE(zone);
}

void
dns_zone_getdbtype(dns_zone_t *zone, char ***argv, isc_mem_t *mctx) {
	size_t size = 0;
	unsigned int i;
	void *mem;
	char **tmp, *tmp2, *base;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(argv != NULL && *argv == NULL);

	LOCK_ZONE(zone);
	size = ISC_CHECKED_MUL(zone->db_argc + 1, sizeof(char *));
	for (i = 0; i < zone->db_argc; i++) {
		size += strlen(zone->db_argv[i]) + 1;
	}
	mem = isc_mem_allocate(mctx, size);
	{
		tmp = mem;
		tmp2 = mem;
		base = mem;
		tmp2 += ISC_CHECKED_MUL(zone->db_argc + 1, sizeof(char *));
		for (i = 0; i < zone->db_argc; i++) {
			*tmp++ = tmp2;
			strlcpy(tmp2, zone->db_argv[i], size - (tmp2 - base));
			tmp2 += strlen(tmp2) + 1;
		}
		*tmp = NULL;
	}
	UNLOCK_ZONE(zone);
	*argv = mem;
}

void
dns_zone_setdbtype(dns_zone_t *zone, unsigned int dbargc,
		   const char *const *dbargv) {
	char **argv = NULL;
	unsigned int i;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(dbargc >= 1);
	REQUIRE(dbargv != NULL);

	LOCK_ZONE(zone);

	/* Set up a new database argument list. */
	argv = isc_mem_cget(zone->mctx, dbargc, sizeof(*argv));
	for (i = 0; i < dbargc; i++) {
		argv[i] = NULL;
	}
	for (i = 0; i < dbargc; i++) {
		argv[i] = isc_mem_strdup(zone->mctx, dbargv[i]);
	}

	/* Free the old list. */
	dns__zone_freedbargs(zone);

	zone->db_argc = dbargc;
	zone->db_argv = argv;

	UNLOCK_ZONE(zone);
}

void
dns_zone_setview(dns_zone_t *zone, dns_view_t *view) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	dns__zone_setview_helper(zone, view);
	UNLOCK_ZONE(zone);
}

dns_view_t *
dns_zone_getview(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->view;
}

void
dns_zone_setorigin(dns_zone_t *zone, const dns_name_t *origin) {
	char namebuf[1024];

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(origin != NULL);

	LOCK_ZONE(zone);
	INSIST(zone != zone->raw);
	if (dns_name_dynamic(&zone->origin)) {
		dns_name_free(&zone->origin, zone->mctx);
		dns_name_init(&zone->origin);
	}
	dns_name_dup(origin, zone->mctx, &zone->origin);

	if (zone->strnamerd != NULL) {
		isc_mem_free(zone->mctx, zone->strnamerd);
	}
	if (zone->strname != NULL) {
		isc_mem_free(zone->mctx, zone->strname);
	}

	zone_namerd_tostr(zone, namebuf, sizeof namebuf);
	zone->strnamerd = isc_mem_strdup(zone->mctx, namebuf);
	zone_name_tostr(zone, namebuf, sizeof namebuf);
	zone->strname = isc_mem_strdup(zone->mctx, namebuf);

	if (dns__zone_inline_secure(zone)) {
		dns_zone_setorigin(zone->raw, origin);
	}
	UNLOCK_ZONE(zone);
}

static void
setstring(dns_zone_t *zone, char **field, const char *value) {
	char *copy;

	if (value != NULL) {
		copy = isc_mem_strdup(zone->mctx, value);
	} else {
		copy = NULL;
	}

	if (*field != NULL) {
		isc_mem_free(zone->mctx, *field);
	}

	*field = copy;
}

typedef struct foundtoken foundtoken_t;
typedef struct token_names token_names_t;
typedef isc_result_t (*tokenparse_t)(const token_names_t *names,
				     const foundtoken_t *token,
				     isc_buffer_t *b);

struct foundtoken {
	const char *pos;
	size_t len;
	tokenparse_t parse;
};

struct token_names {
	dns_name_t *zonename;
	const char *viewname;
	const char *typename;
};

static int
foundtoken_order(const void *a, const void *b) {
	/* sort char pointers in order of which occurs first in memory */
	return ((foundtoken_t *)a)->pos - ((foundtoken_t *)b)->pos;
}

static isc_result_t
putmem(isc_buffer_t *b, const char *base, size_t length) {
	size_t space = isc_buffer_availablelength(b) - 1;
	if (space < length) {
		isc_buffer_putmem(b, (const unsigned char *)base, space);
		return ISC_R_NOSPACE;
	}

	isc_buffer_putmem(b, (const unsigned char *)base, length);
	return ISC_R_SUCCESS;
}

static isc_result_t
tokenparse_type(const token_names_t *names, const foundtoken_t *token,
		isc_buffer_t *b) {
	UNUSED(token);

	return putmem(b, names->typename, strlen(names->typename));
}

static isc_result_t
tokenparse_name(const token_names_t *names,
		const foundtoken_t *token ISC_ATTR_UNUSED, isc_buffer_t *b) {
	char name[DNS_NAME_FORMATSIZE];

	dns_name_format(names->zonename, name, sizeof(name));
	return putmem(b, name, strlen(name));
}

static isc_result_t
tokenparse_view(const token_names_t *names, const foundtoken_t *token,
		isc_buffer_t *b) {
	UNUSED(token);

	return putmem(b, names->viewname, strlen(names->viewname));
}

static isc_result_t
tokenparse_char(const token_names_t *names, const foundtoken_t *token,
		isc_buffer_t *b) {
	char name[DNS_NAME_FORMATSIZE];
	size_t chartokidx;
	char c;

	dns_name_format(names->zonename, name, sizeof(name));

	chartokidx = token->pos[token->len - 1] - '1';
	INSIST(chartokidx <= 2);
	if (chartokidx < strlen(name)) {
		c = name[chartokidx];
	} else {
		c = '.';
	}
	return putmem(b, &c, 1);
}

static isc_result_t
tokenparse_label(const token_names_t *names, const foundtoken_t *token,
		 isc_buffer_t *b) {
	isc_result_t result;
	char buf[DNS_NAME_FORMATSIZE];
	dns_fixedname_t ft;
	dns_name_t *target = dns_fixedname_initname(&ft);
	unsigned int labels;
	char labeltokidx;
	int ilabel = -1;

	dns_name_copy(dns_rootname, target);
	labels = dns_name_countlabels(names->zonename);

	labeltokidx = isc_ascii_tolower(token->pos[token->len - 1]);
	if (token->len == 2) {
		/*
		 * %z, %y, %x pattern
		 */
		INSIST(labeltokidx >= 'x' && labeltokidx <= 'z');
	} else {
		/*
		 * $label1, $label2, $label3 pattern
		 */
		INSIST(labeltokidx >= '1' && labeltokidx <= '3');
	}

	if (labeltokidx == '1' || labeltokidx == 'z') {
		ilabel = labels - 1;
	} else if (labeltokidx == '2' || labeltokidx == 'y') {
		ilabel = labels - 2;
	} else if (labeltokidx == '3' || labeltokidx == 'x') {
		ilabel = labels - 3;
	}

	if (ilabel >= 0) {
		dns_name_getlabelsequence(names->zonename, ilabel, 1, target);
	}
	dns_name_format(target, buf, sizeof(buf));
	result = putmem(b, buf, strlen(buf));

	return result;
}

typedef struct {
	const char *name;
	tokenparse_t parse;
} token_t;
static const token_t tokens[] = {
	{ "$type", tokenparse_type },	 { "$name", tokenparse_name },
	{ "$view", tokenparse_view },	 { "$char1", tokenparse_char },
	{ "$char2", tokenparse_char },	 { "$char3", tokenparse_char },
	{ "$label1", tokenparse_label }, { "$label2", tokenparse_label },
	{ "$label3", tokenparse_label }, { "%t", tokenparse_type },
	{ "%s", tokenparse_name },	 { "%v", tokenparse_view },
	{ "%1", tokenparse_char },	 { "%2", tokenparse_char },
	{ "%3", tokenparse_char },	 { "%z", tokenparse_label },
	{ "%y", tokenparse_label },	 { "%x", tokenparse_label }
};

/*
 * Set the masterfile field, expanding:
 *
 *    - $name or "%s" to the zone name
 *    - $type or "%t" to the zone type
 *    - $view or "%v" to the view name.
 *    - $char1 or "%1" to the first character of the zone name
 *    - $char2 or "%2" to the second character of the zone name (or a dot if
 *      there is no second character)
 *    - $char3 or "%3" to the third character of the zone name (or a dot if
 *      there is no third character)
 *    - $label1 or "%z" to the toplevel domain of the zone (or a dot if it is
 *      the TLD)
 *    - $label2 or "%y" to the next label under the toplevel domain (or a dot if
 *      there is no next label)
 *    - $label2 or "%x" to the next-next label under the toplevel domain (or a
 *      dot if there is no next-next label)
 *
 * Cap the length at PATH_MAX.
 */
void
dns_zone_expandzonefile(isc_buffer_t *b, const char *filename,
			const dns_name_t *zonename, const char *viewname,
			const char *typename) {
	isc_result_t result;
	foundtoken_t founds[ARRAY_SIZE(tokens)];
	dns_fixedname_t fz;
	size_t tags = 0;
	token_names_t names = { .zonename = dns_fixedname_initname(&fz),
				.viewname = viewname,
				.typename = typename };

	REQUIRE(zonename != NULL);
	REQUIRE(filename != NULL);
	REQUIRE(typename != NULL);

	if (viewname == NULL) {
		names.viewname = "";
	}

	/* Normalize the name by converting to lower case */
	result = dns_name_downcase(zonename, names.zonename);
	INSIST(result == ISC_R_SUCCESS);

	for (size_t i = 0; i < ARRAY_SIZE(tokens); i++) {
		const token_t *token = &tokens[i];
		const char *p = strcasestr(filename, token->name);

		if (p != NULL) {
			founds[tags++] =
				(foundtoken_t){ .pos = p,
						.len = strlen(token->name),
						.parse = token->parse };
		}
	}

	if (tags == 0) {
		putmem(b, filename, strlen(filename));
		goto cleanup;
	}

	/* sort the tag offsets in order of occurrence */
	qsort(founds, tags, sizeof(foundtoken_t), foundtoken_order);

	const char *p = filename;
	for (size_t i = 0; i < tags; i++) {
		foundtoken_t *token = &founds[i];

		CHECK(putmem(b, p, token->pos - p));

		p = token->pos;
		INSIST(p != NULL);
		CHECK(token->parse(&names, token, b));

		/* Advance the input pointer past the token */
		p += founds[i].len;
	}

	const char *end = filename + strlen(filename);
	putmem(b, p, end - p);

cleanup:
	isc_buffer_putuint8(b, 0);
}

static void
setfilename(dns_zone_t *zone, char **field, const char *value) {
	char filename[PATH_MAX];
	isc_buffer_t b;

	if (value == NULL) {
		*field = NULL;
		return;
	}

	isc_buffer_init(&b, filename, sizeof(filename));
	dns_zone_expandzonefile(&b, value, &zone->origin,
				zone->view != NULL ? zone->view->name : NULL,
				dns_zonetype_name(zone->type));
	setstring(zone, field, filename);
}

void
dns_zone_setfile(dns_zone_t *zone, const char *file, const char *initial_file,
		 dns_masterformat_t format, const dns_master_style_t *style) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(zone->stream == NULL);

	LOCK_ZONE(zone);
	setfilename(zone, &zone->masterfile, file);
	setstring(zone, &zone->initfile, initial_file);
	zone->masterformat = format;
	if (format == dns_masterformat_text) {
		zone->masterstyle = style;
	}
	default_journal(zone);
	UNLOCK_ZONE(zone);
}

const char *
dns_zone_getfile(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->masterfile;
}

void
dns_zone_setstream(dns_zone_t *zone, const FILE *stream,
		   dns_masterformat_t format, const dns_master_style_t *style) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(stream != NULL);
	REQUIRE(zone->masterfile == NULL);

	LOCK_ZONE(zone);
	zone->stream = stream;
	zone->masterformat = format;
	if (format == dns_masterformat_text) {
		zone->masterstyle = style;
	}
	default_journal(zone);
	UNLOCK_ZONE(zone);
}

dns_ttl_t
dns_zone_getmaxttl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->maxttl;
}

void
dns_zone_setmaxttl(dns_zone_t *zone, dns_ttl_t maxttl) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (maxttl != 0) {
		DNS_ZONE_SETOPTION(zone, DNS_ZONEOPT_CHECKTTL);
	} else {
		DNS_ZONE_CLROPTION(zone, DNS_ZONEOPT_CHECKTTL);
	}
	zone->maxttl = maxttl;
	UNLOCK_ZONE(zone);

	return;
}

static void
default_journal(dns_zone_t *zone) {
	char *journal;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(LOCKED_ZONE(zone));

	if (zone->masterfile != NULL) {
		/* Calculate string length including '\0'. */
		int len = strlen(zone->masterfile) + sizeof(".jnl");
		journal = isc_mem_allocate(zone->mctx, len);
		strlcpy(journal, zone->masterfile, len);
		strlcat(journal, ".jnl", len);
	} else {
		journal = NULL;
	}
	setstring(zone, &zone->journal, journal);
	if (journal != NULL) {
		isc_mem_free(zone->mctx, journal);
	}
}

void
dns_zone_setjournal(dns_zone_t *zone, const char *myjournal) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	setstring(zone, &zone->journal, myjournal);
	UNLOCK_ZONE(zone);
}

char *
dns_zone_getjournal(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->journal;
}

isc_mem_t *
dns_zone_getmctx(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->mctx;
}

dns_zonemgr_t *
dns_zone_getmgr(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->zmgr;
}

void
dns_zone_setkasp(dns_zone_t *zone, dns_kasp_t *kasp) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (zone->kasp != NULL) {
		dns_kasp_detach(&zone->kasp);
	}
	if (kasp != NULL) {
		dns_kasp_attach(kasp, &zone->kasp);
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_setdefaultkasp(dns_zone_t *zone, dns_kasp_t *kasp) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (zone->defaultkasp != NULL) {
		dns_kasp_detach(&zone->defaultkasp);
	}
	if (kasp != NULL) {
		dns_kasp_attach(kasp, &zone->defaultkasp);
	}
	UNLOCK_ZONE(zone);
}

dns_kasp_t *
dns_zone_getkasp(dns_zone_t *zone) {
	dns_kasp_t *kasp = NULL;

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (dns__zone_inline_raw(zone) && zone->secure != NULL) {
		kasp = zone->secure->kasp;
	} else {
		kasp = zone->kasp;
	}
	UNLOCK_ZONE(zone);

	return kasp;
}

void
dns_zone_setxfrsource4(dns_zone_t *zone, const isc_sockaddr_t *xfrsource) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(xfrsource != NULL);

	LOCK_ZONE(zone);
	zone->xfrsource4 = *xfrsource;
	UNLOCK_ZONE(zone);
}

void
dns_zone_getxfrsource4(dns_zone_t *zone, isc_sockaddr_t *xfrsource) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(xfrsource != NULL);

	LOCK_ZONE(zone);
	*xfrsource = zone->xfrsource4;
	UNLOCK_ZONE(zone);
}

void
dns_zone_setxfrsource6(dns_zone_t *zone, const isc_sockaddr_t *xfrsource) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(xfrsource != NULL);

	LOCK_ZONE(zone);
	zone->xfrsource6 = *xfrsource;
	UNLOCK_ZONE(zone);
}

void
dns_zone_getxfrsource6(dns_zone_t *zone, isc_sockaddr_t *xfrsource) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(xfrsource != NULL);

	LOCK_ZONE(zone);
	*xfrsource = zone->xfrsource6;
	UNLOCK_ZONE(zone);
}

void
dns_zone_setparentalsrc4(dns_zone_t *zone, const isc_sockaddr_t *parentalsrc) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(parentalsrc != NULL);

	LOCK_ZONE(zone);
	zone->parentalsrc4 = *parentalsrc;
	UNLOCK_ZONE(zone);
}

void
dns_zone_getparentalsrc4(dns_zone_t *zone, isc_sockaddr_t *parentalsrc) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(parentalsrc != NULL);

	LOCK_ZONE(zone);
	*parentalsrc = zone->parentalsrc4;
	UNLOCK_ZONE(zone);
}

void
dns_zone_setparentalsrc6(dns_zone_t *zone, const isc_sockaddr_t *parentalsrc) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	zone->parentalsrc6 = *parentalsrc;
	UNLOCK_ZONE(zone);
}

void
dns_zone_getparentalsrc6(dns_zone_t *zone, isc_sockaddr_t *parentalsrc) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(parentalsrc != NULL);

	LOCK_ZONE(zone);
	*parentalsrc = zone->parentalsrc6;
	UNLOCK_ZONE(zone);
}

void
dns_zone_setnotifysrc4(dns_zone_t *zone, dns_rdatatype_t type,
		       const isc_sockaddr_t *notifysrc) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(notifysrc != NULL);

	LOCK_ZONE(zone);
	switch (type) {
	case dns_rdatatype_soa:
		zone->notifysoa.notifysrc4 = *notifysrc;
		break;
	case dns_rdatatype_cds:
		zone->notifycds.notifysrc4 = *notifysrc;
		break;
	default:
		UNREACHABLE();
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_setnotifysrc6(dns_zone_t *zone, dns_rdatatype_t type,
		       const isc_sockaddr_t *notifysrc) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(notifysrc != NULL);

	LOCK_ZONE(zone);
	switch (type) {
	case dns_rdatatype_soa:
		zone->notifysoa.notifysrc6 = *notifysrc;
		break;
	case dns_rdatatype_cds:
		zone->notifycds.notifysrc6 = *notifysrc;
		break;
	default:
		UNREACHABLE();
	}
	UNLOCK_ZONE(zone);
}

static bool
has_pf(isc_sockaddr_t *addresses, size_t count, int pf) {
	for (size_t i = 0; i < count; i++) {
		if (isc_sockaddr_pf(&addresses[i]) == pf) {
			return true;
		}
	}
	return false;
}

static void
report_no_active_addresses(dns_zone_t *zone, isc_sockaddr_t *addresses,
			   size_t count, const char *what) {
	if (isc_net_probeipv4() == ISC_R_DISABLED) {
		if (!has_pf(addresses, count, AF_INET6)) {
			dns_zone_log(zone, ISC_LOG_NOTICE,
				     "IPv4 disabled and no IPv6 %s", what);
		}
	} else if (isc_net_probeipv6() == ISC_R_DISABLED) {
		if (!has_pf(addresses, count, AF_INET)) {
			dns_zone_log(zone, ISC_LOG_NOTICE,
				     "IPv6 disabled and no IPv4 %s", what);
		}
	}
}

static void
setremote(dns_zone_t *zone, dns_remote_t *remote, const char *remotestr,
	  isc_sockaddr_t *addresses, isc_sockaddr_t *sources,
	  dns_name_t **keynames, dns_name_t **tlsnames, bool refresh,
	  bool report, uint32_t count) {
	dns_remote_t newremote;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(DNS_REMOTE_VALID(remote));

	newremote.magic = DNS_REMOTE_MAGIC;
	newremote.addresses = addresses;
	newremote.sources = sources;
	newremote.keynames = keynames;
	newremote.tlsnames = tlsnames;
	newremote.addrcnt = count;

	if (dns_remote_equal(remote, &newremote)) {
		return;
	}

	/*
	 * The refresh code assumes that 'servers' wouldn't change under it.
	 * If it will change then kill off any current refresh in progress
	 * and update the primaries info.  If it won't change then we can just
	 * unlock and exit.
	 */
	if (zone->request != NULL && refresh) {
		dns_request_cancel(zone->request);
	}

	dns_remote_clear(remote);

	/*
	 * If count == 0, don't allocate any space for servers.
	 */
	if (count == 0) {
		return;
	}

	/*
	 * Now set up the address and key lists.
	 */
	if (report) {
		report_no_active_addresses(zone, addresses, count, remotestr);
	}

	dns_remote_init(remote, count, addresses, sources, keynames, tlsnames,
			true, zone->mctx);
}

void
dns_zone_setalsonotify(dns_zone_t *zone, isc_sockaddr_t *addresses,
		       isc_sockaddr_t *sources, dns_name_t **keynames,
		       dns_name_t **tlsnames, uint32_t count) {
	bool refresh = false;
	bool report = false;

	LOCK_ZONE(zone);
	setremote(zone, &zone->alsonotify, "also-notify", addresses, sources,
		  keynames, tlsnames, refresh, report, count);
	UNLOCK_ZONE(zone);
}

void
dns_zone_setprimaries(dns_zone_t *zone, isc_sockaddr_t *addresses,
		      isc_sockaddr_t *sources, dns_name_t **keynames,
		      dns_name_t **tlsnames, uint32_t count) {
	bool refresh = true;
	bool report = true;

	LOCK_ZONE(zone);
	setremote(zone, &zone->primaries, "primaries", addresses, sources,
		  keynames, tlsnames, refresh, report, count);
	DNS_ZONE_CLRFLAG(zone, DNS_ZONEFLG_NOPRIMARIES);
	UNLOCK_ZONE(zone);
}

void
dns_zone_setparentals(dns_zone_t *zone, isc_sockaddr_t *addresses,
		      isc_sockaddr_t *sources, dns_name_t **keynames,
		      dns_name_t **tlsnames, uint32_t count) {
	bool refresh = false;
	bool report = true;

	LOCK_ZONE(zone);
	setremote(zone, &zone->parentals, "parental-agents", addresses, sources,
		  keynames, tlsnames, refresh, report, count);
	UNLOCK_ZONE(zone);
}

void
dns_zone_setcdsendpoints(dns_zone_t *zone, isc_sockaddr_t *addresses,
			 isc_sockaddr_t *sources, dns_name_t **keynames,
			 dns_name_t **tlsnames, uint32_t count) {
	bool refresh = false;
	bool report = false;

	LOCK_ZONE(zone);
	setremote(zone, &zone->cds_endpoints, "cds-endpoints", addresses,
		  sources, keynames, tlsnames, refresh, report, count);
	UNLOCK_ZONE(zone);
}

isc_result_t
dns_zone_getdb(dns_zone_t *zone, dns_db_t **dpb) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(DNS_ZONE_VALID(zone));

	ZONEDB_LOCK(&zone->dblock, isc_rwlocktype_read);
	if (zone->db == NULL) {
		result = DNS_R_NOTLOADED;
	} else {
		dns_db_attach(zone->db, dpb);
	}
	ZONEDB_UNLOCK(&zone->dblock, isc_rwlocktype_read);

	return result;
}

void
dns_zone_setdb(dns_zone_t *zone, dns_db_t *db) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(zone->type == dns_zone_staticstub);

	ZONEDB_LOCK(&zone->dblock, isc_rwlocktype_write);
	REQUIRE(zone->db == NULL);
	dns_db_attach(db, &zone->db);
	ZONEDB_UNLOCK(&zone->dblock, isc_rwlocktype_write);
}

void
dns_zone_setminrefreshtime(dns_zone_t *zone, uint32_t val) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(val > 0);

	zone->minrefresh = val;
}

void
dns_zone_setmaxrefreshtime(dns_zone_t *zone, uint32_t val) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(val > 0);

	zone->maxrefresh = val;
}

void
dns_zone_setminretrytime(dns_zone_t *zone, uint32_t val) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(val > 0);

	zone->minretry = val;
}

void
dns_zone_setmaxretrytime(dns_zone_t *zone, uint32_t val) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(val > 0);

	zone->maxretry = val;
}

uint32_t
dns_zone_getmaxrecords(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->maxrecords;
}

void
dns_zone_setmaxrecords(dns_zone_t *zone, uint32_t val) {
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->maxrecords = val;
}

void
dns_zone_setmaxrrperset(dns_zone_t *zone, uint32_t val) {
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->maxrrperset = val;
	if (zone->db != NULL) {
		dns_db_setmaxrrperset(zone->db, val);
	}
}

void
dns_zone_setmaxtypepername(dns_zone_t *zone, uint32_t val) {
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->maxtypepername = val;
	if (zone->db != NULL) {
		dns_db_setmaxtypepername(zone->db, val);
	}
}

void
dns_zone_setnotifyacl(dns_zone_t *zone, dns_acl_t *acl) {
	REQUIRE(DNS_ZONE_VALID(zone));

	dns_zone_clearnotifyacl(zone);

	LOCK_ZONE(zone);
	dns_acl_attach(acl, &zone->notifysoa.notify_acl);
	dns_acl_attach(acl, &zone->notifycds.notify_acl);
	UNLOCK_ZONE(zone);
}

void
dns_zone_setqueryacl(dns_zone_t *zone, dns_acl_t *acl) {
	REQUIRE(DNS_ZONE_VALID(zone));

	dns_zone_clearqueryacl(zone);

	LOCK_ZONE(zone);
	dns_acl_attach(acl, &zone->query_acl);
	UNLOCK_ZONE(zone);
}

void
dns_zone_setqueryonacl(dns_zone_t *zone, dns_acl_t *acl) {
	REQUIRE(DNS_ZONE_VALID(zone));

	dns_zone_clearqueryonacl(zone);

	LOCK_ZONE(zone);
	dns_acl_attach(acl, &zone->queryon_acl);
	UNLOCK_ZONE(zone);
}

void
dns_zone_setupdateacl(dns_zone_t *zone, dns_acl_t *acl) {
	REQUIRE(DNS_ZONE_VALID(zone));

	dns_zone_clearupdateacl(zone);

	LOCK_ZONE(zone);
	dns_acl_attach(acl, &zone->update_acl);
	UNLOCK_ZONE(zone);
}

void
dns_zone_setforwardacl(dns_zone_t *zone, dns_acl_t *acl) {
	REQUIRE(DNS_ZONE_VALID(zone));

	dns_zone_clearforwardacl(zone);

	LOCK_ZONE(zone);
	dns_acl_attach(acl, &zone->forward_acl);
	UNLOCK_ZONE(zone);
}

void
dns_zone_setxfracl(dns_zone_t *zone, dns_acl_t *acl) {
	REQUIRE(DNS_ZONE_VALID(zone));

	dns_zone_clearxfracl(zone);

	LOCK_ZONE(zone);
	dns_acl_attach(acl, &zone->xfr_acl);
	UNLOCK_ZONE(zone);
}

dns_acl_t *
dns_zone_getqueryacl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->query_acl;
}

dns_acl_t *
dns_zone_getqueryonacl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->queryon_acl;
}

dns_acl_t *
dns_zone_getupdateacl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->update_acl;
}

dns_acl_t *
dns_zone_getforwardacl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->forward_acl;
}

dns_acl_t *
dns_zone_getxfracl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->xfr_acl;
}

void
dns_zone_clearupdateacl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (zone->update_acl != NULL) {
		dns_acl_detach(&zone->update_acl);
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_clearforwardacl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (zone->forward_acl != NULL) {
		dns_acl_detach(&zone->forward_acl);
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_clearnotifyacl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (zone->notifysoa.notify_acl != NULL) {
		dns_acl_detach(&zone->notifysoa.notify_acl);
	}
	if (zone->notifycds.notify_acl != NULL) {
		dns_acl_detach(&zone->notifycds.notify_acl);
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_clearqueryacl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (zone->query_acl != NULL) {
		dns_acl_detach(&zone->query_acl);
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_clearqueryonacl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (zone->queryon_acl != NULL) {
		dns_acl_detach(&zone->queryon_acl);
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_clearxfracl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (zone->xfr_acl != NULL) {
		dns_acl_detach(&zone->xfr_acl);
	}
	UNLOCK_ZONE(zone);
}

bool
dns_zone_getupdatedisabled(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->update_disabled;
}

void
dns_zone_setupdatedisabled(dns_zone_t *zone, bool state) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->update_disabled = state;
}

bool
dns_zone_getzeronosoattl(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->zero_no_soa_ttl;
}

void
dns_zone_setzeronosoattl(dns_zone_t *zone, bool state) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->zero_no_soa_ttl = state;
}

void
dns_zone_setchecknames(dns_zone_t *zone, dns_severity_t severity) {
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->check_names = severity;
}

dns_severity_t
dns_zone_getchecknames(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->check_names;
}

void
dns_zone_setjournalsize(dns_zone_t *zone, int32_t size) {
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->journalsize = size;
}

int32_t
dns_zone_getjournalsize(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->journalsize;
}

static void
zone_namerd_tostr(dns_zone_t *zone, char *buf, size_t length) {
	isc_result_t result = ISC_R_FAILURE;
	isc_buffer_t buffer;

	REQUIRE(buf != NULL);
	REQUIRE(length > 1U);

	/*
	 * Leave space for terminating '\0'.
	 */
	isc_buffer_init(&buffer, buf, (unsigned int)length - 1);
	if (zone->type != dns_zone_redirect && zone->type != dns_zone_key) {
		if (dns_name_dynamic(&zone->origin)) {
			result = dns_name_totext(
				&zone->origin, DNS_NAME_OMITFINALDOT, &buffer);
		}
		if (result != ISC_R_SUCCESS &&
		    isc_buffer_availablelength(&buffer) >=
			    (sizeof("<UNKNOWN>") - 1))
		{
			isc_buffer_putstr(&buffer, "<UNKNOWN>");
		}

		if (isc_buffer_availablelength(&buffer) > 0) {
			isc_buffer_putstr(&buffer, "/");
		}
		(void)dns_rdataclass_totext(zone->rdclass, &buffer);
	}

	if (zone->view != NULL && strcmp(zone->view->name, "_bind") != 0 &&
	    strcmp(zone->view->name, "_default") != 0 &&
	    strlen(zone->view->name) < isc_buffer_availablelength(&buffer))
	{
		isc_buffer_putstr(&buffer, "/");
		isc_buffer_putstr(&buffer, zone->view->name);
	}
	if (dns__zone_inline_secure(zone) &&
	    9U < isc_buffer_availablelength(&buffer))
	{
		isc_buffer_putstr(&buffer, " (signed)");
	}
	if (dns__zone_inline_raw(zone) &&
	    11U < isc_buffer_availablelength(&buffer))
	{
		isc_buffer_putstr(&buffer, " (unsigned)");
	}

	buf[isc_buffer_usedlength(&buffer)] = '\0';
}

static void
zone_name_tostr(dns_zone_t *zone, char *buf, size_t length) {
	isc_result_t result = ISC_R_FAILURE;
	isc_buffer_t buffer;

	REQUIRE(buf != NULL);
	REQUIRE(length > 1U);

	/*
	 * Leave space for terminating '\0'.
	 */
	isc_buffer_init(&buffer, buf, (unsigned int)length - 1);
	if (dns_name_dynamic(&zone->origin)) {
		result = dns_name_totext(&zone->origin, DNS_NAME_OMITFINALDOT,
					 &buffer);
	}
	if (result != ISC_R_SUCCESS &&
	    isc_buffer_availablelength(&buffer) >= (sizeof("<UNKNOWN>") - 1))
	{
		isc_buffer_putstr(&buffer, "<UNKNOWN>");
	}

	buf[isc_buffer_usedlength(&buffer)] = '\0';
}

static void
zone_rdclass_tostr(dns_zone_t *zone, char *buf, size_t length) {
	isc_buffer_t buffer;

	REQUIRE(buf != NULL);
	REQUIRE(length > 1U);

	/*
	 * Leave space for terminating '\0'.
	 */
	isc_buffer_init(&buffer, buf, (unsigned int)length - 1);
	(void)dns_rdataclass_totext(zone->rdclass, &buffer);

	buf[isc_buffer_usedlength(&buffer)] = '\0';
}

void
dns_zone_name(dns_zone_t *zone, char *buf, size_t length) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(buf != NULL);

	LOCK_ZONE(zone);
	zone_namerd_tostr(zone, buf, length);
	UNLOCK_ZONE(zone);
}

void
dns_zone_nameonly(dns_zone_t *zone, char *buf, size_t length) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(buf != NULL);
	zone_name_tostr(zone, buf, length);
}

void
dns_zone_setminxfrratein(dns_zone_t *zone, uint32_t bytes, uint32_t seconds) {
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->minxfrratebytesin = bytes;
	zone->minxfrratesecondsin = seconds;
}

uint32_t
dns_zone_getminxfrratebytesin(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->minxfrratebytesin;
}

uint32_t
dns_zone_getminxfrratesecondsin(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->minxfrratesecondsin;
}

void
dns_zone_setmaxxfrin(dns_zone_t *zone, uint32_t maxxfrin) {
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->maxxfrin = maxxfrin;
}

uint32_t
dns_zone_getmaxxfrin(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->maxxfrin;
}

void
dns_zone_setmaxxfrout(dns_zone_t *zone, uint32_t maxxfrout) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->maxxfrout = maxxfrout;
}

uint32_t
dns_zone_getmaxxfrout(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->maxxfrout;
}

dns_zonetype_t
dns_zone_gettype(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->type;
}

dns_name_t *
dns_zone_getorigin(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return &zone->origin;
}

void
dns_zone_setidlein(dns_zone_t *zone, uint32_t idlein) {
	REQUIRE(DNS_ZONE_VALID(zone));

	if (idlein == 0) {
		idlein = DNS_DEFAULT_IDLEIN;
	}
	zone->idlein = idlein;
}

uint32_t
dns_zone_getidlein(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->idlein;
}

void
dns_zone_setidleout(dns_zone_t *zone, uint32_t idleout) {
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->idleout = idleout;
}

uint32_t
dns_zone_getidleout(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->idleout;
}

void
dns_zone_getssutable(dns_zone_t *zone, dns_ssutable_t **table) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(table != NULL);
	REQUIRE(*table == NULL);

	LOCK_ZONE(zone);
	if (zone->ssutable != NULL) {
		dns_ssutable_attach(zone->ssutable, table);
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_setssutable(dns_zone_t *zone, dns_ssutable_t *table) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (zone->ssutable != NULL) {
		dns_ssutable_detach(&zone->ssutable);
	}
	if (table != NULL) {
		dns_ssutable_attach(table, &zone->ssutable);
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_setsigvalidityinterval(dns_zone_t *zone, uint32_t interval) {
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->sigvalidityinterval = interval;
}

uint32_t
dns_zone_getsigvalidityinterval(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->sigvalidityinterval;
}

void
dns_zone_setkeyvalidityinterval(dns_zone_t *zone, uint32_t interval) {
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->keyvalidityinterval = interval;
}

uint32_t
dns_zone_getkeyvalidityinterval(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->keyvalidityinterval;
}

void
dns_zone_setsigresigninginterval(dns_zone_t *zone, uint32_t interval) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	zone->sigresigninginterval = interval;
	dns__zone_set_resigntime(zone);
	if (zone->loop != NULL) {
		dns__zone_settimer(zone, isc_time_now());
	}
	UNLOCK_ZONE(zone);
}

uint32_t
dns_zone_getsigresigninginterval(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->sigresigninginterval;
}

void
dns_zone_getsourceaddr(dns_zone_t *zone, isc_sockaddr_t *sourceaddr) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(sourceaddr != NULL);

	LOCK_ZONE(zone);
	INSIST(dns_remote_count(&zone->primaries) > 0);
	*sourceaddr = zone->sourceaddr;
	UNLOCK_ZONE(zone);
}

isc_result_t
dns_zone_getprimaryaddr(dns_zone_t *zone, isc_sockaddr_t *primaryaddr) {
	isc_result_t result = ISC_R_NOMORE;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(primaryaddr != NULL);

	LOCK_ZONE(zone);
	INSIST(dns_remote_count(&zone->primaries) > 0);
	if (!dns_remote_done(&zone->primaries)) {
		*primaryaddr = dns_remote_curraddr(&zone->primaries);
		result = ISC_R_SUCCESS;
	}
	UNLOCK_ZONE(zone);

	return result;
}

isc_time_t
dns_zone_getxfrintime(dns_zone_t *zone) {
	isc_time_t xfrintime;

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	xfrintime = zone->xfrintime;
	UNLOCK_ZONE(zone);

	return xfrintime;
}

void
dns_zone_setstats(dns_zone_t *zone, isc_stats_t *stats) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(zone->stats == NULL);

	LOCK_ZONE(zone);
	zone->stats = NULL;
	isc_stats_attach(stats, &zone->stats);
	UNLOCK_ZONE(zone);
}

void
dns_zone_setrequeststats(dns_zone_t *zone, isc_stats_t *stats) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (zone->requeststats_on && stats == NULL) {
		zone->requeststats_on = false;
	} else if (!zone->requeststats_on && stats != NULL) {
		if (zone->requeststats == NULL) {
			isc_stats_attach(stats, &zone->requeststats);
		}
		zone->requeststats_on = true;
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_setrcvquerystats(dns_zone_t *zone, isc_statsmulti_t *stats) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (zone->requeststats_on && stats != NULL) {
		if (zone->rcvquerystats == NULL) {
			isc_statsmulti_attach(stats, &zone->rcvquerystats);
			zone->requeststats_on = true;
		}
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_setdnssecsignstats(dns_zone_t *zone, dns_stats_t *stats) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	if (stats != NULL && zone->dnssecsignstats == NULL) {
		dns_stats_attach(stats, &zone->dnssecsignstats);
	}
	UNLOCK_ZONE(zone);
}

dns_stats_t *
dns_zone_getdnssecsignstats(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->dnssecsignstats;
}

isc_stats_t *
dns_zone_getrequeststats(dns_zone_t *zone) {
	/*
	 * We don't lock zone for efficiency reason.  This is not catastrophic
	 * because requeststats must always be valid when requeststats_on is
	 * true.
	 * Some counters may be incremented while requeststats_on is becoming
	 * false, or some cannot be incremented just after the statistics are
	 * installed, but it shouldn't matter much in practice.
	 */
	if (zone->requeststats_on) {
		return zone->requeststats;
	} else {
		return NULL;
	}
}

/*
 * Return the received query stats bucket
 * see note from dns_zone_getrequeststats()
 */
isc_statsmulti_t *
dns_zone_getrcvquerystats(dns_zone_t *zone) {
	if (zone->requeststats_on) {
		return zone->rcvquerystats;
	} else {
		return NULL;
	}
}

void
dns_zone_setkeydirectory(dns_zone_t *zone, const char *directory) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	setstring(zone, &zone->keydirectory, directory);
	UNLOCK_ZONE(zone);
}

const char *
dns_zone_getkeydirectory(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->keydirectory;
}

void
dns_zone_setcheckmx(dns_zone_t *zone, dns_checkmxfunc_t checkmx) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->checkmx = checkmx;
}

void
dns_zone_setchecksrv(dns_zone_t *zone, dns_checksrvfunc_t checksrv) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->checksrv = checksrv;
}

void
dns_zone_setcheckns(dns_zone_t *zone, dns_checknsfunc_t checkns) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->checkns = checkns;
}

void
dns_zone_setcheckisservedby(dns_zone_t *zone,
			    dns_checkisservedbyfunc_t checkisservedby) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->checkisservedby = checkisservedby;
}

void
dns_zone_setisself(dns_zone_t *zone, dns_isselffunc_t isself, void *arg) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	zone->isself = isself;
	zone->isselfarg = arg;
	UNLOCK_ZONE(zone);
}

void
dns__zone_getisself(dns_zone_t *zone, dns_isselffunc_t *isself, void **arg) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(isself != NULL);
	REQUIRE(arg != NULL && *arg == NULL);

	*isself = zone->isself;
	*arg = zone->isselfarg;
}

void
dns_zone_setnotifydefer(dns_zone_t *zone, dns_rdatatype_t type,
			uint32_t defer) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	switch (type) {
	case dns_rdatatype_soa:
		zone->notifysoa.notifydefer = defer;
		break;
	case dns_rdatatype_cds:
		/* not applicable to NOTIFY(CDS), unused */
		zone->notifycds.notifydefer = defer;
		break;
	default:
		UNREACHABLE();
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_setnotifydelay(dns_zone_t *zone, dns_rdatatype_t type,
			uint32_t delay) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	switch (type) {
	case dns_rdatatype_soa:
		zone->notifysoa.notifydelay = delay;
		break;
	case dns_rdatatype_cds:
		/* not applicable to NOTIFY(CDS), unused */
		zone->notifycds.notifydelay = delay;
		break;
	default:
		UNREACHABLE();
	}
	UNLOCK_ZONE(zone);
}

void
dns_zone_setnodes(dns_zone_t *zone, uint32_t nodes) {
	REQUIRE(DNS_ZONE_VALID(zone));

	if (nodes == 0) {
		nodes = 1;
	}
	zone->nodes = nodes;
}

void
dns_zone_setsignatures(dns_zone_t *zone, uint32_t signatures) {
	REQUIRE(DNS_ZONE_VALID(zone));

	/*
	 * We treat signatures as a signed value so explicitly
	 * limit its range here.
	 */
	if (signatures > INT32_MAX) {
		signatures = INT32_MAX;
	} else if (signatures == 0) {
		signatures = 1;
	}
	zone->signatures = signatures;
}

uint32_t
dns_zone_getsignatures(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->signatures;
}

void
dns_zone_setprivatetype(dns_zone_t *zone, dns_rdatatype_t type) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->privatetype = type;
}

dns_rdatatype_t
dns_zone_getprivatetype(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->privatetype;
}

void
dns_zone_setautomatic(dns_zone_t *zone, bool automatic) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	zone->automatic = automatic;
	UNLOCK_ZONE(zone);
}

bool
dns_zone_getautomatic(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->automatic;
}

void
dns_zone_setadded(dns_zone_t *zone, bool added) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	zone->added = added;
	UNLOCK_ZONE(zone);
}

bool
dns_zone_getadded(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->added;
}

void
dns_zone_setmodded(dns_zone_t *zone, bool modded) {
	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	zone->modded = modded;
	UNLOCK_ZONE(zone);
}

bool
dns_zone_getmodded(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->modded;
}

isc_result_t
dns_zone_setrefreshkeyinterval(dns_zone_t *zone, uint32_t interval) {
	REQUIRE(DNS_ZONE_VALID(zone));
	if (interval == 0) {
		return ISC_R_RANGE;
	}
	/* Maximum value: 24 hours (3600 minutes) */
	if (interval > (24 * 60)) {
		interval = (24 * 60);
	}
	/* Multiply by 60 for seconds */
	zone->refreshkeyinterval = interval * 60;
	return ISC_R_SUCCESS;
}

void
dns_zone_setrequestixfr(dns_zone_t *zone, bool flag) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->requestixfr = flag;
}

bool
dns_zone_getrequestixfr(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->requestixfr;
}

void
dns_zone_setrequestixfrmaxdiffs(dns_zone_t *zone, uint32_t maxdiffs) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->requestixfr_maxdiffs = maxdiffs;
}

bool
dns_zone_getrequestixfrmaxdiffs(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->requestixfr_maxdiffs;
}

void
dns_zone_setixfrratio(dns_zone_t *zone, uint32_t ratio) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->ixfr_ratio = ratio;
}

uint32_t
dns_zone_getixfrratio(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->ixfr_ratio;
}

void
dns_zone_setrequestexpire(dns_zone_t *zone, bool flag) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->requestexpire = flag;
}

bool
dns_zone_getrequestexpire(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->requestexpire;
}

void
dns_zone_setserialupdatemethod(dns_zone_t *zone, dns_updatemethod_t method) {
	REQUIRE(DNS_ZONE_VALID(zone));
	zone->updatemethod = method;
}

dns_updatemethod_t
dns_zone_getserialupdatemethod(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->updatemethod;
}

void
dns_zone_getloadtime(dns_zone_t *zone, isc_time_t *loadtime) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(loadtime != NULL);

	LOCK_ZONE(zone);
	*loadtime = zone->loadtime;
	UNLOCK_ZONE(zone);
}

void
dns_zone_getexpiretime(dns_zone_t *zone, isc_time_t *expiretime) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(expiretime != NULL);

	LOCK_ZONE(zone);
	*expiretime = zone->expiretime;
	UNLOCK_ZONE(zone);
}

void
dns_zone_getrefreshtime(dns_zone_t *zone, isc_time_t *refreshtime) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(refreshtime != NULL);

	LOCK_ZONE(zone);
	*refreshtime = zone->refreshtime;
	UNLOCK_ZONE(zone);
}

void
dns_zone_getrefreshkeytime(dns_zone_t *zone, isc_time_t *refreshkeytime) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(refreshkeytime != NULL);

	LOCK_ZONE(zone);
	*refreshkeytime = zone->refreshkeytime;
	UNLOCK_ZONE(zone);
}

void
dns_zone_setstatlevel(dns_zone_t *zone, dns_zonestat_level_t level) {
	REQUIRE(DNS_ZONE_VALID(zone));

	zone->statlevel = level;
}

dns_zonestat_level_t
dns_zone_getstatlevel(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->statlevel;
}

unsigned int
dns_zone_gettid(dns_zone_t *zone) {
	return zone->tid;
}

isc_loop_t *
dns_zone_getloop(dns_zone_t *zone) {
	return zone->loop;
}

isc_result_t
dns_zone_getrad(dns_zone_t *zone, dns_name_t *name) {
	isc_result_t result = ISC_R_NOTFOUND;

	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(DNS_NAME_VALID(name));

	rcu_read_lock();
	dns_rad_t *rad = rcu_dereference(zone->rad);
	if (rad != NULL) {
		dns_name_t *inner = dns_fixedname_name(&rad->fname);
		dns_name_copy(inner, name);
		result = ISC_R_SUCCESS;
	}
	rcu_read_unlock();

	return result;
}

void
dns_zone_setrad(dns_zone_t *zone, dns_name_t *name) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(name == NULL || DNS_NAME_VALID(name));

	rcu_read_lock();
	dns_rad_t *new_rad = NULL;
	if (name != NULL) {
		new_rad = isc_mem_get(zone->mctx, sizeof(*new_rad));
		*new_rad = (dns_rad_t){};
		dns_fixedname_init(&new_rad->fname);

		isc_mem_attach(zone->mctx, &new_rad->mctx);
		dns_name_copy(name, dns_fixedname_name(&new_rad->fname));
	}
	dns_rad_t *xchg_rad = rcu_xchg_pointer(&zone->rad, new_rad);

	if (xchg_rad != NULL) {
		call_rcu(&xchg_rad->rcu_head, free_rad_rcu);
	}
	rcu_read_unlock();
}

void *
dns_zone_gethooktable(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));
	return zone->hooktable;
}

void
dns_zone_sethooktable(dns_zone_t *zone, void *hooktable,
		      void (*hooktable_free)(isc_mem_t *, void **)) {
	REQUIRE(DNS_ZONE_VALID(zone));
	REQUIRE(zone->hooktable == NULL);
	REQUIRE(zone->hooktable_free == NULL);

	zone->hooktable = hooktable;
	zone->hooktable_free = hooktable_free;
}

void
dns_zone_setcfg(dns_zone_t *zone, const char *cfg) {
	REQUIRE(DNS_ZONE_VALID(zone));

	if (zone->cfg != NULL) {
		isc_mem_free(zone->mctx, zone->cfg);
	}
	if (cfg != NULL) {
		zone->cfg = isc_mem_strdup(zone->mctx, cfg);
	}
}

const char *
dns_zone_getcfg(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->cfg;
}

/*
 * Get the transport type used for the SOA query to the current primary server
 * before an ongoing incoming zone transfer.
 *
 * Requires:
 *      The zone is locked by the caller.
 */
static dns_transport_type_t
get_request_transport_type(dns_zone_t *zone) {
	dns_transport_type_t transport_type = DNS_TRANSPORT_NONE;

	if (zone->transport != NULL) {
		transport_type = dns_transport_get_type(zone->transport);
	} else {
		transport_type = (DNS_ZONE_FLAG(zone, DNS_ZONEFLG_USEVC))
					 ? DNS_TRANSPORT_TCP
					 : DNS_TRANSPORT_UDP;

		/* Check if the peer is forced to always use TCP. */
		if (transport_type != DNS_TRANSPORT_TCP &&
		    !dns_remote_done(&zone->primaries))
		{
			isc_result_t result;
			isc_sockaddr_t primaryaddr;
			isc_netaddr_t primaryip;
			dns_peer_t *peer = NULL;

			primaryaddr = dns_remote_curraddr(&zone->primaries);
			isc_netaddr_fromsockaddr(&primaryip, &primaryaddr);
			result = dns_peerlist_peerbyaddr(zone->view->peers,
							 &primaryip, &peer);
			if (result == ISC_R_SUCCESS && peer != NULL) {
				bool usetcp;
				result = dns_peer_getforcetcp(peer, &usetcp);
				if (result == ISC_R_SUCCESS && usetcp) {
					transport_type = DNS_TRANSPORT_TCP;
				}
			}
		}
	}

	return transport_type;
}

dns_transport_type_t
dns_zone_getrequesttransporttype(dns_zone_t *zone) {
	dns_transport_type_t transport_type;

	REQUIRE(DNS_ZONE_VALID(zone));

	LOCK_ZONE(zone);
	transport_type = get_request_transport_type(zone);
	UNLOCK_ZONE(zone);

	return transport_type;
}

dns_keystorelist_t *
dns_zone_getkeystores(dns_zone_t *zone) {
	return zone->zmgr->keystores;
}

isc_stats_t *
dns_zone_getgluecachestats(dns_zone_t *zone) {
	REQUIRE(DNS_ZONE_VALID(zone));

	return zone->gluecachestats;
}
