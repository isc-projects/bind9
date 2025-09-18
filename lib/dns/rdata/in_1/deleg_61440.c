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

#pragma once

#include <stdbool.h>

#include <isc/result.h>

#define RRTYPE_DELEG_ATTRIBUTES                                            \
	(DNS_RDATATYPEATTR_FOLLOWADDITIONAL | DNS_RDATATYPEATTR_ATPARENT | \
	 DNS_RDATATYPEATTR_ZONECUTAUTH)

/*
 * Delegation Information Registry
 */
enum deleg_encoding {
	deleg_unknown,
	deleg_namelist,
	deleg_ipv4,
	deleg_ipv6,
	deleg_keylist
};

enum deleg_type {
	delegkey_mandatory = 0,
	delegkey_ipv4 = 1,
	delegkey_ipv6 = 2,
	delegkey_name = 3,
	delegkey_include = 4,
};

static const struct {
	const char *name;
	unsigned int value;
	enum deleg_encoding encoding;
	bool initial; /* Part of the first defined set of encodings. */
} direg[] = {
	{ "mandatory", delegkey_mandatory, deleg_keylist, true },
	{ "server-ipv4", delegkey_ipv4, deleg_ipv4, true },
	{ "server-ipv6", delegkey_ipv6, deleg_ipv6, true },
	{ "server-name", delegkey_name, deleg_namelist, true },
	{ "include-delegparam", delegkey_include, deleg_namelist, true },
};

static int
deleg_keycmp(const void *a1, const void *a2) {
	const unsigned char *u1 = a1, *u2 = a2;
	if (*u1 != *u2) {
		return *u1 - *u2;
	}
	return *(++u1) - *(++u2);
}

static isc_result_t
deleg_sortkeylist(isc_buffer_t *target, unsigned int used) {
	isc_region_t region;

	isc_buffer_usedregion(target, &region);
	isc_region_consume(&region, used);
	INSIST(region.length > 0U);
	qsort(region.base, region.length / 2, 2, deleg_keycmp);
	/* Reject duplicates. */
	while (region.length >= 4) {
		if (region.base[0] == region.base[2] &&
		    region.base[1] == region.base[3])
		{
			return DNS_R_SYNTAX;
		}
		isc_region_consume(&region, 2);
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
deleg_validate(uint16_t key, isc_region_t *region) {
	size_t i, j;

	for (i = 0; i < ARRAY_SIZE(direg); i++) {
		if (direg[i].value == key) {
			switch (direg[i].encoding) {
			case deleg_ipv4:
				if ((region->length % 4) != 0 ||
				    region->length == 0)
				{
					return DNS_R_FORMERR;
				}
				break;
			case deleg_ipv6:
				if ((region->length % 16) != 0 ||
				    region->length == 0)
				{
					return DNS_R_FORMERR;
				}
				break;
			case deleg_namelist:
				if (region->length == 0) {
					return DNS_R_FORMERR;
				}
				break;
			case deleg_keylist: {
				if ((region->length % 2) != 0 ||
				    region->length == 0)
				{
					return DNS_R_FORMERR;
				}
				/* In order? */
				while (region->length >= 4) {
					if (region->base[0] > region->base[2] ||
					    (region->base[0] ==
						     region->base[2] &&
					     region->base[1] >=
						     region->base[3]))
					{
						return DNS_R_FORMERR;
					}
					isc_region_consume(region, 2);
				}
				break;
			}
			case deleg_unknown:
				for (j = 0; j < region->length; j++) {
					if (!islower(region->base[j]) &&
					    !isdigit(region->base[j]) &&
					    region->base[j] != '-')
					{
						return DNS_R_FORMERR;
					}
				}
				break;
			default:
				UNREACHABLE();
			}
		}
	}
	return ISC_R_SUCCESS;
}

/*
 * Parse keyname from region.
 */
static isc_result_t
deleg_keyfromregion(isc_textregion_t *region, char sep, uint16_t *value,
		    isc_buffer_t *target) {
	char *e = NULL;
	size_t i;
	unsigned long ul;

	/* Look for known key names.  */
	for (i = 0; i < ARRAY_SIZE(direg); i++) {
		size_t len = strlen(direg[i].name);
		if (strncasecmp(region->base, direg[i].name, len) != 0) {
			continue;
		}

		INSIST(region->length >= len);
		if (region->length != len && region->base[len] != sep) {
			continue;
		}
		isc_textregion_consume(region, len);
		ul = direg[i].value;
		goto finish;
	}
	/* Handle keyXXXXX form. */
	if (strncmp(region->base, "key", 3) != 0) {
		return DNS_R_SYNTAX;
	}
	isc_textregion_consume(region, 3);
	/* Disallow [+-]XXXXX which is allowed by strtoul. */
	if (region->length == 0 || *region->base == '-' || *region->base == '+')
	{
		return DNS_R_SYNTAX;
	}
	/* No zero padding. */
	if (region->length > 1 && *region->base == '0' &&
	    region->base[1] != '=')
	{
		return DNS_R_SYNTAX;
	}
	ul = strtoul(region->base, &e, 10);
	/* Valid number? */
	if (e == region->base || (*e != sep && *e != 0)) {
		return DNS_R_SYNTAX;
	}
	if (ul > 0xffff) {
		return ISC_R_RANGE;
	}
	isc_textregion_consume(region, e - region->base);
finish:
	if (sep == ',' && region->length == 1) {
		return DNS_R_SYNTAX;
	}
	/* Consume separator. */
	if (region->length != 0) {
		isc_textregion_consume(region, 1);
	}
	RETERR(uint16_tobuffer(ul, target));
	SET_IF_NOT_NULL(value, ul);
	return ISC_R_SUCCESS;
}

static isc_result_t
servname_fromtxt(isc_textregion_t *region, const dns_name_t *origin,
		 unsigned int options, isc_lex_t *lexer,
		 dns_rdatacallbacks_t *callbacks, isc_buffer_t *target) {
	isc_textregion_t src = *region;

	if (origin == NULL) {
		origin = dns_rootname;
	}

	do {
		char buf[DNS_NAME_FORMATSIZE];
		isc_buffer_t b;
		dns_fixedname_t fn;
		dns_name_t *name = dns_fixedname_initname(&fn);

		isc_buffer_init(&b, buf, sizeof(buf));
		RETERR(commatxt_fromtext(&src, true, true, &b));

		/* skip the leading length byte */
		isc_buffer_forward(&b, 1);

		RETERR(dns_name_fromtext(name, &b, origin, options));
		RETERR(dns_name_towire(name, NULL, target));

		/* check for valid hostnames */
		if ((options & DNS_RDATA_CHECKNAMES) == 0 ||
		    dns_name_ishostname(name, false))
		{
			continue;
		}

		if ((options & DNS_RDATA_CHECKNAMESFAIL) != 0) {
			RETERR(DNS_R_BADNAME);
		}
		if (callbacks != NULL) {
			warn_badname(name, lexer, callbacks);
		}
	} while (src.length != 0);

	isc_textregion_consume(region, region->length);
	return ISC_R_SUCCESS;
}

static isc_result_t
deleg_fromtext(isc_textregion_t *region, const dns_name_t *origin,
	       unsigned int options, isc_lex_t *lexer,
	       dns_rdatacallbacks_t *callbacks, isc_buffer_t *target) {
	char *e = NULL;
	char abuf[16];
	char tbuf[sizeof("aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:255.255.255.255,")];
	isc_buffer_t sb;
	isc_region_t keyregion;
	size_t len;
	uint16_t key;
	unsigned int i;
	unsigned int used;

	for (i = 0; i < ARRAY_SIZE(direg); i++) {
		len = strlen(direg[i].name);
		if (strncmp(region->base, direg[i].name, len) != 0 ||
		    (region->base[len] != 0 && region->base[len] != '='))
		{
			continue;
		}

		if (region->base[len] == '=') {
			len++;
		}

		RETERR(uint16_tobuffer(direg[i].value, target));
		isc_textregion_consume(region, len);

		sb = *target;
		RETERR(uint16_tobuffer(0, target)); /* dummy length */

		switch (direg[i].encoding) {
		case deleg_ipv4:
			do {
				snprintf(tbuf, sizeof(tbuf), "%*s",
					 (int)(region->length), region->base);
				e = strchr(tbuf, ',');
				if (e != NULL) {
					*e++ = 0;
					isc_textregion_consume(region,
							       e - tbuf);
				}
				if (inet_pton(AF_INET, tbuf, abuf) != 1) {
					return DNS_R_SYNTAX;
				}
				mem_tobuffer(target, abuf, 4);
			} while (e != NULL);
			break;
		case deleg_ipv6:
			do {
				snprintf(tbuf, sizeof(tbuf), "%*s",
					 (int)(region->length), region->base);
				e = strchr(tbuf, ',');
				if (e != NULL) {
					*e++ = 0;
					isc_textregion_consume(region,
							       e - tbuf);
				}
				if (inet_pton(AF_INET6, tbuf, abuf) != 1) {
					return DNS_R_SYNTAX;
				}
				mem_tobuffer(target, abuf, 16);
			} while (e != NULL);
			break;
		case deleg_namelist:
			RETERR(servname_fromtxt(region, origin, options, lexer,
						callbacks, target));
			break;
		case deleg_keylist:
			if (region->length == 0) {
				return DNS_R_SYNTAX;
			}
			used = isc_buffer_usedlength(target);
			while (region->length != 0) {
				RETERR(deleg_keyfromregion(region, ',', NULL,
							   target));
			}
			RETERR(deleg_sortkeylist(target, used));
			break;
		case deleg_unknown:
		default:
			UNREACHABLE();
		}

		len = isc_buffer_usedlength(target) -
		      isc_buffer_usedlength(&sb) - 2;
		RETERR(uint16_tobuffer(len, &sb)); /* actual length */
		return ISC_R_SUCCESS;
	}

	RETERR(deleg_keyfromregion(region, '=', &key, target));
	if (region->length == 0) {
		RETERR(uint16_tobuffer(0, target)); /* length */
		/* Sanity check keyXXXXX form. */
		keyregion.base = isc_buffer_used(target);
		keyregion.length = 0;
		return deleg_validate(key, &keyregion);
	}
	sb = *target;
	RETERR(uint16_tobuffer(0, target)); /* dummy length */
	RETERR(multitxt_fromtext(region, target));
	len = isc_buffer_usedlength(target) - isc_buffer_usedlength(&sb) - 2;
	RETERR(uint16_tobuffer(len, &sb)); /* length */
	/* Sanity check keyXXXXX form. */
	keyregion.base = isc_buffer_used(&sb);
	keyregion.length = len;
	return deleg_validate(key, &keyregion);
}

static isc_result_t
deleg_sortkeys(isc_buffer_t *target, unsigned int used) {
	isc_region_t r1, r2, man = { .base = NULL, .length = 0 };
	bool have_address = false, have_name = false;
	unsigned char buf[1024];
	uint16_t mankey = 0;

	if (isc_buffer_usedlength(target) == used) {
		return ISC_R_SUCCESS;
	}

	/*
	 * Get the parameters into r1.
	 */
	isc_buffer_usedregion(target, &r1);
	isc_region_consume(&r1, used);

	while (1) {
		uint16_t key1, len1, key2, len2;
		unsigned char *base1, *base2;

		r2 = r1;

		/*
		 * Get the first parameter.
		 */
		base1 = r1.base;
		key1 = uint16_fromregion(&r1);
		isc_region_consume(&r1, 2);
		len1 = uint16_fromregion(&r1);
		isc_region_consume(&r1, 2);
		isc_region_consume(&r1, len1);

		/*
		 * Was there only one key left?
		 */
		if (r1.length == 0) {
			if (mankey != 0) {
				/* Is this the last mandatory key? */
				if (key1 != mankey || man.length != 0) {
					return DNS_R_INCONSISTENTRR;
				}
			} else if (key1 == 0) {
				/* Lone mandatory field. */
				return DNS_R_DISALLOWED;
			}

			/* Both name and address are present. */
			if ((have_address && key1 == delegkey_name) ||
			    (have_name &&
			     (key1 == delegkey_ipv4 || key1 == delegkey_ipv6)))
			{
				return DNS_R_DISALLOWED;
			}

			return ISC_R_SUCCESS;
		}

		/*
		 * Find the smallest parameter.
		 */
		while (r1.length != 0) {
			base2 = r1.base;
			key2 = uint16_fromregion(&r1);
			isc_region_consume(&r1, 2);
			len2 = uint16_fromregion(&r1);
			isc_region_consume(&r1, 2);
			isc_region_consume(&r1, len2);
			if (key2 == key1) {
				return DNS_R_DUPLICATE;
			}
			if (key2 < key1) {
				base1 = base2;
				key1 = key2;
				len1 = len2;
			}
		}

		/*
		 * Do we need to move the smallest parameter to the start?
		 */
		if (base1 != r2.base) {
			size_t offset = 0;
			size_t bytes = len1 + 4;
			size_t length = base1 - r2.base;

			/*
			 * Move the smallest parameter to the start.
			 */
			while (bytes > 0) {
				size_t count;

				if (bytes > sizeof(buf)) {
					count = sizeof(buf);
				} else {
					count = bytes;
				}
				memmove(buf, base1, count);
				memmove(r2.base + offset + count,
					r2.base + offset, length);
				memmove(r2.base + offset, buf, count);
				base1 += count;
				bytes -= count;
				offset += count;
			}
		}

		/*
		 * Check key against mandatory key list.
		 */
		if (mankey != 0) {
			if (key1 > mankey) {
				return DNS_R_INCONSISTENTRR;
			}
			if (key1 == mankey) {
				if (man.length >= 2) {
					mankey = uint16_fromregion(&man);
					isc_region_consume(&man, 2);
				} else {
					mankey = 0;
				}
			}
		}

		/*
		 * Is this the mandatory key?
		 */
		if (key1 == 0) {
			man = r2;
			man.length = len1 + 4;
			isc_region_consume(&man, 4);
			if (man.length < 2) {
				return DNS_R_SYNTAX;
			}

			mankey = uint16_fromregion(&man);
			isc_region_consume(&man, 2);
			if (mankey == 0) {
				return DNS_R_DISALLOWED;
			}
		}

		/*
		 * Remember if this was a name or address field.
		 */
		switch (key1) {
		case delegkey_ipv4:
		case delegkey_ipv6:
			have_address = true;
			break;
		case delegkey_name:
			have_name = true;
			break;
		default:
			break;
		}

		/*
		 * Consume the smallest parameter.
		 */
		isc_region_consume(&r2, len1 + 4);
		r1 = r2;
	}
}

static isc_result_t
generic_fromtext_in_deleg(ARGS_FROMTEXT) {
	isc_token_t token;
	unsigned int used;
	bool eolok = false;

	UNUSED(type);
	UNUSED(rdclass);

	/*
	 * DelegInfos
	 */
	used = isc_buffer_usedlength(target);
	while (1) {
		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_qvpair, eolok));
		if (token.type == isc_tokentype_eol ||
		    token.type == isc_tokentype_eof)
		{
			isc_lex_ungettoken(lexer, &token);
			return deleg_sortkeys(target, used);
		}

		if (token.type != isc_tokentype_string && /* key only */
		    token.type != isc_tokentype_qvpair &&
		    token.type != isc_tokentype_vpair)
		{
			RETTOK(DNS_R_SYNTAX);
		}
		RETTOK(deleg_fromtext(&token.value.as_textregion, origin,
				      options, lexer, callbacks, target));
		eolok = true;
	}
}

static isc_result_t
comma_name_totext(const dns_name_t *name, isc_buffer_t *target) {
	char in[DNS_NAME_FORMATSIZE];
	size_t len = isc_buffer_availablelength(target);

	dns_name_format(name, in, sizeof(in));

	for (char *sp = in; *sp != '\0'; sp++) {
		if (*sp == ',') {
			if (len < 3) {
				return ISC_R_NOSPACE;
			}
			isc_buffer_putstr(target, "\\\\,");
		} else if (*sp == '\\') {
			if (len < 2) {
				return ISC_R_NOSPACE;
			}
			isc_buffer_putstr(target, "\\\\");
		} else {
			if (len < 1) {
				return ISC_R_NOSPACE;
			}
			isc_buffer_putuint8(target, *sp);
		}
		len--;
	}

	if (len < 1) {
		return ISC_R_NOSPACE;
	}
	isc_buffer_putuint8(target, '.');

	return ISC_R_SUCCESS;
}

static inline int
param_index(unsigned short value) {
	for (size_t i = 0; i < ARRAY_SIZE(direg); i++) {
		if (direg[i].value == value) {
			return (int)i;
		}
	}
	return -1;
}

static inline enum deleg_encoding
param_encoding(int i) {
	if (i >= 0) {
		return direg[i].encoding;
	}
	return deleg_unknown;
}

static const char *
deleg_paramkey(unsigned short value, char *buf, size_t len) {
	int i = param_index(value);

	if (i >= 0) {
		return direg[i].name;
	} else {
		int n = snprintf(buf, len, "key%u", value);
		INSIST(n > 0 && (unsigned int)n < len);
		return buf;
	}
}

static isc_result_t
generic_totext_in_deleg(ARGS_TOTEXT) {
	isc_region_t region;
	char buf[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255")];
	bool compat = (tctx->flags & DNS_STYLEFLAG_SVCPARAMKEYCOMPAT) != 0;
	bool first = true;

	REQUIRE(rdata->length != 0);

	dns_rdata_toregion(rdata, &region);

	while (region.length > 0) {
		enum deleg_encoding encoding = deleg_unknown;
		uint16_t num;
		isc_region_t r;

		if (!first) {
			RETERR(str_totext(" ", target));
		}
		first = false;

		INSIST(region.length >= 2);
		num = uint16_fromregion(&region);
		isc_region_consume(&region, 2);

		int i = param_index(num);
		if (i >= 0 && ((direg[i].initial) || !compat)) {
			encoding = param_encoding(i);
		}
		RETERR(str_totext(deleg_paramkey(num, buf, sizeof(buf)),
				  target));

		INSIST(region.length >= 2);
		num = uint16_fromregion(&region);
		isc_region_consume(&region, 2);

		INSIST(region.length >= num);
		r = region;
		r.length = num;
		isc_region_consume(&region, num);
		if (num == 0) {
			continue;
		}
		RETERR(str_totext("=", target));
		switch (encoding) {
		case deleg_ipv4:
			while (r.length > 0U) {
				INSIST(r.length >= 4U);
				inet_ntop(AF_INET, r.base, buf, sizeof(buf));
				RETERR(str_totext(buf, target));
				isc_region_consume(&r, 4);
				if (r.length != 0U) {
					RETERR(str_totext(",", target));
				}
			}
			break;
		case deleg_ipv6:
			while (r.length > 0U) {
				INSIST(r.length >= 16U);
				inet_ntop(AF_INET6, r.base, buf, sizeof(buf));
				RETERR(str_totext(buf, target));
				isc_region_consume(&r, 16);
				if (r.length != 0U) {
					RETERR(str_totext(",", target));
				}
			}
			break;
		case deleg_namelist:
			while (r.length > 0U) {
				dns_fixedname_t fn;
				dns_name_t *name = dns_fixedname_initname(&fn);
				isc_buffer_t b;

				isc_buffer_init(&b, r.base, r.length);
				isc_buffer_add(&b, r.length);
				isc_buffer_setactive(&b, r.length);
				RETERR(dns_name_fromwire(name, &b, NULL, NULL));
				RETERR(comma_name_totext(name, target));

				isc_region_consume(
					&r, isc_buffer_consumedlength(&b));
				if (r.length != 0U) {
					RETERR(str_totext(",", target));
				}
			}
			break;
		case deleg_keylist:
			while (r.length > 0) {
				num = uint16_fromregion(&r);
				isc_region_consume(&r, 2);
				RETERR(str_totext(
					deleg_paramkey(num, buf, sizeof(buf)),
					target));
				if (r.length != 0) {
					RETERR(str_totext(",", target));
				}
			}
			break;
		case deleg_unknown:
			RETERR(multitxt_totext(&r, false, target));
			break;
		default:
			UNREACHABLE();
		}
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
generic_fromwire_in_deleg(ARGS_FROMWIRE) {
	isc_region_t region, man = { .base = NULL, .length = 0 };
	uint16_t lastkey = 0, mankey = 0;
	bool first = true;

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(dctx);

	/*
	 * DelegInfos
	 */
	isc_buffer_activeregion(source, &region);
	if (region.length < 2) {
		return ISC_R_UNEXPECTEDEND;
	}

	while (region.length > 0U) {
		isc_region_t keyregion;
		uint16_t key, len;

		/*
		 * DelegInfoKey
		 */
		if (region.length < 2U) {
			return ISC_R_UNEXPECTEDEND;
		}
		RETERR(mem_tobuffer(target, region.base, 2));
		key = uint16_fromregion(&region);
		isc_region_consume(&region, 2);

		/*
		 * Keys must be unique and in order.
		 */
		if (!first && key <= lastkey) {
			return DNS_R_FORMERR;
		}

		first = false;
		lastkey = key;

		/*
		 * Check mandatory keys.
		 */
		if (mankey != 0) {
			/* Missing mandatory key? */
			if (key > mankey) {
				return DNS_R_FORMERR;
			}
			if (key == mankey) {
				/* Get next mandatory key. */
				if (man.length >= 2) {
					mankey = uint16_fromregion(&man);
					isc_region_consume(&man, 2);
				} else {
					mankey = 0;
				}
			}
		}

		/*
		 * DelegInfoValue length.
		 */
		if (region.length < 2U) {
			return ISC_R_UNEXPECTEDEND;
		}
		RETERR(mem_tobuffer(target, region.base, 2));
		len = uint16_fromregion(&region);
		isc_region_consume(&region, 2);

		/*
		 * DelegInfoValue.
		 */
		if (region.length < len) {
			return ISC_R_UNEXPECTEDEND;
		}

		/*
		 * Remember manatory key.
		 */
		if (key == delegkey_mandatory) {
			man = region;
			man.length = len;
			/* Get first mandatory key */
			if (man.length >= 2) {
				mankey = uint16_fromregion(&man);
				isc_region_consume(&man, 2);
				if (mankey == delegkey_mandatory) {
					return DNS_R_FORMERR;
				}
			} else {
				return DNS_R_FORMERR;
			}
		}

		keyregion = region;
		keyregion.length = len;
		RETERR(deleg_validate(key, &keyregion));
		RETERR(mem_tobuffer(target, region.base, len));
		isc_region_consume(&region, len);
		isc_buffer_forward(source, len + 4);
	}

	/*
	 * Do we have an outstanding mandatory key?
	 */
	if (mankey != 0) {
		return DNS_R_FORMERR;
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
generic_fromstruct_in_deleg(ARGS_FROMSTRUCT) {
	dns_rdata_in_deleg_t *deleg = source;

	REQUIRE(deleg != NULL);
	REQUIRE(deleg->common.rdtype == type);
	REQUIRE(deleg->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	return mem_tobuffer(target, deleg->dinfo, deleg->dinfolen);
}

static isc_result_t
generic_tostruct_in_deleg(ARGS_TOSTRUCT) {
	isc_region_t region;
	dns_rdata_in_deleg_t *deleg = target;

	REQUIRE(deleg != NULL);
	REQUIRE(rdata->length != 0);

	DNS_RDATACOMMON_INIT(deleg, rdata->type, rdata->rdclass);

	dns_rdata_toregion(rdata, &region);

	deleg->dinfolen = region.length;
	deleg->dinfo = region.base;

	deleg->offset = 0;

	return ISC_R_SUCCESS;
}

static bool
generic_checknames_in_deleg(ARGS_CHECKNAMES) {
	isc_region_t region;

	dns_rdata_toregion(rdata, &region);
	while (region.length > 0) {
		uint16_t key = uint16_fromregion(&region);

		isc_region_consume(&region, 2);

		/* get the DelegInfo lenth */
		uint16_t len = uint16_fromregion(&region);
		isc_region_consume(&region, 2);

		isc_region_t r = { .base = region.base, .length = len };
		isc_region_consume(&region, len);

		if (param_encoding(param_index(key)) != deleg_namelist) {
			continue;
		}

		while (r.length > 0U) {
			dns_name_t name = DNS_NAME_INITEMPTY;

			dns_name_fromregion(&name, &r);
			isc_region_consume(&r, name.length);

			if (bad != NULL) {
				dns_name_clone(&name, bad);
			}
			if (!dns_name_ishostname(&name, false)) {
				return false;
			}
			if (dns_name_issubdomain(&name, owner)) {
				return false;
			}
		}
	}
	return true;
}

static isc_result_t
generic_rdata_in_deleg_first(dns_rdata_in_deleg_t *deleg) {
	if (deleg->dinfolen == 0) {
		return ISC_R_NOMORE;
	}
	deleg->offset = 0;
	return ISC_R_SUCCESS;
}

static isc_result_t
generic_rdata_in_deleg_next(dns_rdata_in_deleg_t *deleg) {
	isc_region_t region;
	size_t len;

	if (deleg->offset >= deleg->dinfolen) {
		return ISC_R_NOMORE;
	}

	region.base = deleg->dinfo + deleg->offset;
	region.length = deleg->dinfolen - deleg->offset;
	INSIST(region.length >= 4);
	isc_region_consume(&region, 2);
	len = uint16_fromregion(&region);
	INSIST(region.length >= len + 2);
	deleg->offset += len + 4;
	return deleg->offset >= deleg->dinfolen ? ISC_R_NOMORE : ISC_R_SUCCESS;
}

static void
generic_rdata_in_deleg_current(dns_rdata_in_deleg_t *deleg,
			       isc_region_t *region) {
	size_t len;

	INSIST(deleg->offset <= deleg->dinfolen);

	region->base = deleg->dinfo + deleg->offset;
	region->length = deleg->dinfolen - deleg->offset;
	INSIST(region->length >= 4);
	isc_region_consume(region, 2);
	len = uint16_fromregion(region);
	INSIST(region->length >= len + 2);
	region->base = deleg->dinfo + deleg->offset;
	region->length = len + 4;
}

static isc_result_t
fromtext_in_deleg(ARGS_FROMTEXT) {
	REQUIRE(type == dns_rdatatype_deleg);
	REQUIRE(rdclass == dns_rdataclass_in);

	return generic_fromtext_in_deleg(CALL_FROMTEXT);
}

static isc_result_t
totext_in_deleg(ARGS_TOTEXT) {
	REQUIRE(rdata->type == dns_rdatatype_deleg);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	return generic_totext_in_deleg(CALL_TOTEXT);
}

static isc_result_t
fromwire_in_deleg(ARGS_FROMWIRE) {
	REQUIRE(type == dns_rdatatype_deleg);
	REQUIRE(rdclass == dns_rdataclass_in);

	return generic_fromwire_in_deleg(CALL_FROMWIRE);
}

static int
compare_in_deleg(ARGS_COMPARE) {
	isc_region_t region1;
	isc_region_t region2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_deleg);
	REQUIRE(rdata1->rdclass == dns_rdataclass_in);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	return isc_region_compare(&region1, &region2);
}

static isc_result_t
fromstruct_in_deleg(ARGS_FROMSTRUCT) {
	dns_rdata_in_deleg_t *deleg = source;

	REQUIRE(type == dns_rdatatype_deleg);
	REQUIRE(rdclass == dns_rdataclass_in);
	REQUIRE(deleg != NULL);
	REQUIRE(deleg->common.rdtype == type);
	REQUIRE(deleg->common.rdclass == rdclass);

	return generic_fromstruct_in_deleg(CALL_FROMSTRUCT);
}

static isc_result_t
tostruct_in_deleg(ARGS_TOSTRUCT) {
	dns_rdata_in_deleg_t *deleg = target;

	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->type == dns_rdatatype_deleg);
	REQUIRE(deleg != NULL);
	REQUIRE(rdata->length != 0);

	return generic_tostruct_in_deleg(CALL_TOSTRUCT);
}

static isc_result_t
additionaldata_in_deleg(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_deleg);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return ISC_R_SUCCESS;
}

static isc_result_t
digest_in_deleg(ARGS_DIGEST) {
	isc_region_t region1;

	REQUIRE(rdata->type == dns_rdatatype_deleg);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	dns_rdata_toregion(rdata, &region1);
	return (digest)(arg, &region1);
}

static bool
checkowner_in_deleg(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_deleg);
	REQUIRE(rdclass == dns_rdataclass_in);

	return true;
}

static bool
checknames_in_deleg(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_deleg);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	return generic_checknames_in_deleg(CALL_CHECKNAMES);
}

static int
casecompare_in_deleg(ARGS_COMPARE) {
	return compare_in_deleg(rdata1, rdata2);
}

isc_result_t
dns_rdata_in_deleg_first(dns_rdata_in_deleg_t *deleg) {
	REQUIRE(deleg != NULL);
	REQUIRE(deleg->common.rdtype == dns_rdatatype_deleg);
	REQUIRE(deleg->common.rdclass == dns_rdataclass_in);

	return generic_rdata_in_deleg_first(deleg);
}

isc_result_t
dns_rdata_in_deleg_next(dns_rdata_in_deleg_t *deleg) {
	REQUIRE(deleg != NULL);
	REQUIRE(deleg->common.rdtype == dns_rdatatype_deleg);
	REQUIRE(deleg->common.rdclass == dns_rdataclass_in);

	return generic_rdata_in_deleg_next(deleg);
}

void
dns_rdata_in_deleg_current(dns_rdata_in_deleg_t *deleg, isc_region_t *region) {
	REQUIRE(deleg != NULL);
	REQUIRE(deleg->common.rdtype == dns_rdatatype_deleg);
	REQUIRE(deleg->common.rdclass == dns_rdataclass_in);
	REQUIRE(region != NULL);

	generic_rdata_in_deleg_current(deleg, region);
}
