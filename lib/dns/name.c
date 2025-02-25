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

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <isc/ascii.h>
#include <isc/attributes.h>
#include <isc/buffer.h>
#include <isc/hash.h>
#include <isc/hex.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/thread.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/name.h>

typedef enum {
	ft_init = 0,
	ft_start,
	ft_ordinary,
	ft_initialescape,
	ft_escape,
	ft_escdecimal,
	ft_at
} ft_state;

/*%
 * Note that the name data must be a char array, not a string
 * literal, to avoid compiler warnings about discarding
 * the const attribute of a string.
 */
static unsigned char root_ndata[] = { "" };
static dns_name_t root = DNS_NAME_INITABSOLUTE(root_ndata);
const dns_name_t *dns_rootname = &root;

static unsigned char wild_ndata[] = { "\001*" };

static dns_name_t const wild = DNS_NAME_INITNONABSOLUTE(wild_ndata);
const dns_name_t *dns_wildcardname = &wild;

/*
 * dns_name_t to text post-conversion procedure.
 */
static thread_local dns_name_totextfilter_t *totext_filter_proc = NULL;

bool
dns_name_isvalid(const dns_name_t *name) {
	unsigned char *ndata;
	unsigned int offset, count, length, nlabels;

	if (!DNS_NAME_VALID(name)) {
		return false;
	}

	ndata = name->ndata;
	length = name->length;
	offset = 0;
	nlabels = 0;

	while (offset != length) {
		count = *ndata;
		if (count > DNS_NAME_LABELLEN) {
			return false;
		}

		nlabels++;
		offset += count + 1;
		ndata += count + 1;
		if (offset > length) {
			return false;
		}

		if (count == 0) {
			break;
		}
	}

	if (nlabels > DNS_NAME_MAXLABELS || offset != name->length) {
		return false;
	}

	return true;
}

bool
dns_name_hasbuffer(const dns_name_t *name) {
	/*
	 * Does 'name' have a dedicated buffer?
	 */

	REQUIRE(DNS_NAME_VALID(name));

	if (name->buffer != NULL) {
		return true;
	}

	return false;
}

bool
dns_name_isabsolute(const dns_name_t *name) {
	/*
	 * Does 'name' end in the root label?
	 */

	REQUIRE(DNS_NAME_VALID(name));

	return name->attributes.absolute;
}

#define hyphenchar(c) ((c) == 0x2d)
#define asterchar(c)  ((c) == 0x2a)
#define alphachar(c) \
	(((c) >= 0x41 && (c) <= 0x5a) || ((c) >= 0x61 && (c) <= 0x7a))
#define digitchar(c)  ((c) >= 0x30 && (c) <= 0x39)
#define borderchar(c) (alphachar(c) || digitchar(c))
#define middlechar(c) (borderchar(c) || hyphenchar(c))
#define domainchar(c) ((c) > 0x20 && (c) < 0x7f)

bool
dns_name_ismailbox(const dns_name_t *name) {
	unsigned char *ndata, ch;
	unsigned int n;
	bool first;

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(name->length > 0);
	REQUIRE(name->attributes.absolute);

	/*
	 * Root label.
	 */
	if (name->length == 1) {
		return true;
	}

	ndata = name->ndata;
	n = *ndata++;
	INSIST(n <= DNS_NAME_LABELLEN);
	while (n--) {
		ch = *ndata++;
		if (!domainchar(ch)) {
			return false;
		}
	}

	if (ndata == name->ndata + name->length) {
		return false;
	}

	/*
	 * RFC952/RFC1123 hostname.
	 */
	while (ndata < (name->ndata + name->length)) {
		n = *ndata++;
		INSIST(n <= DNS_NAME_LABELLEN);
		first = true;
		while (n--) {
			ch = *ndata++;
			if (first || n == 0) {
				if (!borderchar(ch)) {
					return false;
				}
			} else {
				if (!middlechar(ch)) {
					return false;
				}
			}
			first = false;
		}
	}
	return true;
}

bool
dns_name_ishostname(const dns_name_t *name, bool wildcard) {
	unsigned char *ndata, ch;
	unsigned int n;
	bool first;

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(name->length > 0);
	REQUIRE(name->attributes.absolute);

	/*
	 * Root label.
	 */
	if (name->length == 1) {
		return true;
	}

	/*
	 * Skip wildcard if this is a ownername.
	 */
	ndata = name->ndata;
	if (wildcard && ndata[0] == 1 && ndata[1] == '*') {
		ndata += 2;
	}

	/*
	 * RFC952/RFC1123 hostname.
	 */
	while (ndata < (name->ndata + name->length)) {
		n = *ndata++;
		INSIST(n <= DNS_NAME_LABELLEN);
		first = true;
		while (n--) {
			ch = *ndata++;
			if (first || n == 0) {
				if (!borderchar(ch)) {
					return false;
				}
			} else {
				if (!middlechar(ch)) {
					return false;
				}
			}
			first = false;
		}
	}
	return true;
}

bool
dns_name_iswildcard(const dns_name_t *name) {
	unsigned char *ndata;

	/*
	 * Is 'name' a wildcard name?
	 */

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(name->length > 0);

	if (name->length >= 2) {
		ndata = name->ndata;
		if (ndata[0] == 1 && ndata[1] == '*') {
			return true;
		}
	}

	return false;
}

bool
dns_name_internalwildcard(const dns_name_t *name) {
	unsigned char *ndata;
	unsigned int count;
	unsigned int label;

	/*
	 * Does 'name' contain a internal wildcard?
	 */

	REQUIRE(DNS_NAME_VALID(name));

	/*
	 * Skip first label.
	 */
	ndata = name->ndata;
	count = *ndata++;
	INSIST(count <= DNS_NAME_LABELLEN);
	ndata += count;
	label = 1;

	uint8_t labels = dns_name_countlabels(name);
	while (label + 1 < labels) {
		count = *ndata++;
		INSIST(count <= DNS_NAME_LABELLEN);

		if (count == 1 && *ndata == '*') {
			return true;
		}
		ndata += count;
		label++;
	}
	return false;
}

uint32_t
dns_name_hash(const dns_name_t *name) {
	REQUIRE(DNS_NAME_VALID(name));

	return isc_hash32(name->ndata, name->length, false);
}

dns_namereln_t
dns_name_fullcompare(const dns_name_t *name1, const dns_name_t *name2,
		     int *orderp, unsigned int *nlabelsp) {
	unsigned int l1, l2, l, count1, count2, count, nlabels;
	int cdiff, ldiff, diff;
	unsigned char *label1, *label2;
	dns_offsets_t offsets1, offsets2;
	dns_namereln_t namereln = dns_namereln_none;

	/*
	 * Determine the relative ordering under the DNSSEC order relation of
	 * 'name1' and 'name2', and also determine the hierarchical
	 * relationship of the names.
	 *
	 * Note: It makes no sense for one of the names to be relative and the
	 * other absolute.  If both names are relative, then to be meaningfully
	 * compared the caller must ensure that they are both relative to the
	 * same domain.
	 */

	REQUIRE(DNS_NAME_VALID(name1));
	REQUIRE(DNS_NAME_VALID(name2));
	REQUIRE(orderp != NULL);
	REQUIRE(nlabelsp != NULL);
	/*
	 * Either name1 is absolute and name2 is absolute, or neither is.
	 */
	REQUIRE((name1->attributes.absolute) == (name2->attributes.absolute));

	if (name1 == name2) {
		*orderp = 0;
		*nlabelsp = dns_name_countlabels(name1);

		return dns_namereln_equal;
	}

	l1 = dns_name_offsets(name1, offsets1);
	l2 = dns_name_offsets(name2, offsets2);

	nlabels = 0;
	if (l2 > l1) {
		l = l1;
		ldiff = 0 - (l2 - l1);
	} else {
		l = l2;
		ldiff = l1 - l2;
	}

	while (l-- > 0) {
		l1--;
		l2--;
		label1 = &name1->ndata[offsets1[l1]];
		label2 = &name2->ndata[offsets2[l2]];
		count1 = *label1++;
		count2 = *label2++;

		cdiff = (int)count1 - (int)count2;
		if (cdiff < 0) {
			count = count1;
		} else {
			count = count2;
		}

		diff = isc_ascii_lowercmp(label1, label2, count);
		if (diff != 0) {
			*orderp = diff;
			goto done;
		}

		if (cdiff != 0) {
			*orderp = cdiff;
			goto done;
		}
		nlabels++;
	}

	*orderp = ldiff;
	if (ldiff < 0) {
		namereln = dns_namereln_contains;
	} else if (ldiff > 0) {
		namereln = dns_namereln_subdomain;
	} else {
		namereln = dns_namereln_equal;
	}
	*nlabelsp = nlabels;
	return namereln;

done:
	*nlabelsp = nlabels;
	if (nlabels > 0) {
		namereln = dns_namereln_commonancestor;
	}

	return namereln;
}

int
dns_name_compare(const dns_name_t *name1, const dns_name_t *name2) {
	int order;
	unsigned int nlabels;

	/*
	 * Determine the relative ordering under the DNSSEC order relation of
	 * 'name1' and 'name2'.
	 *
	 * Note: It makes no sense for one of the names to be relative and the
	 * other absolute.  If both names are relative, then to be meaningfully
	 * compared the caller must ensure that they are both relative to the
	 * same domain.
	 */

	(void)dns_name_fullcompare(name1, name2, &order, &nlabels);

	return order;
}

bool
dns_name_equal(const dns_name_t *name1, const dns_name_t *name2) {
	unsigned int length;

	/*
	 * Are 'name1' and 'name2' equal?
	 *
	 * Note: It makes no sense for one of the names to be relative and the
	 * other absolute.  If both names are relative, then to be meaningfully
	 * compared the caller must ensure that they are both relative to the
	 * same domain.
	 */

	REQUIRE(DNS_NAME_VALID(name1));
	REQUIRE(DNS_NAME_VALID(name2));
	/*
	 * Either name1 is absolute and name2 is absolute, or neither is.
	 */
	REQUIRE((name1->attributes.absolute) == (name2->attributes.absolute));

	if (name1 == name2) {
		return true;
	}

	length = name1->length;
	if (length != name2->length) {
		return false;
	}

	/* label lengths are < 64 so tolower() does not affect them */
	return isc_ascii_lowerequal(name1->ndata, name2->ndata, length);
}

bool
dns_name_caseequal(const dns_name_t *name1, const dns_name_t *name2) {
	/*
	 * Are 'name1' and 'name2' equal?
	 *
	 * Note: It makes no sense for one of the names to be relative and the
	 * other absolute.  If both names are relative, then to be meaningfully
	 * compared the caller must ensure that they are both relative to the
	 * same domain.
	 */

	REQUIRE(DNS_NAME_VALID(name1));
	REQUIRE(DNS_NAME_VALID(name2));
	/*
	 * Either name1 is absolute and name2 is absolute, or neither is.
	 */
	REQUIRE((name1->attributes.absolute) == (name2->attributes.absolute));

	if (name1->length != name2->length) {
		return false;
	}

	if (memcmp(name1->ndata, name2->ndata, name1->length) != 0) {
		return false;
	}

	return true;
}

int
dns_name_rdatacompare(const dns_name_t *name1, const dns_name_t *name2) {
	/*
	 * Compare two absolute names as rdata.
	 */

	REQUIRE(DNS_NAME_VALID(name1));
	REQUIRE(name1->length > 0);
	REQUIRE(name1->attributes.absolute);
	REQUIRE(DNS_NAME_VALID(name2));
	REQUIRE(name2->length > 0);
	REQUIRE(name2->attributes.absolute);

	/* label lengths are < 64 so tolower() does not affect them */
	return isc_ascii_lowercmp(name1->ndata, name2->ndata,
				  ISC_MIN(name1->length, name2->length));
}

bool
dns_name_issubdomain(const dns_name_t *name1, const dns_name_t *name2) {
	int order;
	unsigned int nlabels;
	dns_namereln_t namereln;

	/*
	 * Is 'name1' a subdomain of 'name2'?
	 *
	 * Note: It makes no sense for one of the names to be relative and the
	 * other absolute.  If both names are relative, then to be meaningfully
	 * compared the caller must ensure that they are both relative to the
	 * same domain.
	 */

	namereln = dns_name_fullcompare(name1, name2, &order, &nlabels);
	if (namereln == dns_namereln_subdomain ||
	    namereln == dns_namereln_equal)
	{
		return true;
	}

	return false;
}

bool
dns_name_matcheswildcard(const dns_name_t *name, const dns_name_t *wname) {
	int order;
	unsigned int nlabels, labels;
	dns_name_t tname;

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(name->length > 0);
	REQUIRE(DNS_NAME_VALID(wname));
	labels = dns_name_countlabels(wname);
	REQUIRE(labels > 0);
	REQUIRE(dns_name_iswildcard(wname));

	dns_name_init(&tname);
	dns_name_getlabelsequence(wname, 1, labels - 1, &tname);
	if (dns_name_fullcompare(name, &tname, &order, &nlabels) ==
	    dns_namereln_subdomain)
	{
		return true;
	}
	return false;
}

void
dns_name_getlabel(const dns_name_t *name, unsigned int n, dns_label_t *label) {
	dns_offsets_t offsets;

	/*
	 * Make 'label' refer to the 'n'th least significant label of 'name'.
	 */

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(label != NULL);

	uint8_t labels = dns_name_offsets(name, offsets);

	REQUIRE(labels > 0);
	REQUIRE(n < labels);

	label->base = &name->ndata[offsets[n]];
	if (n == (unsigned int)labels - 1) {
		label->length = name->length - offsets[n];
	} else {
		label->length = offsets[n + 1] - offsets[n];
	}
}

void
dns_name_getlabelsequence(const dns_name_t *source, unsigned int first,
			  unsigned int n, dns_name_t *target) {
	unsigned char *p, l;
	unsigned int firstoffset, endoffset;
	unsigned int i;

	/*
	 * Make 'target' refer to the 'n' labels including and following
	 * 'first' in 'source'.
	 */

	REQUIRE(DNS_NAME_VALID(source));
	REQUIRE(DNS_NAME_VALID(target));
	REQUIRE(DNS_NAME_BINDABLE(target));

	uint8_t labels = dns_name_countlabels(source);
	REQUIRE(first <= labels && n <= labels - first);

	p = source->ndata;
	if (first == labels) {
		firstoffset = source->length;
	} else {
		for (i = 0; i < first; i++) {
			l = *p;
			p += l + 1;
		}
		firstoffset = (unsigned int)(p - source->ndata);
	}

	if (first + n == labels) {
		endoffset = source->length;
	} else {
		for (i = 0; i < n; i++) {
			l = *p;
			p += l + 1;
		}
		endoffset = (unsigned int)(p - source->ndata);
	}

	target->ndata = &source->ndata[firstoffset];
	target->length = endoffset - firstoffset;

	if (first + n == labels && n > 0 && source->attributes.absolute) {
		target->attributes.absolute = true;
	} else {
		target->attributes.absolute = false;
	}
}

void
dns_name_clone(const dns_name_t *source, dns_name_t *target) {
	/*
	 * Make 'target' refer to the same name as 'source'.
	 */

	REQUIRE(DNS_NAME_VALID(source));
	REQUIRE(DNS_NAME_VALID(target));
	REQUIRE(DNS_NAME_BINDABLE(target));

	target->ndata = source->ndata;
	target->length = source->length;
	target->attributes = source->attributes;
	target->attributes.readonly = false;
	target->attributes.dynamic = false;
}

void
dns_name_fromregion(dns_name_t *name, const isc_region_t *r) {
	size_t length;
	isc_region_t r2 = { .base = NULL, .length = 0 };

	/*
	 * Make 'name' refer to region 'r'.
	 */

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(r != NULL);
	REQUIRE(DNS_NAME_BINDABLE(name));

	name->ndata = r->base;
	if (name->buffer != NULL) {
		isc_buffer_clear(name->buffer);
		isc_buffer_availableregion(name->buffer, &r2);
		length = (r->length < r2.length) ? r->length : r2.length;
		if (length > DNS_NAME_MAXWIRE) {
			length = DNS_NAME_MAXWIRE;
		}
	} else {
		length = (r->length <= DNS_NAME_MAXWIRE) ? r->length
							 : DNS_NAME_MAXWIRE;
	}

	name->attributes.absolute = false;

	if (length > 0) {
		size_t offset = 0;
		uint8_t nlabels = 0;
		while (offset != length) {
			uint8_t count;

			INSIST(nlabels < DNS_NAME_MAXLABELS);
			nlabels++;

			count = name->ndata[offset];
			INSIST(count <= DNS_NAME_LABELLEN);

			offset += count + 1;
			INSIST(offset <= length);

			if (count == 0) {
				name->attributes.absolute = true;
				break;
			}
		}
		name->length = offset;
	}

	if (name->buffer != NULL) {
		/*
		 * name->length has been updated by set_offsets to the actual
		 * length of the name data so we can now copy the actual name
		 * data and not anything after it.
		 */
		if (name->length > 0) {
			memmove(r2.base, r->base, name->length);
		}
		name->ndata = r2.base;
		isc_buffer_add(name->buffer, name->length);
	}
}

static isc_result_t
convert_text(isc_buffer_t *source, const dns_name_t *origin,
	     unsigned int options, dns_name_t *name, isc_buffer_t *target) {
	unsigned char *ndata = NULL, *label = NULL;
	char *tdata = NULL;
	char c;
	ft_state state;
	unsigned int value = 0, count = 0;
	unsigned int n1 = 0, n2 = 0;
	unsigned int tlen, nrem, nused, digits = 0, labels, tused;
	bool done;
	bool downcase;

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(ISC_BUFFER_VALID(source));
	REQUIRE(ISC_BUFFER_VALID(target));

	downcase = ((options & DNS_NAME_DOWNCASE) != 0);

	if (target == NULL && name->buffer != NULL) {
		target = name->buffer;
		isc_buffer_clear(target);
	}

	REQUIRE(DNS_NAME_BINDABLE(name));

	/*
	 * Set up the state machine.
	 */
	tdata = (char *)source->base + source->current;
	tlen = isc_buffer_remaininglength(source);
	tused = 0;
	ndata = isc_buffer_used(target);
	nrem = isc_buffer_availablelength(target);
	if (nrem > DNS_NAME_MAXWIRE) {
		nrem = DNS_NAME_MAXWIRE;
	}
	nused = 0;
	labels = 0;
	done = false;
	state = ft_init;

	while (nrem > 0 && tlen > 0 && !done) {
		c = *tdata++;
		tlen--;
		tused++;

		switch (state) {
		case ft_init:
			/*
			 * Is this the root name?
			 */
			if (c == '.') {
				if (tlen != 0) {
					return DNS_R_EMPTYLABEL;
				}
				labels++;
				*ndata++ = 0;
				nrem--;
				nused++;
				done = true;
				break;
			}
			if (c == '@' && tlen == 0) {
				state = ft_at;
				break;
			}

			FALLTHROUGH;
		case ft_start:
			label = ndata;
			ndata++;
			nrem--;
			nused++;
			count = 0;
			if (c == '\\') {
				state = ft_initialescape;
				break;
			}
			state = ft_ordinary;
			if (nrem == 0) {
				return ISC_R_NOSPACE;
			}
			FALLTHROUGH;
		case ft_ordinary:
			if (c == '.') {
				if (count == 0) {
					return DNS_R_EMPTYLABEL;
				}
				*label = count;
				labels++;
				INSIST(labels < DNS_NAME_MAXLABELS);
				if (tlen == 0) {
					labels++;
					*ndata++ = 0;
					nrem--;
					nused++;
					done = true;
				}
				state = ft_start;
			} else if (c == '\\') {
				state = ft_escape;
			} else {
				if (count >= DNS_NAME_LABELLEN) {
					return DNS_R_LABELTOOLONG;
				}
				count++;
				if (downcase) {
					c = isc_ascii_tolower(c);
				}
				*ndata++ = c;
				nrem--;
				nused++;
			}
			break;
		case ft_initialescape:
			if (c == '[') {
				/*
				 * This looks like a bitstring label, which
				 * was deprecated.  Intentionally drop it.
				 */
				return DNS_R_BADLABELTYPE;
			}
			state = ft_escape;
			POST(state);
			FALLTHROUGH;
		case ft_escape:
			if (!isdigit((unsigned char)c)) {
				if (count >= DNS_NAME_LABELLEN) {
					return DNS_R_LABELTOOLONG;
				}
				count++;
				if (downcase) {
					c = isc_ascii_tolower(c);
				}
				*ndata++ = c;
				nrem--;
				nused++;
				state = ft_ordinary;
				break;
			}
			digits = 0;
			value = 0;
			state = ft_escdecimal;
			FALLTHROUGH;
		case ft_escdecimal:
			if (!isdigit((unsigned char)c)) {
				return DNS_R_BADESCAPE;
			}
			value = 10 * value + c - '0';
			digits++;
			if (digits == 3) {
				if (value > 255) {
					return DNS_R_BADESCAPE;
				}
				if (count >= DNS_NAME_LABELLEN) {
					return DNS_R_LABELTOOLONG;
				}
				count++;
				if (downcase) {
					value = isc_ascii_tolower(value);
				}
				*ndata++ = value;
				nrem--;
				nused++;
				state = ft_ordinary;
			}
			break;
		default:
			FATAL_ERROR("Unexpected state %d", state);
			/* Does not return. */
		}
	}

	if (!done) {
		if (nrem == 0) {
			return ISC_R_NOSPACE;
		}
		INSIST(tlen == 0);
		if (state != ft_ordinary && state != ft_at) {
			return ISC_R_UNEXPECTEDEND;
		}
		if (state == ft_ordinary) {
			INSIST(count != 0);
			INSIST(label != NULL);
			*label = count;
			labels++;
			INSIST(labels < DNS_NAME_MAXLABELS);
		}
		if (origin != NULL) {
			if (nrem < origin->length) {
				return ISC_R_NOSPACE;
			}
			label = origin->ndata;
			n1 = origin->length;
			nrem -= n1;
			POST(nrem);
			while (n1 > 0) {
				n2 = *label++;
				INSIST(n2 <= DNS_NAME_LABELLEN);
				*ndata++ = n2;
				n1 -= n2 + 1;
				nused += n2 + 1;
				while (n2 > 0) {
					c = *label++;
					if (downcase) {
						c = isc_ascii_tolower(c);
					}
					*ndata++ = c;
					n2--;
				}
				labels++;
				if (n1 > 0) {
					INSIST(labels < DNS_NAME_MAXLABELS);
				}
			}
			if (origin->attributes.absolute) {
				name->attributes.absolute = true;
			}
		}
	} else {
		name->attributes.absolute = true;
	}

	name->ndata = (unsigned char *)target->base + target->used;
	name->length = nused;

	isc_buffer_forward(source, tused);
	isc_buffer_add(target, name->length);

	return ISC_R_SUCCESS;
}

isc_result_t
dns_name_wirefromtext(isc_buffer_t *source, const dns_name_t *origin,
		      unsigned int options, isc_buffer_t *target) {
	dns_name_t name;

	REQUIRE(ISC_BUFFER_VALID(target));

	dns_name_init(&name);
	return convert_text(source, origin, options, &name, target);
}

isc_result_t
dns_name_fromtext(dns_name_t *name, isc_buffer_t *source,
		  const dns_name_t *origin, unsigned int options) {
	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(ISC_BUFFER_VALID(name->buffer));

	isc_buffer_clear(name->buffer);
	return convert_text(source, origin, options, name, name->buffer);
}

isc_result_t
dns_name_totext(const dns_name_t *name, unsigned int options,
		isc_buffer_t *target) {
	unsigned char *ndata;
	char *tdata;
	unsigned int nlen, tlen;
	unsigned char c;
	unsigned int trem, count;
	unsigned int labels;
	bool saw_root = false;
	unsigned int oused;
	bool omit_final_dot = ((options & DNS_NAME_OMITFINALDOT) != 0);

	/*
	 * This function assumes the name is in proper uncompressed
	 * wire format.
	 */
	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(ISC_BUFFER_VALID(target));

	oused = target->used;

	ndata = name->ndata;
	nlen = name->length;
	labels = dns_name_countlabels(name);
	tdata = isc_buffer_used(target);
	tlen = isc_buffer_availablelength(target);

	trem = tlen;

	if (labels == 0 && nlen == 0) {
		/*
		 * Special handling for an empty name.
		 */
		if (trem == 0) {
			return ISC_R_NOSPACE;
		}

		/*
		 * The names of these booleans are misleading in this case.
		 * This empty name is not necessarily from the root node of
		 * the DNS root zone, nor is a final dot going to be included.
		 * They need to be set this way, though, to keep the "@"
		 * from being trounced.
		 */
		saw_root = true;
		omit_final_dot = false;
		*tdata++ = '@';
		trem--;

		/*
		 * Skip the while() loop.
		 */
		nlen = 0;
	} else if (nlen == 1 && labels == 1 && *ndata == '\0') {
		/*
		 * Special handling for the root label.
		 */
		if (trem == 0) {
			return ISC_R_NOSPACE;
		}

		saw_root = true;
		omit_final_dot = false;
		*tdata++ = '.';
		trem--;

		/*
		 * Skip the while() loop.
		 */
		nlen = 0;
	}

	while (labels > 0 && nlen > 0 && trem > 0) {
		labels--;
		count = *ndata++;
		nlen--;
		if (count == 0) {
			saw_root = true;
			break;
		}
		if (count <= DNS_NAME_LABELLEN) {
			INSIST(nlen >= count);
			while (count > 0) {
				c = *ndata;
				switch (c) {
				/* Special modifiers in zone files. */
				case 0x40: /* '@' */
				case 0x24: /* '$' */
					if ((options & DNS_NAME_PRINCIPAL) != 0)
					{
						goto no_escape;
					}
					FALLTHROUGH;
				case 0x22: /* '"' */
				case 0x28: /* '(' */
				case 0x29: /* ')' */
				case 0x2E: /* '.' */
				case 0x3B: /* ';' */
				case 0x5C: /* '\\' */
					if (trem < 2) {
						return ISC_R_NOSPACE;
					}
					*tdata++ = '\\';
					*tdata++ = c;
					ndata++;
					trem -= 2;
					nlen--;
					break;
				no_escape:
				default:
					if (c > 0x20 && c < 0x7f) {
						if (trem == 0) {
							return ISC_R_NOSPACE;
						}
						*tdata++ = c;
						ndata++;
						trem--;
						nlen--;
					} else {
						if (trem < 4) {
							return ISC_R_NOSPACE;
						}
						*tdata++ = 0x5c;
						*tdata++ = 0x30 +
							   ((c / 100) % 10);
						*tdata++ = 0x30 +
							   ((c / 10) % 10);
						*tdata++ = 0x30 + (c % 10);
						trem -= 4;
						ndata++;
						nlen--;
					}
				}
				count--;
			}
		} else {
			FATAL_ERROR("Unexpected label type %02x", count);
			UNREACHABLE();
		}

		/*
		 * The following assumes names are absolute.  If not, we
		 * fix things up later.  Note that this means that in some
		 * cases one more byte of text buffer is required than is
		 * needed in the final output.
		 */
		if (trem == 0) {
			return ISC_R_NOSPACE;
		}
		*tdata++ = '.';
		trem--;
	}

	if (nlen != 0 && trem == 0) {
		return ISC_R_NOSPACE;
	}

	if (!saw_root || omit_final_dot) {
		trem++;
		tdata--;
	}
	if (trem > 0) {
		*tdata = 0;
	}
	isc_buffer_add(target, tlen - trem);

	if (totext_filter_proc != NULL) {
		return (totext_filter_proc)(target, oused);
	}

	return ISC_R_SUCCESS;
}

isc_result_t
dns_name_tofilenametext(const dns_name_t *name, bool omit_final_dot,
			isc_buffer_t *target) {
	unsigned char *ndata;
	char *tdata;
	unsigned int nlen, tlen;
	unsigned char c;
	unsigned int trem, count;
	unsigned int labels;

	/*
	 * This function assumes the name is in proper uncompressed
	 * wire format.
	 */
	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(name->attributes.absolute);
	REQUIRE(ISC_BUFFER_VALID(target));

	ndata = name->ndata;
	nlen = name->length;
	labels = dns_name_countlabels(name);
	tdata = isc_buffer_used(target);
	tlen = isc_buffer_availablelength(target);

	trem = tlen;

	if (nlen == 1 && labels == 1 && *ndata == '\0') {
		/*
		 * Special handling for the root label.
		 */
		if (trem == 0) {
			return ISC_R_NOSPACE;
		}

		omit_final_dot = false;
		*tdata++ = '.';
		trem--;

		/*
		 * Skip the while() loop.
		 */
		nlen = 0;
	}

	while (labels > 0 && nlen > 0 && trem > 0) {
		labels--;
		count = *ndata++;
		nlen--;
		if (count == 0) {
			break;
		}
		if (count <= DNS_NAME_LABELLEN) {
			INSIST(nlen >= count);
			while (count > 0) {
				c = *ndata;
				if ((c >= 0x30 && c <= 0x39) || /* digit */
				    (c >= 0x41 && c <= 0x5A) || /* uppercase */
				    (c >= 0x61 && c <= 0x7A) || /* lowercase */
				    c == 0x2D ||		/* hyphen */
				    c == 0x5F)			/* underscore */
				{
					if (trem == 0) {
						return ISC_R_NOSPACE;
					}
					/* downcase */
					if (c >= 0x41 && c <= 0x5A) {
						c += 0x20;
					}
					*tdata++ = c;
					ndata++;
					trem--;
					nlen--;
				} else {
					if (trem < 4) {
						return ISC_R_NOSPACE;
					}
					snprintf(tdata, trem, "%%%02X", c);
					tdata += 3;
					trem -= 3;
					ndata++;
					nlen--;
				}
				count--;
			}
		} else {
			FATAL_ERROR("Unexpected label type %02x", count);
			UNREACHABLE();
		}

		/*
		 * The following assumes names are absolute.  If not, we
		 * fix things up later.  Note that this means that in some
		 * cases one more byte of text buffer is required than is
		 * needed in the final output.
		 */
		if (trem == 0) {
			return ISC_R_NOSPACE;
		}
		*tdata++ = '.';
		trem--;
	}

	if (nlen != 0 && trem == 0) {
		return ISC_R_NOSPACE;
	}

	if (omit_final_dot) {
		trem++;
	}

	isc_buffer_add(target, tlen - trem);

	return ISC_R_SUCCESS;
}

isc_result_t
dns_name_downcase(const dns_name_t *source, dns_name_t *name) {
	/*
	 * Downcase 'source'.
	 */

	REQUIRE(DNS_NAME_VALID(source));
	REQUIRE(DNS_NAME_VALID(name));

	if (source == name) {
		REQUIRE(!name->attributes.readonly);
		isc_ascii_lowercopy(name->ndata, source->ndata, source->length);
		return ISC_R_SUCCESS;
	}

	REQUIRE(DNS_NAME_BINDABLE(name));
	REQUIRE(ISC_BUFFER_VALID(name->buffer));

	isc_buffer_clear(name->buffer);
	name->ndata = (uint8_t *)name->buffer->base + name->buffer->used;

	/* label lengths are < 64 so tolower() does not affect them */
	isc_ascii_lowercopy(name->ndata, source->ndata, source->length);

	name->length = source->length;
	name->attributes = (struct dns_name_attrs){
		.absolute = source->attributes.absolute
	};
	isc_buffer_add(name->buffer, name->length);

	return ISC_R_SUCCESS;
}

isc_result_t
dns_name_fromwire(dns_name_t *const name, isc_buffer_t *const source,
		  const dns_decompress_t dctx, isc_buffer_t *target) {
	/*
	 * Copy the name at source into target, decompressing it.
	 *
	 *	*** WARNING ***
	 *
	 * dns_name_fromwire() deals with raw network data. An error in this
	 * routine could result in the failure or hijacking of the server.
	 *
	 * The description of name compression in RFC 1035 section 4.1.4 is
	 * subtle wrt certain edge cases. The first important sentence is:
	 *
	 * > In this scheme, an entire domain name or a list of labels at the
	 * > end of a domain name is replaced with a pointer to a prior
	 * > occurance of the same name.
	 *
	 * The key word is "prior". This says that compression pointers must
	 * point strictly earlier in the message (before our "marker" variable),
	 * which is enough to prevent DoS attacks due to compression loops.
	 *
	 * The next important sentence is:
	 *
	 * > If a domain name is contained in a part of the message subject to a
	 * > length field (such as the RDATA section of an RR), and compression
	 * > is used, the length of the compressed name is used in the length
	 * > calculation, rather than the length of the expanded name.
	 *
	 * When decompressing, this means that the amount of the source buffer
	 * that we consumed (which is checked wrt the container's length field)
	 * is the length of the compressed name. A compressed name is defined as
	 * a sequence of labels ending with the root label or a compression
	 * pointer, that is, the segment of the name that dns_name_fromwire()
	 * examines first.
	 *
	 * This matters when handling names that play dirty tricks, like:
	 *
	 *	+---+---+---+---+---+---+
	 *	| 4 | 1 |'a'|192| 0 | 0 |
	 *	+---+---+---+---+---+---+
	 *
	 * We start at octet 1. There is an ordinary single character label "a",
	 * followed by a compression pointer that refers back to octet zero.
	 * Here there is a label of length 4, which weirdly re-uses the octets
	 * we already examined as the data for the label. It is followed by the
	 * root label,
	 *
	 * The specification says that the compressed name ends after the first
	 * zero octet (after the compression pointer) not the second zero octet,
	 * even though the second octet is later in the message. This shows the
	 * correct way to set our "consumed" variable.
	 */

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(DNS_NAME_BINDABLE(name));
	REQUIRE((target != NULL && ISC_BUFFER_VALID(target)) ||
		(target == NULL && ISC_BUFFER_VALID(name->buffer)));

	if (target == NULL && name->buffer != NULL) {
		target = name->buffer;
		isc_buffer_clear(target);
	}

	uint8_t *const name_buf = isc_buffer_used(target);
	const uint32_t name_max = ISC_MIN(DNS_NAME_MAXWIRE,
					  isc_buffer_availablelength(target));
	uint32_t name_len = 0;

	/*
	 * After chasing a compression pointer, these variables refer to the
	 * source buffer as follows:
	 *
	 * sb --- mr --- cr --- st --- cd --- sm
	 *
	 * sb = source_buf (const)
	 * mr = marker
	 * cr = cursor
	 * st = start (const)
	 * cd = consumed
	 * sm = source_max (const)
	 *
	 * The marker hops backwards for each pointer.
	 * The cursor steps forwards for each label.
	 * The amount of the source we consumed is set once.
	 */
	const uint8_t *const source_buf = isc_buffer_base(source);
	const uint8_t *const source_max = isc_buffer_used(source);
	const uint8_t *const start = isc_buffer_current(source);
	const uint8_t *marker = start;
	const uint8_t *cursor = start;
	const uint8_t *consumed = NULL;

	/*
	 * One iteration per label.
	 */
	while (cursor < source_max) {
		const uint8_t label_len = *cursor++;
		if (label_len <= DNS_NAME_LABELLEN) {
			/*
			 * Normal label: record its offset, and check bounds on
			 * the name length, which also ensures we don't overrun
			 * the offsets array. Don't touch any source bytes yet!
			 * The source bounds check will happen when we loop.
			 */
			/* and then a step to the ri-i-i-i-i-ight */
			cursor += label_len;
			name_len += label_len + 1;
			if (name_len > name_max) {
				return name_max == DNS_NAME_MAXWIRE
					       ? DNS_R_NAMETOOLONG
					       : ISC_R_NOSPACE;
			} else if (label_len == 0) {
				goto root_label;
			}
		} else if (label_len < 192) {
			return DNS_R_BADLABELTYPE;
		} else if (!dns_decompress_getpermitted(dctx)) {
			return DNS_R_DISALLOWED;
		} else if (cursor < source_max) {
			/*
			 * Compression pointer. Ensure it does not loop.
			 *
			 * Copy multiple labels in one go, to make the most of
			 * memmove() performance. Start at the marker and finish
			 * just before the pointer's hi+lo bytes, before the
			 * cursor. Bounds were already checked.
			 */
			const uint32_t hi = label_len & 0x3F;
			const uint32_t lo = *cursor++;
			const uint8_t *pointer = source_buf + (256 * hi + lo);
			if (pointer >= marker) {
				return DNS_R_BADPOINTER;
			}
			const uint32_t copy_len = (cursor - 2) - marker;
			uint8_t *const dest = name_buf + name_len - copy_len;
			memmove(dest, marker, copy_len);
			consumed = consumed != NULL ? consumed : cursor;
			/* it's just a jump to the left */
			cursor = marker = pointer;
		}
	}
	return ISC_R_UNEXPECTEDEND;
root_label:;
	/*
	 * Copy labels almost like we do for compression pointers,
	 * from the marker up to and including the root label.
	 */
	const uint32_t copy_len = cursor - marker;
	memmove(name_buf + name_len - copy_len, marker, copy_len);
	consumed = consumed != NULL ? consumed : cursor;
	isc_buffer_forward(source, consumed - start);

	name->attributes.absolute = true;
	name->ndata = name_buf;
	name->length = name_len;
	isc_buffer_add(target, name_len);

	return ISC_R_SUCCESS;
}

isc_result_t
dns_name_towire(const dns_name_t *name, dns_compress_t *cctx,
		isc_buffer_t *target) {
	bool compress, multi;
	unsigned int here;
	unsigned int prefix_length;
	unsigned int suffix_coff;

	/*
	 * Convert 'name' into wire format, compressing it as specified by the
	 * compression context 'cctx' (or without compressing if 'cctx'
	 * is NULL), and storing the result in 'target'.
	 */

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(ISC_BUFFER_VALID(target));

	if (cctx == NULL) {
		if (isc_buffer_availablelength(target) < name->length) {
			return ISC_R_NOSPACE;
		}
		memmove(isc_buffer_used(target), name->ndata, name->length);
		isc_buffer_add(target, name->length);
		return ISC_R_SUCCESS;
	}

	compress = !name->attributes.nocompress &&
		   dns_compress_getpermitted(cctx);
	multi = compress && dns_compress_getmultiuse(cctx);

	/*
	 * Write a compression pointer directly if the caller passed us
	 * a pointer to this name's offset that we saved previously.
	 */
	if (multi && cctx->coff < 0x4000) {
		if (isc_buffer_availablelength(target) < 2) {
			return ISC_R_NOSPACE;
		}
		isc_buffer_putuint16(target, cctx->coff | 0xc000);
		return ISC_R_SUCCESS;
	}

	/*
	 * Always add the name to the compression context; if compression
	 * is off, reset the return values before writing the name.
	 */
	prefix_length = name->length;
	suffix_coff = 0;
	dns_compress_name(cctx, target, name, &prefix_length, &suffix_coff);
	if (!compress) {
		prefix_length = name->length;
		suffix_coff = 0;
	}

	/*
	 * Return this name's compression offset for use next time, provided
	 * it isn't too short for compression to help (i.e. it's the root)
	 */
	here = isc_buffer_usedlength(target);
	if (multi && here < 0x4000 && prefix_length > 1) {
		cctx->coff = (uint16_t)here;
	}

	if (prefix_length > 0) {
		if (isc_buffer_availablelength(target) < prefix_length) {
			return ISC_R_NOSPACE;
		}
		memmove(isc_buffer_used(target), name->ndata, prefix_length);
		isc_buffer_add(target, prefix_length);
	}

	if (suffix_coff > 0) {
		if (multi && prefix_length == 0) {
			cctx->coff = suffix_coff;
		}
		if (isc_buffer_availablelength(target) < 2) {
			return ISC_R_NOSPACE;
		}
		isc_buffer_putuint16(target, suffix_coff | 0xc000);
	}

	return ISC_R_SUCCESS;
}

isc_result_t
dns_name_concatenate(const dns_name_t *prefix, const dns_name_t *suffix,
		     dns_name_t *name) {
	unsigned char *ndata = NULL;
	unsigned int nrem, prefix_length, length;
	bool copy_prefix = true;
	bool copy_suffix = true;
	bool absolute = false;
	dns_name_t tmp_name;
	isc_buffer_t *target = NULL;

	/*
	 * Concatenate 'prefix' and 'suffix'.
	 */

	REQUIRE(prefix == NULL || DNS_NAME_VALID(prefix));
	REQUIRE(suffix == NULL || DNS_NAME_VALID(suffix));
	REQUIRE(DNS_NAME_VALID(name) && ISC_BUFFER_VALID(name->buffer));
	REQUIRE(DNS_NAME_BINDABLE(name));

	if (prefix == NULL || prefix->length == 0) {
		copy_prefix = false;
	}
	if (suffix == NULL || suffix->length == 0) {
		copy_suffix = false;
	}
	if (copy_prefix && prefix->attributes.absolute) {
		absolute = true;
		REQUIRE(!copy_suffix);
	}
	if (name == NULL) {
		dns_name_init(&tmp_name);
		name = &tmp_name;
	}

	target = name->buffer;
	isc_buffer_clear(target);

	/*
	 * Set up.
	 */
	nrem = target->length - target->used;
	ndata = (unsigned char *)target->base + target->used;
	if (nrem > DNS_NAME_MAXWIRE) {
		nrem = DNS_NAME_MAXWIRE;
	}
	length = 0;
	prefix_length = 0;
	if (copy_prefix) {
		prefix_length = prefix->length;
		length += prefix_length;
	}
	if (copy_suffix) {
		length += suffix->length;
	}
	if (length > DNS_NAME_MAXWIRE) {
		return DNS_R_NAMETOOLONG;
	}
	if (length > nrem) {
		return ISC_R_NOSPACE;
	}

	if (copy_suffix) {
		if (suffix->attributes.absolute) {
			absolute = true;
		}
		memmove(ndata + prefix_length, suffix->ndata, suffix->length);
	}

	/*
	 * If 'prefix' and 'name' are the same object, we don't have to
	 * copy anything.
	 */
	if (copy_prefix && (prefix != name || prefix->buffer != target)) {
		memmove(ndata, prefix->ndata, prefix_length);
	}

	name->ndata = ndata;
	name->length = length;
	name->attributes.absolute = absolute;

	isc_buffer_add(target, name->length);

	return ISC_R_SUCCESS;
}

void
dns_name_dup(const dns_name_t *source, isc_mem_t *mctx, dns_name_t *target) {
	/*
	 * Make 'target' a dynamically allocated copy of 'source'.
	 */

	REQUIRE(DNS_NAME_VALID(source));
	REQUIRE(source->length > 0);
	REQUIRE(DNS_NAME_VALID(target));
	REQUIRE(DNS_NAME_BINDABLE(target));

	target->ndata = isc_mem_get(mctx, source->length);

	memmove(target->ndata, source->ndata, source->length);

	target->length = source->length;
	target->attributes = (struct dns_name_attrs){ .dynamic = true };
	target->attributes.absolute = source->attributes.absolute;
}

void
dns_name_free(dns_name_t *name, isc_mem_t *mctx) {
	size_t size;

	/*
	 * Free 'name'.
	 */

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(name->attributes.dynamic);

	size = name->length;
	isc_mem_put(mctx, name->ndata, size);
	dns_name_invalidate(name);
}

size_t
dns_name_size(const dns_name_t *name) {
	size_t size;

	REQUIRE(DNS_NAME_VALID(name));

	if (!name->attributes.dynamic) {
		return 0;
	}

	size = name->length;

	return size;
}

isc_result_t
dns_name_digest(const dns_name_t *name, dns_digestfunc_t digest, void *arg) {
	/*
	 * Send 'name' in DNSSEC canonical form to 'digest'.
	 */

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(digest != NULL);

	unsigned char ndata[DNS_NAME_MAXWIRE];
	isc_ascii_lowercopy(ndata, name->ndata, name->length);

	isc_region_t r = {
		.base = ndata,
		.length = name->length,
	};
	return (digest)(arg, &r);
}

bool
dns_name_dynamic(const dns_name_t *name) {
	REQUIRE(DNS_NAME_VALID(name));

	/*
	 * Returns whether there is dynamic memory associated with this name.
	 */

	return name->attributes.dynamic;
}

isc_result_t
dns_name_print(const dns_name_t *name, FILE *stream) {
	isc_result_t result;
	isc_buffer_t b;
	isc_region_t r;
	char t[1024];

	/*
	 * Print 'name' on 'stream'.
	 */

	REQUIRE(DNS_NAME_VALID(name));

	isc_buffer_init(&b, t, sizeof(t));
	result = dns_name_totext(name, 0, &b);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	isc_buffer_usedregion(&b, &r);
	fprintf(stream, "%.*s", (int)r.length, (char *)r.base);

	return ISC_R_SUCCESS;
}

isc_result_t
dns_name_settotextfilter(dns_name_totextfilter_t *proc) {
	/*
	 * If we already have been here set / clear as appropriate.
	 */
	if (totext_filter_proc != NULL && proc != NULL) {
		if (totext_filter_proc == proc) {
			return ISC_R_SUCCESS;
		}
	}
	if (proc == NULL && totext_filter_proc != NULL) {
		totext_filter_proc = NULL;
		return ISC_R_SUCCESS;
	}

	totext_filter_proc = proc;

	return ISC_R_SUCCESS;
}

void
dns_name_format(const dns_name_t *name, char *cp, unsigned int size) {
	isc_result_t result;
	isc_buffer_t buf;

	REQUIRE(size > 0);

	/*
	 * Leave room for null termination after buffer.
	 */
	isc_buffer_init(&buf, cp, size - 1);
	result = dns_name_totext(name, DNS_NAME_OMITFINALDOT, &buf);
	if (result == ISC_R_SUCCESS) {
		isc_buffer_putuint8(&buf, (uint8_t)'\0');
	} else {
		snprintf(cp, size, "<unknown>");
	}
}

/*
 * dns_name_tostring() -- similar to dns_name_format() but allocates its own
 * memory.
 */
isc_result_t
dns_name_tostring(const dns_name_t *name, char **target, isc_mem_t *mctx) {
	isc_result_t result;
	isc_buffer_t buf;
	isc_region_t reg;
	char *p, txt[DNS_NAME_FORMATSIZE];

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(target != NULL && *target == NULL);

	isc_buffer_init(&buf, txt, sizeof(txt));
	result = dns_name_totext(name, 0, &buf);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	isc_buffer_usedregion(&buf, &reg);
	p = isc_mem_allocate(mctx, reg.length + 1);
	memmove(p, (char *)reg.base, (int)reg.length);
	p[reg.length] = '\0';

	*target = p;
	return ISC_R_SUCCESS;
}

isc_result_t
dns_name_fromstring(dns_name_t *target, const char *src,
		    const dns_name_t *origin, unsigned int options,
		    isc_mem_t *mctx) {
	isc_result_t result;
	isc_buffer_t buf;
	dns_fixedname_t fn;
	dns_name_t *name;

	REQUIRE(src != NULL);

	isc_buffer_constinit(&buf, src, strlen(src));
	isc_buffer_add(&buf, strlen(src));
	if (DNS_NAME_BINDABLE(target) && target->buffer != NULL) {
		name = target;
	} else {
		name = dns_fixedname_initname(&fn);
	}

	result = dns_name_fromtext(name, &buf, origin, options);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	if (name != target) {
		dns_name_dup(name, mctx, target);
	}
	return result;
}

void
dns_name_copy(const dns_name_t *source, dns_name_t *dest) {
	isc_buffer_t *target = NULL;
	unsigned char *ndata = NULL;

	REQUIRE(DNS_NAME_VALID(source));
	REQUIRE(DNS_NAME_VALID(dest));
	REQUIRE(DNS_NAME_BINDABLE(dest));

	target = dest->buffer;

	REQUIRE(target != NULL);
	REQUIRE(target->length >= source->length);

	isc_buffer_clear(target);

	ndata = (unsigned char *)target->base;
	dest->ndata = target->base;

	if (source->length != 0) {
		memmove(ndata, source->ndata, source->length);
	}

	dest->ndata = ndata;
	dest->length = source->length;
	dest->attributes.absolute = source->attributes.absolute;

	isc_buffer_add(target, dest->length);
}

/*
 * Service Discovery Prefixes RFC 6763.
 */
static unsigned char b_dns_sd_udp_data[] = "\001b\007_dns-sd\004_udp";
static unsigned char db_dns_sd_udp_data[] = "\002db\007_dns-sd\004_udp";
static unsigned char r_dns_sd_udp_data[] = "\001r\007_dns-sd\004_udp";
static unsigned char dr_dns_sd_udp_data[] = "\002dr\007_dns-sd\004_udp";
static unsigned char lb_dns_sd_udp_data[] = "\002lb\007_dns-sd\004_udp";

static dns_name_t const dns_sd[] = {
	DNS_NAME_INITNONABSOLUTE(b_dns_sd_udp_data),
	DNS_NAME_INITNONABSOLUTE(db_dns_sd_udp_data),
	DNS_NAME_INITNONABSOLUTE(r_dns_sd_udp_data),
	DNS_NAME_INITNONABSOLUTE(dr_dns_sd_udp_data),
	DNS_NAME_INITNONABSOLUTE(lb_dns_sd_udp_data)
};

bool
dns_name_isdnssd(const dns_name_t *name) {
	size_t i;
	dns_name_t prefix;

	if (dns_name_countlabels(name) > 3U) {
		dns_name_init(&prefix);
		dns_name_getlabelsequence(name, 0, 3, &prefix);
		for (i = 0; i < (sizeof(dns_sd) / sizeof(dns_sd[0])); i++) {
			if (dns_name_equal(&prefix, &dns_sd[i])) {
				return true;
			}
		}
	}

	return false;
}

static unsigned char inaddr10[] = "\00210\007IN-ADDR\004ARPA";

static unsigned char inaddr16172[] = "\00216\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr17172[] = "\00217\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr18172[] = "\00218\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr19172[] = "\00219\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr20172[] = "\00220\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr21172[] = "\00221\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr22172[] = "\00222\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr23172[] = "\00223\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr24172[] = "\00224\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr25172[] = "\00225\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr26172[] = "\00226\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr27172[] = "\00227\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr28172[] = "\00228\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr29172[] = "\00229\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr30172[] = "\00230\003172\007IN-ADDR\004ARPA";
static unsigned char inaddr31172[] = "\00231\003172\007IN-ADDR\004ARPA";

static unsigned char inaddr168192[] = "\003168\003192\007IN-ADDR\004ARPA";

static dns_name_t const rfc1918names[] = {
	DNS_NAME_INITABSOLUTE(inaddr10),    DNS_NAME_INITABSOLUTE(inaddr16172),
	DNS_NAME_INITABSOLUTE(inaddr17172), DNS_NAME_INITABSOLUTE(inaddr18172),
	DNS_NAME_INITABSOLUTE(inaddr19172), DNS_NAME_INITABSOLUTE(inaddr20172),
	DNS_NAME_INITABSOLUTE(inaddr21172), DNS_NAME_INITABSOLUTE(inaddr22172),
	DNS_NAME_INITABSOLUTE(inaddr23172), DNS_NAME_INITABSOLUTE(inaddr24172),
	DNS_NAME_INITABSOLUTE(inaddr25172), DNS_NAME_INITABSOLUTE(inaddr26172),
	DNS_NAME_INITABSOLUTE(inaddr27172), DNS_NAME_INITABSOLUTE(inaddr28172),
	DNS_NAME_INITABSOLUTE(inaddr29172), DNS_NAME_INITABSOLUTE(inaddr30172),
	DNS_NAME_INITABSOLUTE(inaddr31172), DNS_NAME_INITABSOLUTE(inaddr168192)
};

bool
dns_name_isrfc1918(const dns_name_t *name) {
	size_t i;

	for (i = 0; i < (sizeof(rfc1918names) / sizeof(*rfc1918names)); i++) {
		if (dns_name_issubdomain(name, &rfc1918names[i])) {
			return true;
		}
	}
	return false;
}

static unsigned char ip6fc[] = "\001c\001f\003ip6\004ARPA";
static unsigned char ip6fd[] = "\001d\001f\003ip6\004ARPA";

static dns_name_t const ulanames[] = { DNS_NAME_INITABSOLUTE(ip6fc),
				       DNS_NAME_INITABSOLUTE(ip6fd) };

bool
dns_name_isula(const dns_name_t *name) {
	size_t i;

	for (i = 0; i < (sizeof(ulanames) / sizeof(*ulanames)); i++) {
		if (dns_name_issubdomain(name, &ulanames[i])) {
			return true;
		}
	}
	return false;
}

bool
dns_name_istat(const dns_name_t *name) {
	unsigned char len;
	const unsigned char *ndata;

	REQUIRE(DNS_NAME_VALID(name));

	if (name->length == 0) {
		return false;
	}

	ndata = name->ndata;
	len = ndata[0];
	INSIST(len <= name->length);
	ndata++;

	/*
	 * Is there at least one trust anchor reported and is the
	 * label length consistent with a trust-anchor-telemetry label.
	 */
	if ((len < 8) || (len - 3) % 5 != 0) {
		return false;
	}

	if (ndata[0] != '_' || isc_ascii_tolower(ndata[1]) != 't' ||
	    isc_ascii_tolower(ndata[2]) != 'a')
	{
		return false;
	}
	ndata += 3;
	len -= 3;

	while (len > 0) {
		INSIST(len >= 5);
		if (ndata[0] != '-' || !isc_hex_char(ndata[1]) ||
		    !isc_hex_char(ndata[2]) || !isc_hex_char(ndata[3]) ||
		    !isc_hex_char(ndata[4]))
		{
			return false;
		}
		ndata += 5;
		len -= 5;
	}
	return true;
}

bool
dns_name_isdnssvcb(const dns_name_t *name) {
	unsigned char len, len1;
	const unsigned char *ndata;

	REQUIRE(DNS_NAME_VALID(name));

	if (name->length < 5) {
		return false;
	}

	ndata = name->ndata;
	len = len1 = ndata[0];
	INSIST(len <= name->length);
	ndata++;

	if (len < 2 || ndata[0] != '_') {
		return false;
	}
	if (isdigit(ndata[1]) && name->length > len + 1) {
		char buf[sizeof("65000")];
		long port;
		char *endp;

		/*
		 * Do we have a valid _port label?
		 */
		if (len > 6U || (ndata[1] == '0' && len != 2)) {
			return false;
		}
		memcpy(buf, ndata + 1, len - 1);
		buf[len - 1] = 0;
		port = strtol(buf, &endp, 10);
		if (*endp != 0 || port < 0 || port > 0xffff) {
			return false;
		}

		/*
		 * Move to next label.
		 */
		ndata += len;
		INSIST(len1 + 1U < name->length);
		len = *ndata;
		INSIST(len + len1 + 1U <= name->length);
		ndata++;
	}

	if (len == 4U && strncasecmp((const char *)ndata, "_dns", 4) == 0) {
		return true;
	}

	return false;
}

bool
dns_name_israd(const dns_name_t *name, const dns_name_t *rad) {
	dns_name_t suffix;
	char labelbuf[64];
	unsigned long v, last = ULONG_MAX;
	char *end, *l;

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(DNS_NAME_VALID(rad));

	uint8_t name_labels = dns_name_countlabels(name);
	uint8_t rad_labels = dns_name_countlabels(rad);

	if (name_labels < rad_labels + 4U || name->length < 4U) {
		return false;
	}

	if (name->ndata[0] != 3 || name->ndata[1] != '_' ||
	    tolower(name->ndata[2]) != 'e' || tolower(name->ndata[3]) != 'r')
	{
		return false;
	}

	dns_name_init(&suffix);
	dns_name_split(name, rad_labels + 1, NULL, &suffix);

	if (suffix.ndata[0] != 3 || suffix.ndata[1] != '_' ||
	    tolower(suffix.ndata[2]) != 'e' || tolower(suffix.ndata[3]) != 'r')
	{
		return false;
	}

	/* type list */
	dns_name_split(name, name_labels - 1, NULL, &suffix);
	INSIST(*suffix.ndata < sizeof(labelbuf));
	memmove(labelbuf, suffix.ndata + 1, *suffix.ndata);
	labelbuf[*suffix.ndata] = 0;
	if (strlen(labelbuf) != *suffix.ndata) {
		return false;
	}
	l = labelbuf;
	do {
		v = strtoul(l, &end, 10);
		if (v > 0xffff || (*end != 0 && *end != '-') || end == l) {
			return false;
		}
		if (last != ULONG_MAX && v <= last) {
			return false;
		}
		last = v;
		if (*end == '-') {
			l = end + 1;
		}
	} while (*end != 0);

	/* extended error code */
	dns_name_split(name, rad_labels + 2, NULL, &suffix);
	INSIST(*suffix.ndata < sizeof(labelbuf));
	memmove(labelbuf, suffix.ndata + 1, *suffix.ndata);
	labelbuf[*suffix.ndata] = 0;
	if (strlen(labelbuf) != *suffix.ndata) {
		return false;
	}
	v = strtoul(labelbuf, &end, 10);
	if (v > 0xfff || *end != 0) {
		return false;
	}

	return dns_name_issubdomain(name, rad);
}

uint8_t
dns_name_offsets(const dns_name_t *name, dns_offsets_t offsets) {
	REQUIRE(DNS_NAME_VALID(name));
	unsigned int offset, count, length, nlabels;
	unsigned char *ndata;

	ndata = name->ndata;
	length = name->length;
	offset = 0;
	nlabels = 0;
	while (offset != length) {
		INSIST(nlabels < DNS_NAME_MAXLABELS);
		if (offsets != NULL) {
			offsets[nlabels] = offset;
		}
		nlabels++;
		count = *ndata;
		INSIST(count <= DNS_NAME_LABELLEN);
		offset += count + 1;
		ndata += count + 1;
		INSIST(offset <= length);
		if (count == 0) {
			/* Final root label */
			break;
		}
	}
	INSIST(offset == name->length);

	return nlabels;
}
