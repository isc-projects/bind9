/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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

#include <config.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/compress.h>

#define NAME_MAGIC			0x444E536EU	/* DNSn. */
#define VALID_NAME(n)			((n) != NULL && \
					 (n)->magic == NAME_MAGIC)

typedef enum {
	ft_init = 0,
	ft_start,
	ft_ordinary,
	ft_initialescape,
	ft_escape,
	ft_escdecimal,
	ft_bitstring,
	ft_binary,
	ft_octal,
	ft_hex,
	ft_dottedquad,
	ft_dqdecimal,
	ft_maybeslash,
	ft_finishbitstring,
	ft_bitlength,
	ft_eatdot
} ft_state;

typedef enum {
	fw_start = 0,
	fw_ordinary,
	fw_copy,
	fw_bitstring,
	fw_newcurrent,
	fw_local
} fw_state;

static char digitvalue[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/*16*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*32*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*48*/
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, /*64*/
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*80*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*96*/
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*112*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*128*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*256*/
};

static char hexdigits[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

static unsigned char maptolower[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
	0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

#define CONVERTTOASCII(c)
#define CONVERTFROMASCII(c)

static struct dns_name root = { NAME_MAGIC, "", 1, 1 };

dns_name_t *dns_rootname = &root;

static void set_offsets(dns_name_t *, isc_boolean_t, isc_boolean_t);
static void compact(dns_name_t *);

/*
 * Yes, get_bit and set_bit are lame.  We define them here so they can
 * be inlined by smart compilers.
 */

static unsigned int
get_bit(unsigned char *array, unsigned int index) {
	unsigned int byte, shift;
	
	byte = array[index / 8];
	shift = 7 - (index % 8);

	return ((byte >> shift) & 0x01);
}

static void
set_bit(unsigned char *array, unsigned int index, unsigned int bit) {
	unsigned int byte, shift, mask;
	
	byte = array[index / 8];
	shift = 7 - (index % 8);
	mask = 1 << shift;

	if (bit)
		array[index / 8] |= mask;
	else
		array[index / 8] &= (~mask & 0xFF);
}

dns_labeltype_t
dns_label_type(dns_label_t *label) {
	/*
	 * Get the type of 'label'.
	 */

	REQUIRE(label != NULL);
	REQUIRE(label->length > 0);
	REQUIRE(label->base[0] <= 63 ||
		label->base[0] == DNS_LABELTYPE_BITSTRING);
     
	if (label->base[0] <= 63)
		return (dns_labeltype_ordinary);
	else
		return (dns_labeltype_bitstring);
}

unsigned int
dns_label_countbits(dns_label_t *label) {
	unsigned int count;

	/*
	 * The number of bits in a bitstring label.
	 */

	REQUIRE(label != NULL);
	REQUIRE(label->length > 2);
	REQUIRE(label->base[0] == DNS_LABELTYPE_BITSTRING);

	count = label->base[1];
	if (count == 0)
		count = 256;
	
	return (count);
}

dns_bitlabel_t
dns_label_getbit(dns_label_t *label, unsigned int n) {
	unsigned int count, bit;

	/*
	 * The 'n'th most significant bit of 'label'.
	 *
	 * Notes:
	 *	Numbering starts at 0.
	 */

	REQUIRE(label != NULL);
	REQUIRE(label->length > 2);
	REQUIRE(label->base[0] == DNS_LABELTYPE_BITSTRING);

	count = label->base[1];
	if (count == 0)
		count = 256;

	REQUIRE(n < count);

	bit = get_bit(&label->base[2], n);
	if (bit == 0)
		return (dns_bitlabel_0);
	return (dns_bitlabel_1);
}

void
dns_name_init(dns_name_t *name) {
	/*
	 * Make 'name' empty.
	 */
	 
	name->magic = NAME_MAGIC;
	name->ndata = NULL;
	name->length = 0;
	name->labels = 0;
}

void
dns_name_invalidate(dns_name_t *name) {
	/*
	 * Make 'name' invalid.
	 */

	REQUIRE(VALID_NAME(name));

	name->magic = 0;
	name->ndata = NULL;
	name->length = 0;
	name->labels = 0;
}

isc_boolean_t
dns_name_isabsolute(dns_name_t *name) {
	/*
	 * Does 'name' end in the root label?
	 */

	REQUIRE(VALID_NAME(name));
	REQUIRE(name->labels > 0);

	if (name->ndata[name->offsets[name->labels - 1]] == 0)
		return (ISC_TRUE);
	return (ISC_FALSE);
}

int
dns_name_compare(dns_name_t *name1, dns_name_t *name2) {
	unsigned int l1, l2, l, count1, count2, count;
	unsigned int b1, b2, n;
	unsigned char c1, c2;
	int cdiff, ldiff;
	unsigned char *label1, *label2;

	/*
	 * Determine the relative ordering under the DNSSEC order relation of
	 * 'name1' and 'name2'.
	 */

	REQUIRE(VALID_NAME(name1));
	REQUIRE(name1->labels > 0);
	REQUIRE(VALID_NAME(name2));
	REQUIRE(name2->labels > 0);

	l1 = name1->labels;
	l2 = name2->labels;
	if (l1 < l2) {
		l = l1;
		ldiff = -1;
	} else {
		l = l2;
		if (l1 > l2)
			ldiff = 1;
		else
			ldiff = 0;
	}

	while (l > 0) {
		l--;
		l1--;
		l2--;
		label1 = &name1->ndata[name1->offsets[l1]];
		label2 = &name2->ndata[name2->offsets[l2]];
		count1 = *label1++;
		count2 = *label2++;
		if (count1 <= 63 && count2 <= 63) {
			if (count1 < count2) {
				cdiff = -1;
				count = count1;
			} else {
				count = count2;
				if (count1 > count2)
					cdiff = 1;
				else
					cdiff = 0;
			}

			while (count > 0) {
				count--;
				c1 = maptolower[*label1++];
				c2 = maptolower[*label2++];
				if (c1 < c2)
					return (-1);
				else if (c1 > c2)
					return (1);
			}
			if (cdiff != 0)
				return (cdiff);
		} else if (count1 == DNS_LABELTYPE_BITSTRING && count2 <= 63) {
			if (count2 == 0)
				return (1);
			return (-1);
		} else if (count2 == DNS_LABELTYPE_BITSTRING && count1 <= 63) {
			if (count1 == 0)
				return (-1);
			return (1);
		} else {
			INSIST(count1 == DNS_LABELTYPE_BITSTRING &&
			       count2 == DNS_LABELTYPE_BITSTRING);
			count1 = *label1++;
			if (count1 == 0)
				count1 = 256;
			count2 = *label2++;
			if (count2 == 0)
				count2 = 256;
			if (count1 < count2) {
				cdiff = -1;
				count = count1;
			} else {
				count = count2;
				if (count1 > count2)
					cdiff = 1;
				else
					cdiff = 0;
			}
			/* Yes, this loop is really slow! */
			for (n = 0; n < count; n++) {
				b1 = get_bit(label1, n);
				b2 = get_bit(label2, n);
				if (b1 < b2)
					return (-1);
				else if (b1 > b2)
					return (1);
			}
			if (cdiff != 0)
				return (cdiff);
		}
	}

	return (ldiff);
}

isc_boolean_t
dns_name_issubdomain(dns_name_t *name1, dns_name_t *name2) {
	isc_boolean_t a1, a2;
	unsigned int l1, l2, count1, count2;
	unsigned int b1, b2, n;
	unsigned char c1, c2;
	unsigned char *label1, *label2;

	/*
	 * Is 'name1' a subdomain of 'name2'?
	 *
	 * Note: It makes no sense for one of the names to be relative and the
	 * other absolute.  If both names are relative, then to be meaningfully
	 * compared the caller must ensure that they are both relative to the
	 * same domain.
	 */

	REQUIRE(VALID_NAME(name1));
	REQUIRE(name1->labels > 0);
	REQUIRE(VALID_NAME(name2));
	REQUIRE(name2->labels > 0);

	/* We're not going for maximal speed yet... */
	a1 = dns_name_isabsolute(name1);
	a2 = dns_name_isabsolute(name2);

	REQUIRE((a1 && a2) || (!a1 && !a2));

	l1 = name1->labels;
	l2 = name2->labels;
	if (l1 < l2)
		return (ISC_FALSE);

	while (l2 > 0) {
		l1--;
		l2--;
		label1 = &name1->ndata[name1->offsets[l1]];
		label2 = &name2->ndata[name2->offsets[l2]];
		count1 = *label1++;
		count2 = *label2++;
		if (count1 <= 63 && count2 <= 63) {
			if (count1 != count2)
				return (ISC_FALSE);
			while (count2 > 0) {
				count2--;
				c1 = maptolower[*label1++];
				c2 = maptolower[*label2++];
				if (c1 != c2)
					return (ISC_FALSE);
			}
		} else {
			if (count1 != count2)
				return (ISC_FALSE);
			INSIST(count1 == DNS_LABELTYPE_BITSTRING &&
			       count2 == DNS_LABELTYPE_BITSTRING);
			count1 = *label1++;
			if (count1 == 0)
				count1 = 256;
			count2 = *label2++;
			if (count2 == 0)
				count2 = 256;
			if (count1 < count2)
				return (ISC_FALSE);
			/* Yes, this loop is really slow! */
			for (n = 0; n < count2; n++) {
				b1 = get_bit(label1, n);
				b2 = get_bit(label2, n);
				if (b1 != b2)
					return (ISC_FALSE);
			}
			if (count1 != count2 && l2 != 0)
				return (ISC_FALSE);
		}
	}

	return (ISC_TRUE);
}

unsigned int
dns_name_countlabels(dns_name_t *name) {
	/*
	 * How many labels does 'name' have?
	 */

	REQUIRE(VALID_NAME(name));

	ENSURE(name->labels <= 128);

	return (name->labels);
}

void
dns_name_getlabel(dns_name_t *name, unsigned int n, dns_label_t *label) {
	/*
	 * Make 'label' refer to the 'n'th least significant label of 'name'.
	 */
	
	REQUIRE(VALID_NAME(name));
	REQUIRE(name->labels > 0);
	REQUIRE(n < name->labels);
	REQUIRE(label != NULL);
	
	label->base = &name->ndata[name->offsets[n]];
	if (n == name->labels - 1)
		label->length = name->length - name->offsets[n];
	else
		label->length = name->offsets[n + 1] - name->offsets[n];
}

void
dns_name_getlabelsequence(dns_name_t *source,
			  unsigned int first, unsigned int n,
			  dns_name_t *target)
{
	/*
	 * Make 'target' refer to the 'n' labels including and following
	 * 'first' in 'source'.
	 */

	REQUIRE(VALID_NAME(source));
	REQUIRE(source->labels > 0);
	REQUIRE(n > 0);
	REQUIRE(first < source->labels);
	REQUIRE(first + n <= source->labels);

	target->ndata = &source->ndata[source->offsets[first]];
	if (first + n == source->labels)
		target->length = source->length - source->offsets[first];
	else
		target->length = source->offsets[first + n] -
			source->offsets[first];
	target->labels = n;

	set_offsets(target, ISC_FALSE, ISC_FALSE);
}

void
dns_name_fromregion(dns_name_t *name, isc_region_t *r) {
	/*
	 * Make 'name' refer to region 'r'.
	 */

	REQUIRE(name != NULL);
	REQUIRE(r != NULL);
	REQUIRE(r->length <= 255);

	name->magic = NAME_MAGIC;
	name->ndata = r->base;
	name->length = r->length;

	if (r->length > 0)
		set_offsets(name, ISC_TRUE, ISC_TRUE);
	else
		name->labels = 0;
}

void
dns_name_toregion(dns_name_t *name, isc_region_t *r) {
	/*
	 * Make 'r' refer to 'name'.
	 */

	REQUIRE(VALID_NAME(name));
	REQUIRE(r != NULL);

	r->base = name->ndata;
	r->length = name->length;
}


dns_result_t
dns_name_fromtext(dns_name_t *name, isc_buffer_t *source,
		  dns_name_t *origin, isc_boolean_t downcase,
		  isc_buffer_t *target)
{
	unsigned char *ndata, *label;
	char *tdata;
	char c;
	ft_state state, kind;
	unsigned int value, count, tbcount, bitlength, maxlength;
	unsigned int n1, n2, vlen, tlen, nrem, digits, labels, tused;
	isc_boolean_t done, saw_bitstring;
	unsigned char dqchars[4];

	/*
	 * Convert the textual representation of a DNS name at source
	 * into uncompressed wire form stored in target.
	 *
	 * Notes:
	 *	Relative domain names will have 'origin' appended to them
	 *	unless 'origin' is NULL, in which case relative domain names
	 *	will remain relative.
	 */

	REQUIRE(name != NULL);
	REQUIRE(isc_buffer_type(source) == ISC_BUFFERTYPE_TEXT);
	REQUIRE(isc_buffer_type(target) == ISC_BUFFERTYPE_BINARY);
	
	/*
	 * Initialize things to make the compiler happy; they're not required.
	 */
	n1 = 0;
	n2 = 0;
	vlen = 0;
	label = NULL;
	digits = 0;
	value = 0;
	count = 0;
	tbcount = 0;
	bitlength = 0;
	maxlength = 0;
	kind = ft_init;	

	/*
	 * Invalidate 'name'.
	 */
	name->magic = 0;
	name->ndata = NULL;
	name->length = 0;
	name->labels = 0;

	/*
	 * Set up the state machine.
	 */
	tdata = (char *)source->base + source->current;
	tlen = source->used - source->current;
	tused = 0;
	ndata = (unsigned char *)target->base + target->used;
	nrem = target->length - target->used;
	if (nrem > 255)
		nrem = 255;
	labels = 0;
	done = ISC_FALSE;
	saw_bitstring = ISC_FALSE;
	state = ft_init;

	while (nrem > 0 && tlen > 0 && !done) {
		c = *tdata++;
		tlen--;
		tused++;

	no_read:
		switch (state) {
		case ft_init:
			/*
			 * Is this the root name?
			 */
			if (c == '.') {
				if (tlen != 0)
					return (DNS_R_EMPTYLABEL);
				labels++;
				*ndata++ = 0;
				nrem--;
				done = ISC_TRUE;
				break;
			}
			/* FALLTHROUGH */
		case ft_start:
			label = ndata;
			ndata++;
			nrem--;
			count = 0;
			if (c == '\\') {
				state = ft_initialescape;
				break;
			}
			kind = ft_ordinary;
			state = ft_ordinary;
			/* FALLTHROUGH */
		case ft_ordinary:
			if (c == '.') {
				if (count == 0)
					return (DNS_R_EMPTYLABEL);
				*label = count;
				labels++;
				if (tlen == 0) {
					labels++;
					*ndata++ = 0;
					nrem--;
					done = ISC_TRUE;
				}
				state = ft_start;
			} else if (c == '\\') {
				state = ft_escape;
			} else {
				if (count >= 63)
					return (DNS_R_LABELTOOLONG);
				count++;
				CONVERTTOASCII(c);
				if (downcase)
					c = maptolower[(int)c];
				*ndata++ = c;
				nrem--;
			}
			break;
		case ft_initialescape:
			if (c == '[') {
				saw_bitstring = ISC_TRUE;
				kind = ft_bitstring;
				state = ft_bitstring;
				*label = DNS_LABELTYPE_BITSTRING;
				label = ndata;
				ndata++;
				nrem--;
				break;
			}
			kind = ft_ordinary;
			state = ft_escape;
			/* FALLTHROUGH */
		case ft_escape:
			if (!isdigit(c)) {
				if (count >= 63)
					return (DNS_R_LABELTOOLONG);
				count++;
				CONVERTTOASCII(c);
				if (downcase)
					c = maptolower[(int)c];
				*ndata++ = c;
				nrem--;
				state = ft_ordinary;
				break;
			}
			digits = 0;
			value = 0;
			state = ft_escdecimal;
			/* FALLTHROUGH */
		case ft_escdecimal:
			if (!isdigit(c))
				return (DNS_R_BADESCAPE);
			value *= 10;
			value += digitvalue[(int)c];
			digits++;
			if (digits == 3) {
				if (value > 255)
					return (DNS_R_BADESCAPE);
				if (count >= 63)
					return (DNS_R_LABELTOOLONG);
				count++;
				if (downcase)
					value = maptolower[value];
				*ndata++ = value;
				nrem--;
				state = ft_ordinary;
			}
			break;
		case ft_bitstring:
			/* count is zero */
			tbcount = 0;
			value = 0;
			if (c == 'b') {
				vlen = 8;
				maxlength = 256;
				kind = ft_binary;
				state = ft_binary;
			} else if (c == 'o') {
				vlen = 8;
				maxlength = 256;
				kind = ft_octal;
				state = ft_octal;
			} else if (c == 'x') {
				vlen = 8;
				maxlength = 256;
				kind = ft_hex;
				state = ft_hex;
			} else if (isdigit(c)) {
				vlen = 32;
				maxlength = 32;
				n1 = 0;
				n2 = 0;
				digits = 0;
				kind = ft_dottedquad;
				state = ft_dqdecimal;
				goto no_read;
			} else
				return (DNS_R_BADBITSTRING);
			break;
		case ft_binary:
			if (c != '0' && c != '1') {
				state = ft_maybeslash;
				goto no_read;
			}
			value <<= 1;
			if (c == '1')
				value |= 1;
			count++;
			tbcount++;
			if (tbcount > 256)
				return (DNS_R_BITSTRINGTOOLONG);
			if (count == 8) {
				*ndata++ = value;
				nrem--;
				count = 0;
			}
			break;
		case ft_octal:
			if (!isdigit(c) || c == '9') {
				state = ft_maybeslash;
				goto no_read;
			}
			value <<= 3;
			value += digitvalue[(int)c];
			count += 3;
			tbcount += 3;
			if (tbcount > 256)
				return (DNS_R_BITSTRINGTOOLONG);
			if (count == 8) {
				*ndata++ = value;
				nrem--;
				count = 0;
			} else if (count == 9) {
				*ndata++ = (value >> 1);
				nrem--;
				value &= 1;
				count = 1;
			} else if (count == 10) {
				*ndata++ = (value >> 2);
				nrem--;
				value &= 3;
				count = 2;
			}
			break;
		case ft_hex:
			if (!isxdigit(c)) {
				state = ft_maybeslash;
				goto no_read;
			}
			value <<= 4;
			value += digitvalue[(int)c];
			count += 4;
			tbcount += 4;
			if (tbcount > 256)
				return (DNS_R_BITSTRINGTOOLONG);
			if (count == 8) {
				*ndata++ = value;
				nrem--;
				count = 0;
			}
			break;
		case ft_dottedquad:
			if (c != '.' && n1 < 3)
				return (DNS_R_BADDOTTEDQUAD);
			dqchars[n1] = value;
			n2 *= 256;
			n2 += value;
			n1++;
			if (n1 == 4) {
				tbcount = 32;
				value = n2;
				state = ft_maybeslash;
				goto no_read;
			}
			value = 0;
			digits = 0;
			state = ft_dqdecimal;
			break;
		case ft_dqdecimal:
			if (!isdigit(c)) {
				if (digits == 0 || value > 255)
					return (DNS_R_BADDOTTEDQUAD);
				state = ft_dottedquad;
				goto no_read;
			}
			digits++;
			if (digits > 3)
				return (DNS_R_BADDOTTEDQUAD);
			value *= 10;
			value += digitvalue[(int)c];
			break;
		case ft_maybeslash:
			bitlength = 0;
			if (c == '/') {
				state = ft_bitlength;
				break;
			}
			/* FALLTHROUGH */
		case ft_finishbitstring:
			if (c == ']') {
				if (tbcount == 0)
					return (DNS_R_BADBITSTRING);
				if (count > 0) {
					n1 = count % 8;
					if (n1 != 0)
						value <<= (8 - n1);
					*ndata++ = value;
					nrem--;
				}
				if (bitlength != 0) {
					if (bitlength > tbcount)
						return (DNS_R_BADBITSTRING);
					if (kind == ft_binary &&
					    bitlength != tbcount) {
						return (DNS_R_BADBITSTRING);
					} else if (kind == ft_octal) {
						/*
						 * Figure out correct number
						 * of octal digits for the
						 * bitlength, and compare to
						 * what was given.
						 */
						n1 = bitlength / 3;
						if (bitlength % 3 != 0)
							n1++;
						n2 = tbcount / 3;
						/* tbcount % 3 == 0 */
						if (n1 != n2)
						  return (DNS_R_BADBITSTRING);
					} else if (kind == ft_hex) {
						/*
						 * Figure out correct number
						 * of hex digits for the
						 * bitlength, and compare to
						 * what was given.
						 */
						n1 = bitlength / 4;
						if (bitlength % 4 != 0)
							n1++;
						n2 = tbcount / 4;
						/* tbcount % 4 == 0 */
						if (n1 != n2)
						  return (DNS_R_BADBITSTRING);
					}
					n1 = bitlength % vlen;
					if (n1 != 0) {
						/*
						 * Are the pad bits in the
						 * last 'vlen' bits zero?
						 */
						if ((value &
						    ~((~0) << (vlen-n1))) != 0)
						  return (DNS_R_BADBITSTRING);
					}
				} else if (kind == ft_dottedquad)
					bitlength = 32;
				else
					bitlength = tbcount;
				if (kind == ft_dottedquad) {
					n1 = bitlength / 8;
					if (bitlength % 8 != 0)
						n1++;
					if (nrem < n1)
						return (DNS_R_NOSPACE);
					for (n2 = 0; n2 < n1; n2++) {
						*ndata++ = dqchars[n2];
						nrem--;
					}
				}
				if (bitlength == 256)
					*label = 0;
				else
					*label = bitlength;
				labels++;
			} else
				return (DNS_R_BADBITSTRING);
			state = ft_eatdot;
			break;
		case ft_bitlength:
			if (!isdigit(c)) {
				if (bitlength == 0)
					return (DNS_R_BADBITSTRING);
				state = ft_finishbitstring;
				goto no_read;
			}
			bitlength *= 10;
			bitlength += digitvalue[(int)c];
			if (bitlength > maxlength)
				return (DNS_R_BADBITSTRING);
			break;
		case ft_eatdot:
			if (c != '.')
				return (DNS_R_BADBITSTRING);
			if (tlen == 0) {
				labels++;
				*ndata++ = 0;
				nrem--;
				done = ISC_TRUE;
			}
			state = ft_start;
			break;
		default:
			FATAL_ERROR(__FILE__, __LINE__,
				    "Unexpected state %d", state);
			/* Does not return. */
		}
	}

	if (!done) {
		if (nrem == 0)
			return (DNS_R_NOSPACE);
		INSIST(tlen == 0);
		if (state != ft_ordinary && state != ft_eatdot)
			return (DNS_R_UNEXPECTEDEND);
		if (state == ft_ordinary) {
			INSIST(count != 0);
			*label = count;
			labels++;
		}
		if (origin != NULL) {
			if (nrem < origin->length)
				return (DNS_R_NOSPACE);
			label = origin->ndata;
			n1 = origin->length;
			nrem -= n1;
			labels += origin->labels;
			while (n1 > 0) {
				c = *label++;
				/* 'origin' is already ASCII. */
				if (downcase)
					c = maptolower[(int)c];
				*ndata++ = c;
				n1--;
			}
		}		
	}

	name->magic = NAME_MAGIC;
	name->ndata = (unsigned char *)target->base + target->used;
	name->labels = labels;
	name->length = target->length - target->used - nrem;

	/*
	 * We should build the offsets table directly.
	 */
	set_offsets(name, ISC_FALSE, ISC_FALSE);

	if (saw_bitstring)
		compact(name);

	isc_buffer_forward(source, tused);
	isc_buffer_add(target, name->length);

	return (DNS_R_SUCCESS);
}

dns_result_t
dns_name_totext(dns_name_t *name, isc_boolean_t omit_final_dot,
		isc_buffer_t *target)
{
	unsigned char *ndata;
	char *tdata;
	unsigned int nlen, tlen;
	unsigned char c;
	unsigned int trem, count;
	unsigned int bytes, nibbles;
	size_t i, len;
	unsigned int labels;
	isc_boolean_t saw_root = ISC_FALSE;
	char num[4];

	/*
	 * This function assumes the name is in proper uncompressed
	 * wire format.
	 */
	REQUIRE(VALID_NAME(name));
	REQUIRE(name->labels > 0);
	REQUIRE(isc_buffer_type(target) == ISC_BUFFERTYPE_TEXT);

	ndata = name->ndata;
	nlen = name->length;
	labels = name->labels;
	tdata = (char *)target->base + target->used;
	tlen = target->length - target->used;

	trem = tlen;

	/* Special handling for root label. */
	if (nlen == 1 && labels == 1 && *ndata == 0) {
		saw_root = ISC_TRUE;
		labels = 0;
		nlen = 0;
		if (trem == 0)
			return (DNS_R_NOSPACE);
		*tdata++ = '.';
		trem--;
	}
		
	while (labels > 0 && nlen > 0 && trem > 0) {
		labels--;
		count = *ndata++;
		nlen--;
		if (count == 0) {
			saw_root = ISC_TRUE;
			break;
		}
		if (count < 64) {
			INSIST(nlen >= count);
			while (count > 0) {
				c = *ndata;
				switch (c) {
				case 0x22: /* '"' */
				case 0x2E: /* '.' */
				case 0x3B: /* ';' */
				case 0x5C: /* '\\' */
				/* Special modifiers in zone files. */
				case 0x40: /* '@' */
				case 0x24: /* '$' */
					if (trem < 2)
						return (DNS_R_NOSPACE);
					*tdata++ = '\\';
					*tdata++ = c;
					ndata++;
					trem -= 2;
					nlen--;
					break;
				default:
					if (c > 0x20 && c < 0x7f) {
						if (trem == 0)
							return (DNS_R_NOSPACE);
						*tdata++ = c;
						ndata++;
						trem--;
						nlen--;
					} else {
						if (trem < 4)
							return (DNS_R_NOSPACE);
						sprintf(tdata, "\\%03u",
							c);
						tdata += 4;
						trem -= 4;
						ndata++;
						nlen--;
					}
				}
				count--;
			}
		} else if (count == DNS_LABELTYPE_BITSTRING) {
			if (trem < 3)
				return (DNS_R_NOSPACE);
			*tdata++ = '\\';
			*tdata++ = '[';
			*tdata++ = 'x';
			trem -= 3;
			INSIST(nlen > 0);
			count = *ndata++;
			if (count == 0)
				count = 256;
			nlen--;
			len = sprintf(num, "%u", count);	/* XXX */
			INSIST(len <= 4);
			bytes = count / 8;
			if (count % 8 != 0)
				bytes++;
			INSIST(nlen >= bytes);
			nibbles = count / 4;
			if (count % 4 != 0)
				nibbles++;
			if (trem < nibbles)
				return (DNS_R_NOSPACE);
			trem -= nibbles;
			nlen -= bytes;
			while (nibbles > 0) {
				c = *ndata++;
				*tdata++ = hexdigits[(c >> 4)];
				nibbles--;
				if (nibbles != 0) {
					*tdata++ = hexdigits[c & 0xf];
					i++;
					nibbles--;
				}
			}
			if (trem < 2 + len)
				return (DNS_R_NOSPACE);
			*tdata++ = '/';
			for (i = 0; i < len; i++)
				*tdata++ = num[i];
			*tdata++ = ']';
			trem -= 2 + len;
		} else {
			FATAL_ERROR(__FILE__, __LINE__,
				    "Unexpected label type %02x", count);
			/* Does not return. */
		}
					 
		/*
		 * The following assumes names are absolute.  If not, we
		 * fix things up later.  Note that this means that in some
		 * cases one more byte of text buffer is required than is
		 * needed in the final output.
		 */
		if (trem == 0)
			return (DNS_R_NOSPACE);
		*tdata++ = '.';
		trem--;
	}

	if (nlen != 0 && trem == 0)
		return (DNS_R_NOSPACE);
	INSIST(nlen == 0);
	if (!saw_root || omit_final_dot)
		trem++;

	isc_buffer_add(target, tlen - trem);

	return (DNS_R_SUCCESS);
}

static void
set_offsets(dns_name_t *name, isc_boolean_t set_labels,
	    isc_boolean_t set_length) {
	unsigned int offset, count, nlabels, nrem, n;
	unsigned char *ndata;

	ndata = name->ndata;
	nrem = name->length;
	offset = 0;
	nlabels = 0;
	while (nrem > 0) {
		INSIST(nlabels < 128);
		name->offsets[nlabels++] = offset;
		count = *ndata++;
		nrem--;
		offset++;
		if (count == 0)
			break;
		if (count > 63) {
			INSIST(count == DNS_LABELTYPE_BITSTRING);
			INSIST(nrem != 0);
			count = *ndata++;
			nrem--;
			offset++;
			if (count == 0)
				count = 256;
			n = count / 8;
			if (count % 8 != 0)
				n++;
			count = n;
		}
		INSIST(nrem >= count);
		nrem -= count;
		offset += count;
		ndata += count;
	}
	if (set_labels)
		name->labels = nlabels;
	if (set_length)
		name->length = offset;
	INSIST(nlabels == name->labels);
}

static void
compact(dns_name_t *name) {
	unsigned char *head, *curr, *last;
	unsigned int count, n, bit;
	unsigned int headbits, currbits, tailbits, newbits;
	unsigned int headrem, newrem;
	unsigned int headindex, currindex, tailindex, newindex;
	unsigned char tail[32];

	/*
	 * The caller MUST ensure that all bitstrings are correctly formatted
	 * and that the offsets table is valid.
	 */

 again:
	memset(tail, 0, sizeof tail);
	INSIST(name->labels != 0);
	n = name->labels - 1;

	while (n > 0) {
		head = &name->ndata[name->offsets[n]];
		if (head[0] == DNS_LABELTYPE_BITSTRING && head[1] != 0) {
			if (n != 0) {
				n--;
				curr = &name->ndata[name->offsets[n]];
				if (curr[0] != DNS_LABELTYPE_BITSTRING)
					break;
				/*
				 * We have consecutive bitstrings labels, and
				 * the more significant label ('head') has
				 * space.
				 */
				currbits = curr[1];
				if (currbits == 0)
					currbits = 256;
				currindex = 0;
				headbits = head[1];
				if (headbits == 0)
					headbits = 256;
				headindex = headbits;
				count = 256 - headbits;
				if (count > currbits)
					count = currbits;
				headrem = headbits % 8;
				if (headrem != 0)
					headrem = 8 - headrem;
				if (headrem != 0) {
					if (headrem > count)
						headrem = count;
					do {
						bit = get_bit(&curr[2],
							      currindex);
						set_bit(&head[2], headindex,
							bit);
						currindex++;
						headindex++;
						headbits++;
						count--;
						headrem--;
					} while (headrem != 0);
				}
				tailindex = 0;
				tailbits = 0;
				while (count > 0) {
					bit = get_bit(&curr[2], currindex);
					set_bit(tail, tailindex, bit);
					currindex++;
					tailindex++;
					tailbits++;
					count--;
				}
				newbits = 0;
				newindex = 0;
				if (currindex < currbits) {
					while (currindex < currbits) {
						bit = get_bit(&curr[2],
							      currindex);
						set_bit(&curr[2], newindex,
							bit);
						currindex++;
						newindex++;
						newbits++;
					}
					INSIST(newbits < 256);
					curr[1] = newbits;
					count = newbits / 8;
					newrem = newbits % 8;
					/* Zero remaining pad bits, if any. */
					if (newrem != 0) {
						count++;
						newrem = 8 - newrem;
						while (newrem > 0) {
							set_bit(&curr[2],
								newindex,
								0);
							newrem--;
							newindex++;
						}
					}
					curr += count + 2;
				} else {
					/* We got rid of curr. */
					name->labels--;
				}
				/* copy head, then tail, then rest to curr. */
				count = headbits + tailbits;
				INSIST(count <= 256);
				curr[0] = DNS_LABELTYPE_BITSTRING;
				if (count == 256)
					curr[1] = 0;
				else
					curr[1] = count;
				curr += 2;
				head += 2;
				count = headbits / 8;
				if (headbits % 8 != 0)
					count++;
				while (count > 0) {
					*curr++ = *head++;
					count--;
				}
				count = tailbits / 8;
				if (tailbits % 8 != 0)
					count++;
				last = tail;
				while (count > 0) {
					*curr++ = *last++;
					count--;
				}
				last = name->ndata + name->length;
				while (head != last)
					*curr++ = *head++;
				name->length = (curr - name->ndata);
				goto again;
			}
		}
		n--;
	}
}

dns_result_t
dns_name_fromwire(dns_name_t *name, isc_buffer_t *source,
		  dns_decompress_t *dctx, isc_boolean_t downcase,
		  isc_buffer_t *target)
{
	unsigned char *cdata, *ndata;
	unsigned int cused, hops, nrem, labels, n;
	unsigned int current, new_current, biggest_pointer;
	isc_boolean_t saw_bitstring, done;
	fw_state state = fw_start;
	unsigned int c;

	/*
	 * Copy the possibly-compressed name at source into target,
	 * decompressing it.
	 */

	REQUIRE(name != NULL);
	REQUIRE(isc_buffer_type(source) == ISC_BUFFERTYPE_BINARY);
	REQUIRE(isc_buffer_type(target) == ISC_BUFFERTYPE_BINARY);
	REQUIRE(dctx != NULL);

	/*
	 * Invalidate 'name'.
	 */
	name->magic = 0;
	name->ndata = NULL;
	name->length = 0;
	name->labels = 0;

	/*
	 * Initialize things to make the compiler happy; they're not required.
	 */
	n = 0;
	new_current = 0;

	/*
	 * Set up.
	 */
	labels = 0;
	hops = 0;
	saw_bitstring = ISC_FALSE;
	done = ISC_FALSE;
	ndata = (unsigned char *)target->base + target->used;
	nrem = target->length - target->used;
	if (nrem > 255)
		nrem = 255;
	cdata = (unsigned char *)source->base + source->current;
	cused = 0;
	current = source->current;
	biggest_pointer = current;

	/*
	 * Note:  The following code is not optimized for speed, but
	 * rather for correctness.  Speed will be addressed in the future.
	 */

	while (current < source->used && !done) {
		c = *cdata++;
		current++;
		if (hops == 0)
			cused++;

		switch (state) {
		case fw_start:
			if (c < 64) {
				labels++;
				if (nrem < c + 1)
					return (DNS_R_NOSPACE);
				nrem -= c + 1;
				*ndata++ = c;
				if (c == 0)
					done = ISC_TRUE;
				n = c;
				state = fw_ordinary;
			} else if (c >= 192) {
				/*
				 * Ordinary 14-bit pointer.
				 */
				if ((dctx->allowed & DNS_COMPRESS_GLOBAL14) ==
				    0)
					return (DNS_R_DISALLOWED);
				new_current = c & 0x3F;
				n = 1;
				state = fw_newcurrent;
			} else if (c == DNS_LABELTYPE_BITSTRING) {
				labels++;
				if (nrem == 0)
					return (DNS_R_NOSPACE);
				nrem--;
				*ndata++ = c;
				saw_bitstring = ISC_TRUE;
				state = fw_bitstring;
			} else if (c == DNS_LABELTYPE_GLOBALCOMP16) {
				/*
				 * 16-bit pointer.
				 */
				if ((dctx->allowed & DNS_COMPRESS_GLOBAL16) ==
				    0)
					return (DNS_R_DISALLOWED);
				new_current = 0;
				n = 2;
				state = fw_newcurrent;
			} else if (c == DNS_LABELTYPE_LOCALCOMP) {
				/*
				 * Local compression.
				 */
				if ((dctx->allowed & DNS_COMPRESS_GLOBAL16) ==
				    0)
					return (DNS_R_DISALLOWED);

				/* XXX */
				return (DNS_R_NOTIMPLEMENTED);
			} else
				return (DNS_R_BADLABELTYPE);
			break;
		case fw_ordinary:
			if (downcase)
				c = maptolower[c];
			/* FALLTHROUGH */
		case fw_copy:
			*ndata++ = c;
			n--;
			if (n == 0)
				state = fw_start;
			break;
		case fw_bitstring:
			if (nrem < c + 1)
				return (DNS_R_NOSPACE);
			nrem -= c + 1;
			*ndata++ = c;
			if (c == 0)
				c = 256;
			n = c / 8;
			if (c % 8 != 0)
				n++;
			state = fw_copy;
			break;
		case fw_newcurrent:
			new_current *= 256;
			new_current += c;
			n--;
			if (n == 0) {
				if (new_current >= biggest_pointer)
					return (DNS_R_BADPOINTER);
				biggest_pointer = new_current;
				current = new_current;
				cdata = (unsigned char *)source->base +
					current;
				hops++;
				if (hops > DNS_POINTER_MAXHOPS)
					return (DNS_R_TOOMANYHOPS);
				state = fw_start;
			}
			break;
		default:
			FATAL_ERROR(__FILE__, __LINE__,
				    "Unknown state %d", state);
			/* Does not return. */
		}
	}

	if (!done)
		return (DNS_R_UNEXPECTEDEND);

	name->magic = NAME_MAGIC;
	name->ndata = (unsigned char *)target->base + target->used;
	name->labels = labels;
	name->length = target->length - target->used - nrem;

	/*
	 * We should build the offsets table directly.
	 */
	set_offsets(name, ISC_FALSE, ISC_FALSE);

	if (saw_bitstring)
		compact(name);

	isc_buffer_forward(source, cused);
	isc_buffer_add(target, name->length);
	
	return (DNS_R_SUCCESS);
}

dns_result_t
dns_name_towire(dns_name_t *name, dns_compress_t *cctx,
		isc_buffer_t *target)
{
	/*
	 * Convert 'name' into wire format, compressing it as specified by the
	 * compression context 'cctx', and storing the result in 'target'.
	 */

	REQUIRE(VALID_NAME(name));
	REQUIRE(cctx != NULL);
	REQUIRE(isc_buffer_type(target) == ISC_BUFFERTYPE_BINARY);

	/*
	 * XXX  We don't try to compress the name; we just copy the
	 * uncompressed version into the target buffer.
	 */

	if (target->length - target->used < name->length)
		return (DNS_R_NOSPACE);
	(void)memcpy((unsigned char *)target->base + target->used,
		     name->ndata, (size_t)name->length);

	isc_buffer_add(target, name->length);

	return (DNS_R_SUCCESS);
}
