#ifndef DST_PARSE_H
#define DST_PARSE_H

/*
 * Portions Copyright (c) 1995-1998 by Trusted Information Systems, Inc.
 *
 * Permission to use, copy modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND TRUSTED INFORMATION SYSTEMS
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
 * TRUSTED INFORMATION SYSTEMS BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THE SOFTWARE.
 */
#include <isc/lang.h>
#include <isc/mem.h>
#include <dst/dst.h>

ISC_LANG_BEGINDECLS

#define MAJOR_VERSION		1
#define MINOR_VERSION		2

#define MAXFIELDSIZE		512
#define MAXFIELDS		12

#define TAG_SHIFT		4
#define TAG_ALG(tag)		(tag >> TAG_SHIFT)
#define TAG(alg, off)		((alg << TAG_SHIFT) + off)

#define RSA_NTAGS		8
#define TAG_RSA_MODULUS		((DST_ALG_RSA << TAG_SHIFT) + 0)
#define TAG_RSA_PUBLICEXPONENT	((DST_ALG_RSA << TAG_SHIFT) + 1)
#define TAG_RSA_PRIVATEEXPONENT	((DST_ALG_RSA << TAG_SHIFT) + 2)
#define TAG_RSA_PRIME1		((DST_ALG_RSA << TAG_SHIFT) + 3)
#define TAG_RSA_PRIME2		((DST_ALG_RSA << TAG_SHIFT) + 4)
#define TAG_RSA_EXPONENT1	((DST_ALG_RSA << TAG_SHIFT) + 5)
#define TAG_RSA_EXPONENT2	((DST_ALG_RSA << TAG_SHIFT) + 6)
#define TAG_RSA_COEFFICIENT	((DST_ALG_RSA << TAG_SHIFT) + 7)

#define DH_NTAGS		4
#define TAG_DH_PRIME		((DST_ALG_DH << TAG_SHIFT) + 0)
#define TAG_DH_GENERATOR	((DST_ALG_DH << TAG_SHIFT) + 1)
#define TAG_DH_PRIVATE		((DST_ALG_DH << TAG_SHIFT) + 2)
#define TAG_DH_PUBLIC		((DST_ALG_DH << TAG_SHIFT) + 3)

#define DSA_NTAGS		5
#define TAG_DSA_PRIME		((DST_ALG_DSA << TAG_SHIFT) + 0)
#define TAG_DSA_SUBPRIME	((DST_ALG_DSA << TAG_SHIFT) + 1)
#define TAG_DSA_BASE		((DST_ALG_DSA << TAG_SHIFT) + 2)
#define TAG_DSA_PRIVATE		((DST_ALG_DSA << TAG_SHIFT) + 3)
#define TAG_DSA_PUBLIC		((DST_ALG_DSA << TAG_SHIFT) + 4)

#define HMACMD5_NTAGS		1
#define TAG_HMACMD5_KEY		((DST_ALG_HMACMD5 << TAG_SHIFT) + 0)

struct dst_private_element {
	unsigned short tag;
	unsigned short length;
	unsigned char *data;
};

typedef struct dst_private_element dst_private_element_t;

struct dst_private {
	unsigned short nelements;
	dst_private_element_t elements[MAXFIELDS];
};

typedef struct dst_private dst_private_t;

void	dst_s_free_private_structure_fields(dst_private_t *priv,
					    isc_mem_t *mctx);
int	dst_s_parse_private_key_file(const char *name, const int alg,
				     const isc_uint16_t id, dst_private_t *priv,
				     isc_mem_t *mctx);
int	dst_s_write_private_key_file(const char *name, const int alg,
				     const isc_uint16_t id,
				     const dst_private_t *priv);

ISC_LANG_ENDDECLS

#endif /* DST_PARSE_H */
