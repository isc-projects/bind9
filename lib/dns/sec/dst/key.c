#include <stdlib.h>

#include <isc/region.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include <dst/dst.h>

#include "dst_internal.h"

isc_uint16_t
dst_region_computeid(const isc_region_t *source, const unsigned int alg) {
	isc_uint32_t ac;
	const unsigned char *p;
	int size;

	REQUIRE(source != NULL);

	if (source->length < 4)
		return (0);

	p = source->base;
	size = source->length;

	if (alg == DST_ALG_RSAMD5)
		return ((p[size - 3] << 8) + p[size - 2]);

	for (ac = 0; size > 1; size -= 2, p += 2)
		ac += ((*p) << 8) + *(p + 1);

	if (size > 0)
		ac += ((*p) << 8);
	ac += (ac >> 16) & 0xffff;

	return ((isc_uint16_t)(ac & 0xffff));
}

dns_name_t *
dst_key_name(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_name);
}

unsigned int
dst_key_size(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_size);
}

unsigned int
dst_key_proto(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_proto);
}

unsigned int
dst_key_alg(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_alg);
}

isc_uint32_t
dst_key_flags(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_flags);
}

isc_uint16_t
dst_key_id(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_id);
}

dns_rdataclass_t
dst_key_class(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_class);
}

isc_boolean_t
dst_key_iszonekey(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));

	if ((key->key_flags & DNS_KEYTYPE_NOAUTH) != 0)
		return (ISC_FALSE);
	if ((key->key_flags & DNS_KEYFLAG_OWNERMASK) != DNS_KEYOWNER_ZONE)
		return (ISC_FALSE);
	if (key->key_proto != DNS_KEYPROTO_DNSSEC &&
	    key->key_proto != DNS_KEYPROTO_ANY)
		return (ISC_FALSE);
	return (ISC_TRUE);
}

isc_boolean_t
dst_key_isnullkey(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));

	if ((key->key_flags & DNS_KEYFLAG_TYPEMASK) != DNS_KEYTYPE_NOKEY)
		return (ISC_FALSE);
	if ((key->key_flags & DNS_KEYFLAG_OWNERMASK) != DNS_KEYOWNER_ZONE)
		return (ISC_FALSE);
	if (key->key_proto != DNS_KEYPROTO_DNSSEC &&
	    key->key_proto != DNS_KEYPROTO_ANY)
		return (ISC_FALSE);
	return (ISC_TRUE);
}
