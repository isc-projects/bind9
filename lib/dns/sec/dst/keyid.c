#include <stdlib.h>

#include <isc/region.h>
#include <isc/util.h>

#include <dst/dst.h>

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
