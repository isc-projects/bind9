/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#include <stdlib.h>

#include <isc/assertions.h>
#include <isc/lfsr.h>

/*
 * Any LFSR added to this table needs to have a large period.
 * Entries should be added from longest bit state to smallest bit state.
 * XXXMLG Need to pull some from Applied Crypto.
 */
isc_lfsr_t isc_lfsr_standard[] = {
	{ 0, 32, 0x80000057U },	/* 32-bit, x^31 + x^6 + x^4 + x^2 + x + 1 */
	{ 0, 32, 0x80000047U },	/* 32-bit, x^31 + x^6 + x^2 + x + 1 */
	{ 0, 30, 0x20000029U },	/* 30-bit, x^29 + x^6 + x^3 + 1 */
	{ 0, 19, 0x00040013U },	/* 19-bit, x^18 + x^4 + x + 1 */
	{ 0, 13, 0x0000100dU },	/* 13-bit, x^12 + x^3 + x^2 + 1 */
	{ 0, 0, 0}
};

#define VALID_LFSR(x)	(x != NULL)

isc_lfsr_t *
isc_lfsr_findlfsr(unsigned int bits)
{
	return (NULL);  /* XXXMLG implement? */
}

void
isc_lfsr_init(isc_lfsr_t *lfsr, isc_uint32_t state, unsigned int bits,
	      isc_uint32_t tap)
{
	REQUIRE(VALID_LFSR(lfsr));
	REQUIRE(8 <= bits && bits <= 32);
	REQUIRE(tap != 0);

	lfsr->state = state;
	lfsr->bits = bits;
	lfsr->tap = tap;
}

/*
 * Return the next state of the lfsr.
 */
static inline isc_uint32_t
lfsr_generate(isc_lfsr_t *lfsr)
{
	unsigned int nbits;

	nbits = lfsr->bits - 1;

	/*
	 * If the previous state is zero, we must fill it with something
	 * here, or we will begin to generate an extremely predictable output.
	 */
	if (lfsr->state == 0)
		lfsr->state = (-1) & ((1 << nbits) - 1);

	if (lfsr->state & 1)
		lfsr->state = ((lfsr->state ^ lfsr->tap) >> 1) | (1 << nbits);
	else
		lfsr->state >>= 1;

	return (lfsr->state);
}

isc_uint32_t
isc_lfsr_generate(isc_lfsr_t *lfsr)
{
	REQUIRE(VALID_LFSR(lfsr));

	return (lfsr_generate(lfsr));
}

static inline isc_uint32_t
lfsr_skipgenerate(isc_lfsr_t *lfsr, unsigned int skip)
{
	while (skip--)
		(void)lfsr_generate(lfsr);

	return (lfsr_generate(lfsr));
}

/*
 * Skip "skip" states in "lfsr" and return the ending state.
 */
isc_uint32_t
isc_lfsr_skipgenerate(isc_lfsr_t *lfsr, unsigned int skip)
{
	REQUIRE(VALID_LFSR(lfsr));

	return (lfsr_skipgenerate(lfsr, skip));
}

/*
 * Skip states in lfsr1 and lfsr2 using the other's current state.
 * Return the final state of lfsr1 ^ lfsr2.
 *
 * Since this uses the _previous_ state of the lfsrs, the the actual values
 * they contain should never be released to anyone other than by return from
 * this function.
 *
 * "skipbits" indicates how many lower bits should be used to advance the
 * lfsrs.  A good value is 1.  If simple combining is desired (without
 * skipping any values) one can use 0.
 */
isc_uint32_t
isc_lfsr_lfsrskipgenerate(isc_lfsr_t *lfsr1, isc_lfsr_t *lfsr2,
			  unsigned int skipbits)
{
	isc_uint32_t state1, state2;
	isc_uint32_t skip1, skip2;
	isc_uint32_t skipmask;

	REQUIRE(VALID_LFSR(lfsr1));
	REQUIRE(VALID_LFSR(lfsr2));
	REQUIRE(skipbits < 31);

	if (skipbits == 0)
		skipmask = 0;
	else
		skipmask = (1 << skipbits) - 1;

	skip1 = lfsr1->state & skipmask;
	skip2 = lfsr2->state & skipmask;

	/* cross-skip. */
	state1 = lfsr_skipgenerate(lfsr1, skip2);
	state2 = lfsr_skipgenerate(lfsr2, skip1);

	return (state1 ^ state2);
}
