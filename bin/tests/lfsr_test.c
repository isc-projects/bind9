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

#include <stdio.h>

#include <isc/assertions.h>
#include <isc/types.h>
#include <isc/lfsr.h>

isc_uint32_t state[1024 * 64];

int
main(int argc, char **argv)
{
	isc_lfsr_t lfsr1, lfsr2;
	int i, j;
	isc_uint32_t temp;

	UNUSED(argc);
	UNUSED(argv);

	/*
	 * Verify that returned values are reproducable.
	 */
	lfsr1 = isc_lfsr_standard[3];
	for (i = 0 ; i < 32 ; i++) {
		state[i] = isc_lfsr_generate(&lfsr1);
		printf("lfsr1:  state[%2d] = %08x\n", i, state[i]);
	}
	lfsr1 = isc_lfsr_standard[3];
	for (i = 0 ; i < 32 ; i++) {
		temp = isc_lfsr_generate(&lfsr1);
		if (state[i] != temp)
			printf("lfsr1:  state[%2d] = %08x, but new state is %08x\n",
			       i, state[i], temp);
	}

	/*
	 * Now do the same with skipping.
	 */
	lfsr1 = isc_lfsr_standard[3];
	for (i = 0 ; i < 32 ; i++) {
		state[i] = isc_lfsr_skipgenerate(&lfsr1, 6);
		printf("lfsr1:  state[%2d] = %08x\n", i, state[i]);
	}
	lfsr1 = isc_lfsr_standard[3];
	for (i = 0 ; i < 32 ; i++) {
		temp = isc_lfsr_skipgenerate(&lfsr1, 6);
		if (state[i] != temp)
			printf("lfsr1:  state[%2d] = %08x, but new state is %08x\n",
			       i, state[i], temp);
	}

	/*
	 * Try to find the period of the LFSR.
	 */
	lfsr2 = isc_lfsr_standard[1];
	printf("Searching for repeating patterns in a %d-bit LFSR\n",
	       lfsr2.bits);
	for (i = 0 ; i < (1024 * 64) ; i++)
		state[i] = isc_lfsr_generate(&lfsr2);
	for (i = 0 ; i < (1024 * 64) ; i++) {
		for (j = i + 1 ; j < (1024 * 64) ; j++) {
			if (state[i] == state[j]) {
				printf("%08x: state %d and %d are the same, distance %d.\n",
				       state[i], i, j, j - i);
				goto next_i;
			}
		}
		next_i:
	}

	return (0);
}
