/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/sockaddr.h>
#include <isc/result.h>
#include <tests/t_api.h>

static int
test_isc_sockaddr_eqaddrprefix(void) {
	struct in_addr ina_a;
	struct in_addr ina_b;
	struct in_addr ina_c;	
	isc_sockaddr_t isa_a;
	isc_sockaddr_t isa_b;
	isc_sockaddr_t isa_c;
		
	if (inet_pton(AF_INET, "194.100.32.87", &ina_a) < 0)
		return T_FAIL;
	if (inet_pton(AF_INET, "194.100.32.80", &ina_b) < 0)
		return T_FAIL;
	if (inet_pton(AF_INET, "194.101.32.87", &ina_c) < 0)
		return T_FAIL;
	isc_sockaddr_fromin(&isa_a, &ina_a, 0);
	isc_sockaddr_fromin(&isa_b, &ina_b, 42);
	isc_sockaddr_fromin(&isa_c, &ina_c, 0);

	if (isc_sockaddr_eqaddrprefix(&isa_a, &isa_b, 0) != ISC_TRUE)
		return T_FAIL;
	if (isc_sockaddr_eqaddrprefix(&isa_a, &isa_b, 29) != ISC_TRUE)
		return T_FAIL;
	if (isc_sockaddr_eqaddrprefix(&isa_a, &isa_b, 30) != ISC_FALSE)
		return T_FAIL;
	if (isc_sockaddr_eqaddrprefix(&isa_a, &isa_b, 32) != ISC_FALSE)
		return T_FAIL;
	if (isc_sockaddr_eqaddrprefix(&isa_a, &isa_c, 8) != ISC_TRUE)
		return T_FAIL;
	if (isc_sockaddr_eqaddrprefix(&isa_a, &isa_c, 16) != ISC_FALSE)
		return T_FAIL;

	return T_PASS;
}

static void
t1(void) {
	int result;
	t_assert("isc_sockaddr_eqaddrprefix", 1, T_REQUIRED,
		 "isc_sockaddr_eqaddrprefix() returns ISC_TRUE when "
		 "prefixes of a and b are equal, and ISC_FALSE when "
		 "they are not equal");
	result = test_isc_sockaddr_eqaddrprefix();
	t_result(result);
}
		
testspec_t	T_testlist[] = {
	{	t1,	"isc_sockaddr_eqaddrprefix"	},
	{	NULL,	NULL				}
};

