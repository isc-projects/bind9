
	/* $Id: serial.c,v 1.1 1999/08/30 14:45:01 marka Exp $ */

#include <isc/serial.h>

isc_boolean_t
isc_serial_lt(isc_uint32_t a, isc_uint32_t b) {
	/*
	 * Undefined => ISC_FALSE
	 */
	if (a == (b ^ 0x80000000U))
		return (ISC_FALSE);
	return (((isc_int32_t)(a - b) < 0) ? ISC_TRUE : ISC_FALSE);
}

isc_boolean_t
isc_serial_gt(isc_uint32_t a, isc_uint32_t b) {
	return (((isc_int32_t)(a - b) > 0) ? ISC_TRUE : ISC_FALSE);
}

isc_boolean_t
isc_serial_le(isc_uint32_t a, isc_uint32_t b) {
	return ((a == b) ? ISC_TRUE : isc_serial_lt(a, b));
}

isc_boolean_t
isc_serial_ge(isc_uint32_t a, isc_uint32_t b) {
	return ((a == b) ? ISC_TRUE : isc_serial_gt(a, b));
}

isc_boolean_t
isc_serial_eq(isc_uint32_t a, isc_uint32_t b) {
	return ((a == b) ? ISC_TRUE : ISC_FALSE);
}

isc_boolean_t
isc_serial_ne(isc_uint32_t a, isc_uint32_t b) {
	return ((a != b) ? ISC_TRUE : ISC_FALSE);
}
