
	/* $Id: serial.h,v 1.1 1999/08/30 14:44:11 marka Exp $ */

#ifndef isc_serial_h
#define isc_serial_h

#include <isc/types.h>
#include <isc/boolean.h>
#include <isc/lang.h>

ISC_LANG_BEGINDECLS

/*
 *	Implement 32 bit serial space arithmetic comparision functions.
 *
 *	Note: Undefined results are returned as ISC_FALSE.
 */

/***
 ***	Functions
 ***/

isc_boolean_t isc_serial_lt(isc_uint32_t a, isc_uint32_t b);
/*
 *	Return true if 'a' < 'b' otherwise false.
 */

isc_boolean_t isc_serial_gt(isc_uint32_t a, isc_uint32_t b);
/*
 *	Return true if 'a' > 'b' otherwise false.
 */

isc_boolean_t isc_serial_le(isc_uint32_t a, isc_uint32_t b);
/*
 *	Return true if 'a' <= 'b' otherwise false.
 */

isc_boolean_t isc_serial_ge(isc_uint32_t a, isc_uint32_t b);
/*
 *	Return true if 'a' >= 'b' otherwise false.
 */

isc_boolean_t isc_serial_eq(isc_uint32_t a, isc_uint32_t b);
/*
 *	Return true if 'a' == 'b' otherwise false.
 */

isc_boolean_t isc_serial_ne(isc_uint32_t a, isc_uint32_t b);
/*
 *	Return true if 'a' != 'b' otherwise false.
 */

ISC_LANG_ENDDECLS

#endif /* isc_serial_h */
