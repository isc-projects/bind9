/* Copyright (C) RSA Data Security, Inc. created 1990, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef DNSSAFE_GLOBAL_H
#define DNSSAFE_GLOBAL_H 1

#ifdef __cplusplus
extern "C" {
#endif

/* PROTOTYPES should be set to one if and only if the compiler supports
     function argument prototyping.
   The following makes PROTOTYPES default to 1 if it has not already been
     defined as 0 with C compiler flags.
 */
#ifndef PROTOTYPES
#define PROTOTYPES 1
#endif

#include <config.h>
#include <isc/int.h>
#include <sys/types.h> /* XXXMLG This should go... */

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
typedef isc_uint16_t UINT2;

/* UINT4 defines a four byte word */
typedef isc_uint32_t UINT4;

#ifndef NULL_PTR
#define NULL_PTR ((POINTER)0)
#endif

#ifndef UNUSED_ARG
#define UNUSED_ARG(x) x = *(&x);
#endif

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
   If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
     returns an empty list.  
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif

#ifdef __cplusplus
}
#endif

#endif /* DNSSAFE_GLOBAL_H */

