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

#ifndef DNS_TYPES_H
#define DNS_TYPES_H 1

/*
 * Including this file gives you type declarations suitable for use in
 * .h files, which lets us avoid circular type reference problems.
 *
 * To actually use a type or get declarations of its methods, you must
 * include the appropriate .h file too.
 */

#include <isc/region.h>
#include <isc/int.h>
#include <isc/list.h>

typedef isc_region_t				dns_label_t;
typedef struct dns_name				dns_name_t;
typedef ISC_LIST(dns_name_t)			dns_namelist_t;
typedef struct dns_db				dns_db_t;
typedef void					dns_dbnode_t;
typedef void					dns_dbversion_t;
typedef unsigned char				dns_offsets_t[128];
typedef struct dns_compress			dns_compress_t;
typedef struct dns_decompress			dns_decompress_t;
typedef isc_uint16_t				dns_rdataclass_t;
typedef isc_uint16_t				dns_rdatatype_t;
typedef isc_uint32_t				dns_ttl_t;
typedef struct dns_rdata			dns_rdata_t;
typedef struct dns_rdatalist			dns_rdatalist_t;
typedef struct dns_signature			dns_signature_t;
typedef struct dns_rdataset			dns_rdataset_t;
typedef ISC_LIST(dns_rdataset_t)		dns_rdatasetlist_t;
typedef struct dns_rdataiterator		dns_rdataiterator_t;

typedef enum {
	dns_labeltype_ordinary = 0,
	dns_labeltype_bitstring = 1
} dns_labeltype_t;

typedef enum {
	dns_bitlabel_0 = 0,
	dns_bitlabel_1 = 1
} dns_bitlabel_t;

typedef enum {
	dns_addmode_replace = 0,
	dns_addmode_merge = 1
} dns_addmode_t;

#include <dns/enumtype.h>
enum {
	ns_t_none = 0,
	TYPEENUM
	ns_t_any = 255
} ns_type_t;

#include <dns/enumclass.h>
enum {
	ns_c_none = 0,
	CLASSENUM
	ns_c_any = 255
} ns_class_t;

#endif /* DNS_TYPES_H */
