
#ifndef DNS_TYPES_H
#define DNS_TYPES_H 1

#include <isc/region.h>
#include <isc/boolean.h>

typedef isc_region_t				dns_label_t;
typedef struct dns_name *			dns_name_t;
typedef struct dns_lex *			dns_lex_t;
typedef struct dns_compression *		dns_compression_t;
typedef struct dns_decompression *		dns_decompression_t;

typedef enum {
	dns_labeltype_ordinary = 0,
	dns_labeltype_bitstring = 1
} dns_labeltype_t;

typedef enum {
	dns_bitlabel_0 = 0,
	dns_bitlabel_1 = 1
} dns_bitlabel_t;

#endif /* DNS_TYPES_H */
