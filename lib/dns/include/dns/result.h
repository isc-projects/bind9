
#ifndef DNS_RESULT_H
#define DNS_RESULT_H 1

typedef unsigned int dns_result_t;

#define DNS_R_SUCCESS			0
#define DNS_R_NOMEMORY			1
/* Names */
#define DNS_R_NOSPACE			2
#define DNS_R_LABELTOOLONG		3
#define DNS_R_BADESCAPE			4
#define DNS_R_BADBITSTRING		5
#define DNS_R_BITSTRINGTOOLONG		6
#define DNS_R_EMPTYLABEL		7
#define DNS_R_BADDOTTEDQUAD		8
#define DNS_R_UNEXPECTEDEND		9
#define DNS_R_NOTIMPLEMENTED		10

#define DNS_R_LASTENTRY			10	/* Last entry on list. */

#define DNS_R_UNEXPECTED		0xFFFFFFFFL

char *					dns_result_totext(dns_result_t);

#endif /* DNS_RESULT_H */
