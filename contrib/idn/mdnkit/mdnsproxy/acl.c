/*
 * acl.c - managing access control list.
 */

/*
 * Copyright (c) 2000 Japan Network Information Center.  All rights reserved.
 *  
 * By using this file, you agree to the terms and conditions set forth bellow.
 * 
 * 			LICENSE TERMS AND CONDITIONS 
 * 
 * The following License Terms and Conditions apply, unless a different
 * license is obtained from Japan Network Information Center ("JPNIC"),
 * a Japanese association, Kokusai-Kougyou-Kanda Bldg 6F, 2-3-4 Uchi-Kanda,
 * Chiyoda-ku, Tokyo 101-0047, Japan.
 * 
 * 1. Use, Modification and Redistribution (including distribution of any
 *    modified or derived work) in source and/or binary forms is permitted
 *    under this License Terms and Conditions.
 * 
 * 2. Redistribution of source code must retain the copyright notices as they
 *    appear in each source code file, this License Terms and Conditions.
 * 
 * 3. Redistribution in binary form must reproduce the Copyright Notice,
 *    this License Terms and Conditions, in the documentation and/or other
 *    materials provided with the distribution.  For the purposes of binary
 *    distribution the "Copyright Notice" refers to the following language:
 *    "Copyright (c) Japan Network Information Center.  All rights reserved."
 * 
 * 4. Neither the name of JPNIC may be used to endorse or promote products
 *    derived from this Software without specific prior written approval of
 *    JPNIC.
 * 
 * 5. Disclaimer/Limitation of Liability: THIS SOFTWARE IS PROVIDED BY JPNIC
 *    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *    PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL JPNIC BE LIABLE
 *    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *    OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *    ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * 6. Indemnification by Licensee
 *    Any person or entities using and/or redistributing this Software under
 *    this License Terms and Conditions shall defend indemnify and hold
 *    harmless JPNIC from and against any and all judgements damages,
 *    expenses, settlement liabilities, cost and other liabilities of any
 *    kind as a result of use and redistribution of this Software or any
 *    claim, suite, action, litigation or proceeding by any third party
 *    arising out of or relates to this License Terms and Conditions.
 * 
 * 7. Governing Law, Jurisdiction and Venue
 *    This License Terms and Conditions shall be governed by and and
 *    construed in accordance with the law of Japan. Any person or entities
 *    using and/or redistributing this Software under this License Terms and
 *    Conditions hereby agrees and consent to the personal and exclusive
 *    jurisdiction and venue of Tokyo District Court of Japan.
 */

#ifndef lint
static char *rcsid = "$Id: acl.c,v 1.1.2.1 2002/02/08 12:14:48 marka Exp $";
#endif

#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#ifdef  WIN32
#include <windows.h>
#include <winsock.h>
#else   /* for normal systems */
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "mdnsproxy.h"

#ifdef TEST
#undef WARN
#define WARN printf
#endif

/*
 * Entry in an access control list.
 */
typedef struct _acl acl_t;
struct _acl {
    struct in_addr address;		/* IP address */
    struct in_addr netmask;		/* net mask */
    acl_t *next;			/* pointer to a next entry */
};

/*
 * Access control list.
 */
static acl_t	*acl = NULL;


/*
 * Internal functions.
 */
static BOOL
acl_parse_address(const char *pattern, struct in_addr *address, 
		  struct in_addr *netmask, int lineNo);

/*
 * Initialize the access control list `acl'.
 */
int
acl_initialize(void)
{
    struct in_addr address;
    struct in_addr netmask;
    config_ctx_t config_ctx;
    acl_t *new_entry;
    acl_t *last_entry;
    int value_count;
    char **values;
    int lineNo;
    int i;

    TRACE("acl_initialize()\n");

    acl = NULL;
    last_entry = NULL;

    config_ctx = config_query_open(KW_ALLOW_ACCESS, &value_count, &values,
	&lineNo);

    while (config_ctx != NULL) {
	if (value_count < 2) {
	    WARN("acl_initialize - wrong # of args for \"%s\", line %d\n",
		KW_ALLOW_ACCESS, lineNo);
	    return FALSE;
	}

	for (i = 1; i < value_count; i++) {
	    if (!acl_parse_address(values[i], &address, &netmask, lineNo))
		return FALSE;

	    new_entry = (acl_t *)malloc(sizeof(acl_t));
	    if (new_entry == NULL) {
		WARN("acl_initialize - cannot allocate memory\n");
		return FALSE;
	    }
	    new_entry->address.s_addr = address.s_addr;
	    new_entry->netmask.s_addr = netmask.s_addr;
	    new_entry->next = NULL;

	    if (last_entry == NULL)
		acl = new_entry;
	    else
		last_entry->next = new_entry;
	    last_entry = new_entry;
	}
	config_ctx = config_query_more(config_ctx, &value_count, &values,
	    &lineNo);
    }

    return TRUE;
}

/*
 * netmask length to netmask conversion table.
 */
static const unsigned long netmasks_by_mask_length[] = {
    0x00000000UL, 0x80000000UL, 0xc0000000UL, 0xe0000000UL,  /*  0.. 3 */
    0xf0000000UL, 0xf8000000UL, 0xfc000000UL, 0xfe000000UL,  /*  4.. 7 */
    0xff000000UL, 0xff800000UL, 0xffc00000UL, 0xffe00000UL,  /*  8..12 */
    0xfff00000UL, 0xfff80000UL, 0xfffc0000UL, 0xfffe0000UL,  /* 13..15 */
    0xffff0000UL, 0xffff8000UL, 0xffffc000UL, 0xffffe000UL,  /* 16..19 */
    0xfffff000UL, 0xfffff800UL, 0xfffffc00UL, 0xfffffe00UL,  /* 20..23 */
    0xffffff00UL, 0xffffff80UL, 0xffffffc0UL, 0xffffffe0UL,  /* 24..27 */
    0xfffffff0UL, 0xfffffff8UL, 0xfffffffcUL, 0xfffffffeUL,  /* 28..31 */
    0xffffffffUL,                                            /* 32     */
};

/*
 * Parse an ACL address pattern (e.g. 192.168.100/24), and put the result
 * into `address' and `netmask'.  It returns TRUE upon success.
 *
 * We accepts the following address patterns:
 * 
 *     octet.octet.octet.octet
 *     octet.octet.octet.octet/netmask
 *     octet.octet.octet/netmask
 *     octet.octet/netmask
 *     octet/netmask
 *
 * Ommited octets are regarded as `0'.
 */
static BOOL
acl_parse_address(const char *pattern, struct in_addr *address, 
		  struct in_addr *netmask, int lineNo)
{
    unsigned int octets[4];
    int netmask_length;
    int digit_count;
    int octet_count;
    const char *p = pattern;

    octets[1] = 0;
    octets[2] = 0;
    octets[3] = 0;
    netmask_length = 32;

    /*
     * Parse an dot noted IP address.
     */
    octet_count = 0;
    while (octet_count < 4) {
	octets[octet_count] = 0;
	if (*p == '0' && '0' <= *(p + 1) && *(p + 1) <= '9') {
	    WARN("acl_parse_address - invalid address \"%.100s\", line %d\n",
		pattern, lineNo);
	    return FALSE;
	}
	for (digit_count = 0; '0' <= *p && *p <= '9'; p++, digit_count++)
	    octets[octet_count] = octets[octet_count] * 10 + (*p - '0');
	if (digit_count == 0 || digit_count > 3 || octets[octet_count] > 255) {
	    WARN("acl_parse_address - invalid address \"%.100s\", line %d\n",
		pattern, lineNo);
	    return FALSE;
	}

	octet_count++;
	if (*p != '.')
	    break;
	p++;
    }

    if (*p == '\0' && octet_count != 4) {
	WARN("acl_parse_address - malformed address \"%.100s\", line %d\n",
	    pattern, lineNo);
	return FALSE;
    }

    /*
     * Parse an optional netmask length preceded by `/'.
     */
    if (*p == '/') {
	netmask_length = 0;
	p++;
	if (*p == '0' && '0' <= *(p + 1) && *(p + 1) <= '9') {
	    WARN("acl_parse_address - invalid netmask length \"%.100s\", "
		"line %d\n", pattern, lineNo);
	    return FALSE;
	}
	for (digit_count = 0; '0' <= *p && *p <= '9'; p++, digit_count++)
	    netmask_length = netmask_length * 10 + (*p - '0');
	if (digit_count == 0 || digit_count > 2 || netmask_length > 32) {
	    WARN("acl_parse_address - invalid netmask length \"%.100s\", "
		"line %d\n", pattern, lineNo);
	    return FALSE;
	}
    }

    if (*p != '\0') {
	WARN("acl_parse_address - invalid address \"%.100s\", line %d\n",
	    pattern, lineNo);
	return FALSE;
    }

    /*
     * Put the result into `address' and `netmask'.
     */
    address->s_addr = htonl((octets[0] << 24) + (octets[1] << 16)
	+ (octets[2] << 8) + octets[3]);
    netmask->s_addr = htonl(netmasks_by_mask_length[netmask_length]);

    /*
     * Check address/netmask mismatch. (e.g. 192.168.10.8/16)
     */
    if ((address->s_addr & netmask->s_addr) != address->s_addr) {
	WARN("acl_parse_address - address/netmask mismatch \"%.100s\", "
	    "line %d\n", pattern, lineNo);
	return FALSE;
    }

    return TRUE;
}

/*
 * Return TRUE if access from `address' is permitted or not.
 * Note that we returns TRUE if no access control pattern is registered.
 */
BOOL
acl_test(struct sockaddr *address)
{
    acl_t *acl_entry;
    struct in_addr inet_address;

    if (acl == NULL)
	return TRUE;

    inet_address.s_addr = ((struct sockaddr_in *)address)->sin_addr.s_addr;

    for (acl_entry = acl; acl_entry != NULL; acl_entry = acl_entry->next) {
	if ((inet_address.s_addr & acl_entry->netmask.s_addr)
	    == acl_entry->address.s_addr) {
	    return TRUE;
	}
    }

    return FALSE;
}

/*
 * Finalize the access control list `acl'.
 */
void
acl_finalize(void)
{
    acl_t *acl_entry;
    acl_t *saved_next;

    acl_entry = acl;
    while (acl_entry != NULL) {
	saved_next = acl_entry->next;
	free(acl_entry);
	acl_entry = saved_next;
    }

    acl = NULL;
}


/*
 * main for test.
 * `proxycnf.o' and `logging.o' are reuqired to build this test program.
 */
#ifdef TEST

#include <string.h>

int
main(int argc, char *argv[])
{
    char line[512];
    char *newline;
    struct sockaddr_in address;

    printf("ACL allow/deny test program\n");
    fflush(stdout);

    if (config_load(argc, argv) != TRUE) {
        printf("failed to load configurations\n");
        return 1 ;
    }
    printf("loaded configuration.\n");

    if (!acl_initialize()) {
        printf("failed to initialize ACL\n");
	return 1;
    }

    for (;;) {
	printf("input address> ");
	fflush(stdout);
	if (fgets(line, 512, stdin) == NULL)
	    break;

	newline = strpbrk(line, "\r\n");
	if (newline != NULL)
	    *newline = '\0';

	if (!inet_aton(line, &address.sin_addr)) {
	    printf("invalid address\n");
	    continue;
	}

	if (acl_test((struct sockaddr *)&address))
	    printf("access from %s is allowed.\n", line);
	else
	    printf("access from %s is denied.\n", line);
    }

    acl_finalize();

    return 0;
}

#endif /* TEST */
