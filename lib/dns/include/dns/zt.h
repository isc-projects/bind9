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

#ifndef	DNS_ZT_H
#define DNS_ZT_H

#include <isc/lang.h>

#include <isc/mem.h>
#include <dns/name.h>
#include <dns/zone.h>
#include <dns/rbt.h>

typedef struct dns_zt dns_zt_t;

ISC_LANG_BEGINDECLS
dns_result_t dns_zt_create(isc_mem_t *mctx, dns_rdataclass_t rdclass,
			   dns_zt_t **zt);
dns_result_t dns_zt_mount(dns_zt_t *zt, dns_zone_t *zone);
dns_result_t dns_zt_unmount(dns_zt_t *zt, dns_zone_t *zone);
dns_result_t dns_zt_find(dns_zt_t *zt, dns_name_t *name,
				dns_name_t *foundname, dns_zone_t **zone);
void dns_zt_detach(dns_zt_t **ztp);
void dns_zt_attach(dns_zt_t *zt, dns_zt_t **ztp);

ISC_LANG_ENDDECLS

#endif
