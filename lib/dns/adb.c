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

#include <config.h>

#include <dns/address.h>

#define DNS_ADB_MAGIC		0x44616462	/* Dadb. */
#define DNS_ADB_VALID(x)	((x) != NULL && (x)->magic == DNS_ADB_MAGIC)

struct dns_adb {
	unsigned int	magic;
};

struct dns_adbhandle {
};

struct dns_adbentry {
};

isc_result_t
dns_adb_create(isc_mem_t *mem, dns_adb_t **newadb)
{
	return (ISC_R_NOTIMPLEMENTED);
}

void
dns_adb_destroy(dns_adb_t **adb)
{
}

isc_result_t
dns_adb_lookup(dns_adb_t *adb, isc_task_t *task, isc_taskaction_t *action,
	       void *arg, dns_rdataset_t *nsdataset, dns_name_t *zone,
	       dns_adbhandle_t **handle)
{
	return (ISC_R_NOTIMPLEMENTED);
}

void
dns_adb_cancel(dns_adb_t *adb, dns_adbhandle_t *adbhandle)
{
}

void
dns_adb_done(dns_adb_t *adb, dns_adbhandle_t *adbhandle)
{
}
