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

#include <isc/assertions.h>

#include <dns/address.h>

#define VCHECK(a,b)		(((a) != NULL) && ((a)->magic == (b)))

#define DNS_ADB_MAGIC			0x44616462	/* Dadb. */
#define DNS_ADB_VALID(x)		VCHECK(x, DNS_ADB_MAGIC)
#define DNS_ADBNAME_MAGIC		0x6164624e	/* adbN. */
#define DNS_ADBNAME_VALID(x)		VCHECK(x, DNS_ADBNAME_MAGIC)
#define DNS_ADBNAMEHOOK_MAGIC		0x61644e48	/* adNH. */
#define DNS_ADBNAMEHOOK_VALID(x)	VCHECK(x, DNS_ADBNAMEHOOK_MAGIC)
#define DNS_ADBZONEINFO_MAGIC		0x6164625a	/* adbZ. */
#define DNS_ADBZONEINFO_VALID(x)	VCHECK(x, DNS_ADBZONEINFO_MAGIC)
#define DNS_ADBENTRY_MAGIC		0x61646245	/* adbE. */
#define DNS_ADBENTRY_VALID(x)		VCHECK(x, DNS_ADBENTRY_MAGIC)
#define DNS_ADBHANDLE_MAGIC		0x61646248	/* adbH. */
#define DNS_ADBHANDLE_VALID(x)		VCHECK(x, DNS_ADBHANDLE_MAGIC)
#define DNS_ADBADDRINFO_MAGIC		0x61644149	/* adAI. */
#define DNS_ADBADDRINFO_VALID(x)	VCHECK(x, DNS_ADBADDRINFO_MAGIC)

typedef struct dns_adbname dns_adbname_t;
typedef struct dns_adbnamehook dns_adbnamehook_t;
typedef struct dns_adbzoneinfo dns_adbzoneinfo_t;

struct dns_adb {
	unsigned int			magic;

	isc_mutex_t			lock;
	isc_mem_t		       *mctx;

	isc_mempool_t		       *nmp;	/* dns_adbname_t */
	isc_mempool_t		       *nhmp;	/* dns_adbnamehook_t */
	isc_mempool_t		       *zimp;	/* dns_adbzoneinfo_t */
	isc_mempool_t		       *emp;	/* dns_adbentry_t */
	isc_mempool_t		       *ahmp;	/* dns_adbhandle_t */
	isc_mempool_t		       *aimp;	/* dns_adbaddrinfo_t */

	ISC_LIST(dns_adbname_t)		names;
};

struct dns_adbname {
	unsigned int			magic;
	dns_name_t		       *name;
	ISC_LIST(dns_adbnamehook_t)	namehooks;
};

/*
 * dns_adbnamehook_t
 *
 * This is a small widget that dangles off a dns_adbname_t.  It contains a
 * pointer to the address information about this host, and a link to the next
 * namehook that will contain the next address this host has.
 */
struct dns_adbnamehook {
	unsigned int			magic;
	dns_adbentry_t		       *address;
	ISC_LINK(dns_adbnamehook_t)	link;
};

/*
 * dns_adbzoneinfo_t
 *
 * This is a small widget that holds zone-specific information about an
 * address.  Currently limited to lameness, but could just as easily be
 * extended to other types of information about zones.
 */
struct dns_adbzoneinfo {
	unsigned int			magic;

	dns_name_t		       *zone;
	unsigned int			lame_timer;

	ISC_LINK(dns_adbzoneinfo_t)	link;
};

/*
 * An address entry.  It holds quite a bit of information about addresses,
 * including edns state, rtt, and of course the address of the host.
 */
struct dns_adbentry {
	unsigned int			magic;

	unsigned int			lock_bucket;
	unsigned int			refcount;

	unsigned int			flags;
	int				goodness;	/* bad <= 0 < good */
	unsigned int			srtt;
	isc_sockaddr_t			sockaddr;

	ISC_LIST(dns_adbzoneinfo_t)	zoneinfo;

	ISC_LINK(dns_adbentry_t)	link;
};

/*
 * dns_adbhandle_t
 *
 * This is returned to the user, and contains all the state we need to do
 * more fetches, return more information to the user, and to return the
 * address list itself.
 */
struct dns_adbhandle {
	unsigned int			magic;

	dns_adb_t		       *adb;

	isc_task_t		       *task;
	isc_taskaction_t	       *taskaction;
	void			       *arg;
	dns_name_t		       *zone;

	dns_adbaddrlist_t		addrlist;

	ISC_LINK(dns_adbhandle_t)	link;
};

/*
 * Internal functions.
 */

/*
 * Public functions.
 */

isc_result_t
dns_adb_create(isc_mem_t *mem, dns_adb_t **newadb)
{
	REQUIRE(mem != NULL);
	REQUIRE(newadb != NULL && *newadb == NULL);

	return (ISC_R_NOTIMPLEMENTED);
}

void
dns_adb_destroy(dns_adb_t **adb)
{
	REQUIRE(adb != NULL);
	REQUIRE(DNS_ADB_VALID(*adb));

	INSIST(1 == 0);
}

isc_result_t
dns_adb_lookup(dns_adb_t *adb, isc_task_t *task, isc_taskaction_t *action,
	       void *arg, dns_rdataset_t *nsrdataset, dns_name_t *zone,
	       dns_adbhandle_t **handle)
{
	REQUIRE(DNS_ADB_VALID(adb));
	if (task != NULL) {
		REQUIRE(action != NULL);
	}
	REQUIRE(nsrdataset != NULL);
	REQUIRE(zone != NULL);
	REQUIRE(handle != NULL && *handle == NULL);

	return (ISC_R_NOTIMPLEMENTED);
}

void
dns_adb_cancel(dns_adb_t *adb, dns_adbhandle_t **handle)
{
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(handle != NULL && DNS_ADBHANDLE_VALID(*handle));

	INSIST(1 == 0);
}

void
dns_adb_done(dns_adb_t *adb, dns_adbhandle_t **handle)
{
	REQUIRE(DNS_ADB_VALID(adb));
	REQUIRE(handle != NULL && DNS_ADBHANDLE_VALID(*handle));

	INSIST(1 == 0);
}
