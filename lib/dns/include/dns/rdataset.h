/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*****
***** Module Info
*****/

/*! \file dns/rdataset.h
 * \brief
 * A DNS rdataset is a handle that can be associated with a collection of
 * rdata all having a common owner name, class, and type.
 *
 * The dns_rdataset_t type is like a "virtual class".  To actually use
 * rdatasets, an implementation of the method suite (e.g. "slabbed rdata") is
 * required.
 *
 * XXX &lt;more&gt; XXX
 *
 * MP:
 *\li	Clients of this module must impose any required synchronization.
 *
 * Reliability:
 *\li	No anticipated impact.
 *
 * Resources:
 *\li	TBS
 *
 * Security:
 *\li	No anticipated impact.
 *
 * Standards:
 *\li	None.
 */

#include <inttypes.h>
#include <stdbool.h>

#include <isc/magic.h>
#include <isc/stdtime.h>

#include <dns/rdataslab.h>
#include <dns/rdatastruct.h>
#include <dns/types.h>

#define DNS_RDATASET_MAXADDITIONAL 13
#define DNS_RDATASET_LENGTH	   2;

typedef enum {
	dns_rdatasetadditional_fromauth,
	dns_rdatasetadditional_fromcache,
	dns_rdatasetadditional_fromglue
} dns_rdatasetadditional_t;

struct dns_rdatasetmethods {
	void (*disassociate)(dns_rdataset_t *rdataset DNS__DB_FLARG);
	isc_result_t (*first)(dns_rdataset_t *rdataset);
	isc_result_t (*next)(dns_rdataset_t *rdataset);
	void (*current)(dns_rdataset_t *rdataset, dns_rdata_t *rdata);
	void (*clone)(dns_rdataset_t	    *source,
		      dns_rdataset_t *target DNS__DB_FLARG);
	unsigned int (*count)(dns_rdataset_t *rdataset);
	isc_result_t (*addnoqname)(dns_rdataset_t *rdataset, dns_name_t *name);
	isc_result_t (*getnoqname)(dns_rdataset_t *rdataset, dns_name_t *name,
				   dns_rdataset_t	 *neg,
				   dns_rdataset_t *negsig DNS__DB_FLARG);
	isc_result_t (*addclosest)(dns_rdataset_t *rdataset, dns_name_t *name);
	isc_result_t (*getclosest)(dns_rdataset_t *rdataset, dns_name_t *name,
				   dns_rdataset_t	 *neg,
				   dns_rdataset_t *negsig DNS__DB_FLARG);
	void (*settrust)(dns_rdataset_t *rdataset, dns_trust_t trust);
	void (*expire)(dns_rdataset_t *rdataset DNS__DB_FLARG);
	void (*clearprefetch)(dns_rdataset_t *rdataset);
	void (*setownercase)(dns_rdataset_t *rdataset, const dns_name_t *name);
	void (*getownercase)(const dns_rdataset_t *rdataset, dns_name_t *name);
	isc_result_t (*addglue)(dns_rdataset_t	*rdataset,
				dns_dbversion_t *version, dns_message_t *msg);
	dns_slabheader_t *(*getheader)(const dns_rdataset_t *rdataset);
	bool (*equals)(const dns_rdataset_t *rdataset1,
		       const dns_rdataset_t *rdataset2);
};

#define DNS_RDATASET_MAGIC	ISC_MAGIC('D', 'N', 'S', 'R')
#define DNS_RDATASET_VALID(set) ISC_MAGIC_VALID(set, DNS_RDATASET_MAGIC)

/*%
 * Direct use of this structure by clients is strongly discouraged, except
 * for the 'link' field which may be used however the client wishes.  The
 * 'private', 'current', and 'index' fields MUST NOT be changed by clients.
 * rdataset implementations may change any of the fields.
 */
struct dns_rdataset {
	unsigned int	       magic;
	dns_rdatasetmethods_t *methods;
	ISC_LINK(dns_rdataset_t) link;

	/*
	 * XXX do we need these, or should they be retrieved by methods?
	 * Leaning towards the latter, since they are not frequently required
	 * once you have the rdataset.
	 */
	dns_rdataclass_t rdclass;
	dns_rdatatype_t	 type;
	dns_ttl_t	 ttl;

	dns_trust_t	trust;
	dns_rdatatype_t covers;

	struct {
		bool question	 : 1;
		bool rendered	 : 1; /*%< message.c: was rendered */
		bool answered	 : 1; /*%< server. */
		bool cache	 : 1; /*%< resolver. */
		bool answer	 : 1; /*%< resolver. */
		bool answersig	 : 1; /*%< resolver. */
		bool external	 : 1; /*%< resolver. */
		bool ncache	 : 1; /*%< resolver. */
		bool chaining	 : 1; /*%< resolver. */
		bool ttladjusted : 1; /*%< message.c: data had differing TTL
		       values, and the rdataset->ttl holds the smallest */
		bool	       chase	    : 1; /*%< Used by resolver. */
		bool	       nxdomain	    : 1;
		bool	       noqname	    : 1;
		bool	       checknames   : 1; /*%< Used by resolver. */
		bool	       required	    : 1;
		bool	       resign	    : 1;
		bool	       closest	    : 1;
		bool	       optout	    : 1; /*%< OPTOUT proof */
		bool	       negative	    : 1;
		bool	       prefetch	    : 1;
		bool	       stale	    : 1;
		bool	       ancient	    : 1;
		bool	       stale_window : 1;
		bool	       keepcase	    : 1;
		bool	       staticstub   : 1;
		dns_orderopt_t order	    : 2;
	} attributes;

	/*%
	 * the counter provides the starting point in the "cyclic" order.
	 * The value UINT32_MAX has a special meaning of "picking up a
	 * random value." in order to take care of databases that do not
	 * increment the counter.
	 */
	uint32_t count;

	/*
	 * This RRSIG RRset should be re-generated around this time.
	 * Only valid if 'resign' attribute is set.
	 */
	union {
		isc_stdtime_t resign;
		isc_stdtime_t expire;
	};

	/*%
	 * Extra fields used by various rdataset implementations, that is, by
	 * the code referred to in the rdataset methods table. The names of
	 * the structures roughly correspond to the file containing the
	 * implementation, except that `rdlist` is used by `rdatalist.c`,
	 * and `sdlz.c`, and `slab` by `rdataslab.c`.
	 *
	 * Pointers in these structs use incomplete structure types,
	 * because the structure definitions and corresponding typedef
	 * names might not be in scope in this header.
	 */
	/*@}*/
	union {
		struct {
			struct dns_keynode *node;
			dns_rdata_t	   *iter;
		} keytable;

		/*
		 * An ncache rdataset is a view of memory held elsewhere:
		 * raw can point to either a buffer on the stack or to an
		 * rdataslab, such as in an rbtdb database.
		 */
		struct {
			unsigned char *raw;
			unsigned char *iter_pos;
			unsigned int   iter_count;
		} ncache;

		/*
		 * A slab rdataset provides access to an rdataslab. In
		 * a QP database, 'raw' will generally point to the
		 * memory immediately following a slabheader. (There
		 * is an exception in the case of rdatasets returned by
		 * the `getnoqname` and `getclosest` methods; see
		 * comments in rdataslab.c for details.)
		 */
		struct {
			struct dns_db	       *db;
			dns_dbnode_t	       *node;
			unsigned char	       *raw;
			unsigned char	       *iter_pos;
			unsigned int		iter_count;
			dns_slabheader_proof_t *noqname, *closest;
		} slab;

		/*
		 * A simple rdatalist, plus an optional dbnode used by
		 * builtin and sdlz.
		 */
		struct {
			struct dns_rdatalist *list;
			struct dns_rdata     *iter;

			/*
			 * These refer to names passed in by the caller of
			 * dns_rdataset_addnoqname() and _addclosest()
			 */
			struct dns_name *noqname, *closest;
			dns_dbnode_t	*node;
		} rdlist;
	};
};

#define DNS_RDATASET_COUNT_UNDEFINED UINT32_MAX

#define DNS_RDATASET_INIT               \
	{ .magic = DNS_RDATASET_MAGIC,  \
	  .link = ISC_LINK_INITIALIZER, \
	  .count = DNS_RDATASET_COUNT_UNDEFINED }

/* clang-format off */
/*
 * This is a hack to build a unique variable name to
 * replace 'res' below. (Two layers of macro indirection are
 * needed to make the line number be part of the variable
 * name; otherwise it would just be "x__LINE__".)
 */
#define DNS__RDATASET_CONNECT(x,y) x##y
#define DNS__RDATASET_CONCAT(x,y) DNS__RDATASET_CONNECT(x,y)
#define DNS_RDATASET_FOREACH_RES(rds, res)                         \
	for (isc_result_t res = dns_rdataset_first((rds));       \
	     res == ISC_R_SUCCESS; res = dns_rdataset_next((rds)))
#define DNS_RDATASET_FOREACH(rds)               \
	DNS_RDATASET_FOREACH_RES(rds, DNS__RDATASET_CONCAT(x, __LINE__))
/* clang-format on */

/*%
 * _OMITDNSSEC:
 * 	Omit DNSSEC records when rendering ncache records.
 */
#define DNS_RDATASETTOWIRE_OMITDNSSEC 0x0001

void
dns_rdataset_init(dns_rdataset_t *rdataset);
/*%<
 * Make 'rdataset' a valid, disassociated rdataset.
 *
 * Requires:
 *\li	'rdataset' is not NULL.
 *
 * Ensures:
 *\li	'rdataset' is a valid, disassociated rdataset.
 */

void
dns_rdataset_invalidate(dns_rdataset_t *rdataset);
/*%<
 * Invalidate 'rdataset'.
 *
 * Requires:
 *\li	'rdataset' is a valid, disassociated rdataset.
 *
 * Ensures:
 *\li	If assertion checking is enabled, future attempts to use 'rdataset'
 *	without initializing it will cause an assertion failure.
 */

#define dns_rdataset_disassociate(rdataset) \
	dns__rdataset_disassociate(rdataset DNS__DB_FILELINE)
void
dns__rdataset_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG);
/*%<
 * Disassociate 'rdataset' from its rdata, allowing it to be reused.
 *
 * Notes:
 *\li	The client must ensure it has no references to rdata in the rdataset
 *	before disassociating.
 *
 * Requires:
 *\li	'rdataset' is a valid, associated rdataset.
 *
 * Ensures:
 *\li	'rdataset' is a valid, disassociated rdataset.
 */

bool
dns_rdataset_isassociated(dns_rdataset_t *rdataset);
/*%<
 * Is 'rdataset' associated?
 *
 * Requires:
 *\li	'rdataset' is a valid rdataset.
 *
 * Returns:
 *\li	#true			'rdataset' is associated.
 *\li	#false			'rdataset' is not associated.
 */

void
dns_rdataset_makequestion(dns_rdataset_t *rdataset, dns_rdataclass_t rdclass,
			  dns_rdatatype_t type);
/*%<
 * Make 'rdataset' a valid, associated, question rdataset, with a
 * question class of 'rdclass' and type 'type'.
 *
 * Notes:
 *\li	Question rdatasets have a class and type, but no rdata.
 *
 * Requires:
 *\li	'rdataset' is a valid, disassociated rdataset.
 *
 * Ensures:
 *\li	'rdataset' is a valid, associated, question rdataset.
 */

#define dns_rdataset_clone(source, target) \
	dns__rdataset_clone(source, target DNS__DB_FILELINE)
void
dns__rdataset_clone(dns_rdataset_t	  *source,
		    dns_rdataset_t *target DNS__DB_FLARG);
/*%<
 * Make 'target' refer to the same rdataset as 'source'.
 *
 * Requires:
 *\li	'source' is a valid, associated rdataset.
 *
 *\li	'target' is a valid, dissociated rdataset.
 *
 * Ensures:
 *\li	'target' references the same rdataset as 'source'.
 */

unsigned int
dns_rdataset_count(dns_rdataset_t *rdataset);
/*%<
 * Return the number of records in 'rdataset'.
 *
 * Requires:
 *\li	'rdataset' is a valid, associated rdataset.
 *
 * Returns:
 *\li	The number of records in 'rdataset'.
 */

isc_result_t
dns_rdataset_first(dns_rdataset_t *rdataset);
/*%<
 * Move the rdata cursor to the first rdata in the rdataset (if any).
 *
 * Requires:
 *\li	'rdataset' is a valid, associated rdataset.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMORE			There are no rdata in the set.
 *
 * Ensures:
 *\li	No other value is returned.
 */

isc_result_t
dns_rdataset_next(dns_rdataset_t *rdataset);
/*%<
 * Move the rdata cursor to the next rdata in the rdataset (if any).
 *
 * Requires:
 *\li	'rdataset' is a valid, associated rdataset.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMORE			There are no more rdata in the set.
 *
 * Ensures:
 *\li	No other value is returned.
 */

void
dns_rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata);
/*%<
 * Make 'rdata' refer to the current rdata.
 *
 * Notes:
 *
 *\li	The data returned in 'rdata' is valid for the life of the
 *	rdataset; in particular, subsequent changes in the cursor position
 *	do not invalidate 'rdata'.
 *
 * Requires:
 *\li	'rdataset' is a valid, associated rdataset.
 *
 *\li	The rdata cursor of 'rdataset' is at a valid location (i.e. the
 *	result of last call to a cursor movement command was ISC_R_SUCCESS).
 *
 * Ensures:
 *\li	'rdata' refers to the rdata at the rdata cursor location of
 *\li	'rdataset'.
 */

isc_result_t
dns_rdataset_totext(dns_rdataset_t *rdataset, const dns_name_t *owner_name,
		    bool omit_final_dot, bool question, isc_buffer_t *target);
/*%<
 * Convert 'rdataset' to text format, storing the result in 'target'.
 *
 * Notes:
 *\li	The rdata cursor position will be changed.
 *
 *\li	The 'question' flag should normally be #false.  If it is
 *	#true, the TTL and rdata fields are not printed.  This is
 *	for use when printing an rdata representing a question section.
 *
 *\li	This interface is deprecated; use dns_master_rdatasettottext()
 * 	and/or dns_master_questiontotext() instead.
 *
 * Requires:
 *\li	'rdataset' is a valid rdataset.
 *
 *\li	'rdataset' is not empty.
 */

isc_result_t
dns_rdataset_towire(dns_rdataset_t *rdataset, const dns_name_t *owner_name,
		    dns_compress_t *cctx, isc_buffer_t *target,
		    unsigned int options, unsigned int *countp);
/*%<
 * Convert 'rdataset' to wire format, compressing names as specified
 * in 'cctx', and storing the result in 'target'.
 *
 * Notes:
 *\li	The rdata cursor position will be changed.
 *
 *\li	The number of RRs added to target will be added to *countp.
 *
 * Requires:
 *\li	'rdataset' is a valid rdataset.
 *
 *\li	'rdataset' is not empty.
 *
 *\li	'countp' is a valid pointer.
 *
 * Ensures:
 *\li	On a return of ISC_R_SUCCESS, 'target' contains a wire format
 *	for the data contained in 'rdataset'.  Any error return leaves
 *	the buffer unchanged.
 *
 *\li	*countp has been incremented by the number of RRs added to
 *	target.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS		- all ok
 *\li	#ISC_R_NOSPACE		- 'target' doesn't have enough room
 *
 *\li	Any error returned by dns_rdata_towire(), dns_rdataset_next(),
 *	dns_name_towire().
 */

isc_result_t
dns_rdataset_towirepartial(dns_rdataset_t   *rdataset,
			   const dns_name_t *owner_name, dns_compress_t *cctx,
			   isc_buffer_t *target, unsigned int options,
			   unsigned int *countp, void **state);
/*%<
 * Like dns_rdataset_towire() except that a partial rdataset may be written.
 *
 * Requires:
 *\li	All the requirements of dns_rdataset_towiresorted().
 *	If 'state' is non NULL then the current position in the
 *	rdataset will be remembered if the rdataset in not
 *	completely written and should be passed on on subsequent
 *	calls (NOT CURRENTLY IMPLEMENTED).
 *
 * Returns:
 *\li	#ISC_R_SUCCESS if all of the records were written.
 *\li	#ISC_R_NOSPACE if unable to fit in all of the records. *countp
 *		      will be updated to reflect the number of records
 *		      written.
 */

isc_result_t
dns_rdataset_additionaldata(dns_rdataset_t	    *rdataset,
			    const dns_name_t	    *owner_name,
			    dns_additionaldatafunc_t add, void *arg,
			    size_t limit);
/*%<
 * For each rdata in rdataset, call 'add' for each name and type in the
 * rdata which is subject to additional section processing.
 *
 * Requires:
 *
 *\li	'rdataset' is a valid, non-question rdataset.
 *
 *\li	'add' is a valid dns_additionaldatafunc_t
 *
 * Ensures:
 *
 *\li	If successful, dns_rdata_additionaldata() will have been called for
 *	each rdata in 'rdataset'.
 *
 *\li	If a call to dns_rdata_additionaldata() is not successful, the
 *	result returned will be the result of dns_rdataset_additionaldata().
 *
 *\li	If the 'limit' is non-zero and the number of the rdatasets is larger
 *	than the 'limit', no additional data will be generated.
 *
 * Returns:
 *
 *\li	#ISC_R_SUCCESS
 *
 *\li	#DNS_R_TOOMANYRECORDS in case rdataset count is larger than 'limit'
 *
 *\li	Any error that dns_rdata_additionaldata() can return.
 */

#define dns_rdataset_getnoqname(rdataset, name, neg, negsig) \
	dns__rdataset_getnoqname(rdataset, name, neg, negsig DNS__DB_FILELINE)
isc_result_t
dns__rdataset_getnoqname(dns_rdataset_t *rdataset, dns_name_t *name,
			 dns_rdataset_t	       *neg,
			 dns_rdataset_t *negsig DNS__DB_FLARG);
/*%<
 * Return the noqname proof for this record.
 *
 * Requires:
 *\li	'rdataset' to be valid and 'noqname' attribute to be set.
 *\li	'name' to be valid.
 *\li	'neg' and 'negsig' to be valid and not associated.
 */

isc_result_t
dns_rdataset_addnoqname(dns_rdataset_t *rdataset, dns_name_t *name);
/*%<
 * Associate a noqname proof with this record.
 * Sets 'noqname' attribute if successful.
 * Adjusts the 'rdataset->ttl' to minimum of the 'rdataset->ttl' and
 * the 'nsec'/'nsec3' and 'rrsig(nsec)'/'rrsig(nsec3)' ttl.
 *
 * Requires:
 *\li	'rdataset' to be valid and 'noqname' attribute to be set.
 *\li	'name' to be valid and have NSEC or NSEC3 and associated RRSIG
 *	 rdatasets.
 */

#define dns_rdataset_getclosest(rdataset, name, nsec, nsecsig) \
	dns__rdataset_getclosest(rdataset, name, nsec, nsecsig DNS__DB_FILELINE)
isc_result_t
dns__rdataset_getclosest(dns_rdataset_t *rdataset, dns_name_t *name,
			 dns_rdataset_t		*nsec,
			 dns_rdataset_t *nsecsig DNS__DB_FLARG);
/*%<
 * Return the closest encloser for this record.
 *
 * Requires:
 *\li	'rdataset' to be valid and 'closest' attribute to be set.
 *\li	'name' to be valid.
 *\li	'nsec' and 'nsecsig' to be valid and not associated.
 */

isc_result_t
dns_rdataset_addclosest(dns_rdataset_t *rdataset, dns_name_t *name);
/*%<
 * Associate a closest encloset proof with this record.
 * Sets 'closest' attribute if successful.
 * Adjusts the 'rdataset->ttl' to minimum of the 'rdataset->ttl' and
 * the 'nsec' and 'rrsig(nsec)' ttl.
 *
 * Requires:
 *\li	'rdataset' to be valid and 'closest' attribute to be set.
 *\li	'name' to be valid and have NSEC3 and RRSIG(NSEC3) rdatasets.
 */

void
dns_rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust);
/*%<
 * Set the trust of the 'rdataset' to trust in any in the backing database.
 * The local trust level of 'rdataset' is also set.
 */

#define dns_rdataset_expire(rdataset) \
	dns__rdataset_expire(rdataset DNS__DB_FILELINE)
void
dns__rdataset_expire(dns_rdataset_t *rdataset DNS__DB_FLARG);
/*%<
 * Mark the rdataset to be expired in the backing database.
 */

void
dns_rdataset_clearprefetch(dns_rdataset_t *rdataset);
/*%<
 * Clear the PREFETCH attribute for the given rdataset in the
 * underlying database.
 *
 * In the cache database, this signals that the rdataset is not
 * eligible to be prefetched when the TTL is close to expiring.
 * It has no function in other databases.
 */

void
dns_rdataset_setownercase(dns_rdataset_t *rdataset, const dns_name_t *name);
/*%<
 * Store the casing of 'name', the owner name of 'rdataset', into
 * a bitfield so that the name can be capitalized the same when when
 * the rdataset is used later. This sets the CASESET attribute.
 */

void
dns_rdataset_getownercase(const dns_rdataset_t *rdataset, dns_name_t *name);
/*%<
 * If the CASESET attribute is set, retrieve the case bitfield that was
 * previously stored by dns_rdataset_getownername(), and capitalize 'name'
 * according to it. If CASESET is not set, do nothing.
 */

void
dns_rdataset_trimttl(dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset,
		     dns_rdata_rrsig_t *rrsig, isc_stdtime_t now,
		     bool acceptexpired);
/*%<
 * Trim the ttl of 'rdataset' and 'sigrdataset' so that they will expire
 * at or before 'rrsig->expiretime'.  If 'acceptexpired' is true and the
 * signature has expired or will expire in the next 120 seconds, limit
 * the ttl to be no more than 120 seconds.
 *
 * The ttl is further limited by the original ttl as stored in 'rrsig'
 * and the original ttl values of 'rdataset' and 'sigrdataset'.
 *
 * Requires:
 * \li	'rdataset' is a valid rdataset.
 * \li	'sigrdataset' is a valid rdataset.
 * \li	'rrsig' is non NULL.
 */

const char *
dns_trust_totext(dns_trust_t trust);
/*%<
 * Display trust in textual form.
 */

dns_slabheader_t *
dns_rdataset_getheader(const dns_rdataset_t *rdataset);
/*%<
 * Return a pointer to the slabheader for a slab rdataset. If 'rdataset'
 * is not a slab rdataset or if the slab is raw (lacking a header), return
 * NULL.
 *
 * Requires:
 * \li	'rdataset' is a valid rdataset.
 */

bool
dns_rdataset_equals(const dns_rdataset_t *rdataset1,
		    const dns_rdataset_t *rdataset2);
/*%<
 * Returns true if the rdata in the rdataset is equal.
 *
 * Requires:
 * \li	'rdataset1' is a valid rdataset.
 * \li	'rdataset2' is a valid rdataset.
 */

/*%
 * Returns true if the rdataset is of type 'type', or type RRSIG
 * and covers 'type'.
 */
static inline bool
dns_rdataset_matchestype(const dns_rdataset_t *rdataset,
			 const dns_rdatatype_t type) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));

	return rdataset->type == type ||
	       (rdataset->type == dns_rdatatype_rrsig &&
		rdataset->covers == type);
}

/*%
 * Returns true if the rdataset is of type 'type', or type RRSIG
 * and covers 'type'.
 */
static inline bool
dns_rdataset_issigtype(const dns_rdataset_t *rdataset,
		       const dns_rdatatype_t type) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));

	return rdataset->type == dns_rdatatype_rrsig &&
	       rdataset->covers == type;
}
