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

/***
 *** Imports
 ***/

#include <config.h>

#include <stddef.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/boolean.h>
#include <isc/region.h>
#include <isc/types.h>

#include <dns/message.h>
#include <dns/rdataset.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/rdatalist.h>
#include <dns/compress.h>

#define MESSAGE_MAGIC		0x4d534740U	/* MSG@ */
#define VALID_MESSAGE(msg)	(((msg)->magic) == MESSAGE_MAGIC)

#define VALID_NAMED_SECTION(s)  (((s) > DNS_SECTION_ANY) \
				 && ((s) < DNS_SECTION_MAX))
#define VALID_SECTION(s)	(((s) >= DNS_SECTION_ANY) \
				 && ((s) < DNS_SECTION_MAX))

/*
 * This is the size of each individual scratchpad buffer, and the numbers
 * of various block allocations used within the server.
 */
#define SCRATCHPAD_SIZE		512
#define NAME_COUNT		 16
#define RDATA_COUNT		 32
#define RDATALIST_COUNT		 32 /* should match RDATASET_COUNT */
#define RDATASET_COUNT		 32

/*
 * "helper" type, which consists of a block of some type, and is linkable.
 * For it to work, sizeof(dns_msgblock_t) must be a multiple of the pointer
 * size, or the allocated elements will not be alligned correctly.
 */
struct dns_msgblock {
	unsigned int			length;
	unsigned int			remaining;
	ISC_LINK(dns_msgblock_t)	link;
}; /* dynamically sized */

static inline void
msgblock_free(isc_mem_t *, dns_msgblock_t *);

#define msgblock_get(block, type) \
	((type *)msgblock_internalget(block, sizeof(type)))

static inline void *
msgblock_internalget(dns_msgblock_t *, unsigned int);

static inline void
msgblock_reset(dns_msgblock_t *, unsigned int);

static inline dns_msgblock_t *
msgblock_allocate(isc_mem_t *, unsigned int, unsigned int);

/*
 * Allocate a new dns_msgblock_t, and return a pointer to it.  If no memory
 * is free, return NULL.
 */
static inline dns_msgblock_t *
msgblock_allocate(isc_mem_t *mctx, unsigned int sizeof_type,
		  unsigned int count)
{
	dns_msgblock_t *block;
	unsigned int length;

	length = sizeof(dns_msgblock_t) + (sizeof_type * count);

	block = isc_mem_get(mctx, length);
	if (block == NULL)
		return NULL;

	block->length = length;
	block->remaining = count;

	ISC_LINK_INIT(block, link);

	return (block);
}

/*
 * Return an element from the msgblock.  If no more are available, return
 * NULL.
 */
static inline void *
msgblock_internalget(dns_msgblock_t *block, unsigned int sizeof_type)
{
	void *ptr;

	if (block->remaining == 0)
		return (NULL);

	block->remaining--;

	ptr = (((unsigned char *)block)
	       + sizeof(dns_msgblock_t)
	       + (sizeof_type * block->remaining));

	return (ptr);
}

static inline void
msgblock_reset(dns_msgblock_t *block, unsigned int count)
{
	block->remaining = count;
}

/*
 * Release memory associated with a message block.
 */
static inline void
msgblock_free(isc_mem_t *mctx, dns_msgblock_t *block)
{
	isc_mem_put(mctx, block, block->length);
}

/*
 * Allocate a new dynamic buffer, and attach it to this message as the
 * "current" buffer.  (which is always the last on the list, for our
 * uses)
 */
static inline dns_result_t
newbuffer(dns_message_t *msg)
{
	isc_result_t result;
	isc_dynbuffer_t *dynbuf;

	dynbuf = NULL;
	result = isc_dynbuffer_allocate(msg->mctx, &dynbuf, SCRATCHPAD_SIZE,
					ISC_BUFFERTYPE_BINARY);
	if (result != ISC_R_SUCCESS)
		return (DNS_R_NOMEMORY);

	ISC_LIST_APPEND(msg->scratchpad, dynbuf, link);
	return (DNS_R_SUCCESS);
}

static inline isc_buffer_t *
currentbuffer(dns_message_t *msg)
{
	isc_dynbuffer_t *dynbuf;

	dynbuf = ISC_LIST_TAIL(msg->scratchpad);

	return (&dynbuf->buffer);
}

static inline void
releasename(dns_message_t *msg, dns_name_t *name)
{
	msg->nextname = name;
}

static inline dns_name_t *
newname(dns_message_t *msg)
{
	dns_msgblock_t *msgblock;
	dns_name_t *name;

	if (msg->nextname != NULL) {
		name = msg->nextname;
		msg->nextname = NULL;
		dns_name_init(name, NULL);
		return (name);
	}

	msgblock = ISC_LIST_HEAD(msg->names);
	name = msgblock_get(msgblock, dns_name_t);
	if (name == NULL) {
		msgblock = msgblock_allocate(msg->mctx, sizeof(dns_name_t),
					     NAME_COUNT);
		if (msgblock == NULL)
			return (NULL);

		ISC_LIST_APPEND(msg->names, msgblock, link);

		name = msgblock_get(msgblock, dns_name_t);
	}

	dns_name_init(name, NULL);
	return (name);
}

static inline void
releaserdata(dns_message_t *msg, dns_rdata_t *rdata)
{
	msg->nextrdata = rdata;
}

static inline dns_rdata_t *
newrdata(dns_message_t *msg)
{
	dns_msgblock_t *msgblock;
	dns_rdata_t *rdata;

	if (msg->nextrdata != NULL) {
		rdata = msg->nextrdata;
		msg->nextrdata = NULL;
		return (rdata);
	}

	msgblock = ISC_LIST_HEAD(msg->rdatas);
	rdata = msgblock_get(msgblock, dns_rdata_t);
	if (rdata == NULL) {
		msgblock = msgblock_allocate(msg->mctx, sizeof(dns_rdata_t),
					     RDATA_COUNT);
		if (msgblock == NULL)
			return (NULL);

		ISC_LIST_APPEND(msg->rdatas, msgblock, link);

		rdata = msgblock_get(msgblock, dns_rdata_t);
	}

	return (rdata);
}

static inline void
releaserdatalist(dns_message_t *msg, dns_rdatalist_t *rdatalist)
{
	msg->nextrdatalist = rdatalist;
}

static inline dns_rdatalist_t *
newrdatalist(dns_message_t *msg)
{
	dns_msgblock_t *msgblock;
	dns_rdatalist_t *rdatalist;

	if (msg->nextrdatalist != NULL) {
		rdatalist = msg->nextrdatalist;
		msg->nextrdatalist = NULL;
		return (rdatalist);
	}

	msgblock = ISC_LIST_HEAD(msg->rdatalists);
	rdatalist = msgblock_get(msgblock, dns_rdatalist_t);
	if (rdatalist == NULL) {
		msgblock = msgblock_allocate(msg->mctx,
					     sizeof(dns_rdatalist_t),
					     RDATALIST_COUNT);
		if (msgblock == NULL)
			return (NULL);

		ISC_LIST_APPEND(msg->rdatalists, msgblock, link);

		rdatalist = msgblock_get(msgblock, dns_rdatalist_t);
	}

	return (rdatalist);
}

static inline void
releaserdataset(dns_message_t *msg, dns_rdataset_t *rdataset)
{
	msg->nextrdataset = rdataset;
}

static inline dns_rdataset_t *
newrdataset(dns_message_t *msg)
{
	dns_msgblock_t *msgblock;
	dns_rdataset_t *rdataset;

	if (msg->nextrdataset != NULL) {
		rdataset = msg->nextrdataset;
		msg->nextrdataset = NULL;
		return (rdataset);
	}

	msgblock = ISC_LIST_HEAD(msg->rdatasets);
	rdataset = msgblock_get(msgblock, dns_rdataset_t);
	if (rdataset == NULL) {
		msgblock = msgblock_allocate(msg->mctx, sizeof(dns_rdataset_t),
					     RDATASET_COUNT);
		if (msgblock == NULL)
			return (NULL);

		ISC_LIST_APPEND(msg->rdatasets, msgblock, link);

		rdataset = msgblock_get(msgblock, dns_rdataset_t);
	}

	return (rdataset);
}

/*
 * Init elements to default state.  Used both when allocating a new element
 * and when resetting one.
 */
static inline void
msginit(dns_message_t *m)
{
	unsigned int i;

	m->id = 0;
	m->flags = 0;
	m->rcode = 0;
	m->opcode = 0;
	m->rdclass = 0;

	for (i = 0 ; i < DNS_SECTION_MAX ; i++) {
		m->cursors[i] = NULL;
		m->counts[i] = NULL;
	}

	m->state = DNS_SECTION_ANY;  /* indicate nothing parsed or rendered */

	m->nextname = NULL;
	m->nextrdata = NULL;
	m->nextrdataset = NULL;
	m->nextrdatalist = NULL;

	m->buffer = NULL;
	m->need_cctx_cleanup = ISC_FALSE;
}

/*
 * Free all but one (or everything) for this message.  This is used by
 * both dns_message_reset() and dns_message_parse().
 */
static void
msgreset(dns_message_t *msg, isc_boolean_t everything)
{
	dns_msgblock_t *msgblock, *next_msgblock;
	isc_dynbuffer_t *dynbuf, *next_dynbuf;
	dns_rdataset_t *rds, *next_rds;
	dns_name_t *name, *next_name;
	unsigned int i;

	/*
	 * Clean up name lists by calling the rdataset disassociate function.
	 */
	for (i = 0 ; i < DNS_SECTION_MAX ; i++) {
		name = ISC_LIST_HEAD(msg->sections[i]);
		while (name != NULL) {
			next_name = ISC_LIST_NEXT(name, link);
			ISC_LIST_UNLINK(msg->sections[i], name, link);

			rds = ISC_LIST_HEAD(name->list);
			while (rds != NULL) {
				next_rds = ISC_LIST_NEXT(rds, link);
				ISC_LIST_UNLINK(name->list, rds, link);

				dns_rdataset_disassociate(rds);
				rds = next_rds;
			}
			name = next_name;
		}
	}

	/*
	 * Clean up linked lists.
	 */

	dynbuf = ISC_LIST_HEAD(msg->scratchpad);
	INSIST(dynbuf != NULL);
	if (everything == ISC_FALSE) {
		isc_dynbuffer_reset(dynbuf);
		dynbuf = ISC_LIST_NEXT(dynbuf, link);
	}
	while (dynbuf != NULL) {
		next_dynbuf = ISC_LIST_NEXT(dynbuf, link);
		ISC_LIST_UNLINK(msg->scratchpad, dynbuf, link);
		isc_dynbuffer_free(msg->mctx, &dynbuf);
		dynbuf = next_dynbuf;
	}

	msgblock = ISC_LIST_HEAD(msg->names);
	INSIST(msgblock != NULL);
	if (everything == ISC_FALSE) {
		msgblock_reset(msgblock, NAME_COUNT);
		msgblock = ISC_LIST_NEXT(msgblock, link);
	}
	while (msgblock != NULL) {
		next_msgblock = ISC_LIST_NEXT(msgblock, link);
		ISC_LIST_UNLINK(msg->names, msgblock, link);
		msgblock_free(msg->mctx, msgblock);
		msgblock = next_msgblock;
	}

	msgblock = ISC_LIST_HEAD(msg->rdatas);
	INSIST(msgblock != NULL);
	if (everything == ISC_FALSE) {
		msgblock_reset(msgblock, RDATA_COUNT);
		msgblock = ISC_LIST_NEXT(msgblock, link);
	}
	while (msgblock != NULL) {
		next_msgblock = ISC_LIST_NEXT(msgblock, link);
		ISC_LIST_UNLINK(msg->rdatas, msgblock, link);
		msgblock_free(msg->mctx, msgblock);
		msgblock = next_msgblock;
	}

	msgblock = ISC_LIST_HEAD(msg->rdatasets);
	INSIST(msgblock != NULL);
	if (everything == ISC_FALSE) {
		msgblock_reset(msgblock, RDATASET_COUNT);
		msgblock = ISC_LIST_NEXT(msgblock, link);
	}
	while (msgblock != NULL) {
		next_msgblock = ISC_LIST_NEXT(msgblock, link);
		ISC_LIST_UNLINK(msg->rdatasets, msgblock, link);
		msgblock_free(msg->mctx, msgblock);
		msgblock = next_msgblock;
	}

	if (msg->from_to_wire == DNS_MESSAGE_INTENT_PARSE) {
		msgblock = ISC_LIST_HEAD(msg->rdatalists);
		INSIST(msgblock != NULL);
		if (everything == ISC_FALSE) {
			msgblock_reset(msgblock, RDATALIST_COUNT);
			msgblock = ISC_LIST_NEXT(msgblock, link);
		}
		while (msgblock != NULL) {
			next_msgblock = ISC_LIST_NEXT(msgblock, link);
			ISC_LIST_UNLINK(msg->rdatalists, msgblock, link);
			msgblock_free(msg->mctx, msgblock);
			msgblock = next_msgblock;
		}
	}

	if (msg->need_cctx_cleanup)
		dns_compress_invalidate(&msg->cctx);

	/*
	 * Set other bits to normal default values.
	 */
	msginit(msg);
}

dns_result_t
dns_message_create(isc_mem_t *mctx, dns_message_t **msg, unsigned int intent)
{
	dns_message_t *m;
	isc_result_t iresult;
	dns_msgblock_t *msgblock;
	isc_dynbuffer_t *dynbuf;
	unsigned int i;

	REQUIRE(mctx != NULL);
	REQUIRE(msg != NULL);
	REQUIRE(*msg == NULL);
	REQUIRE(intent == DNS_MESSAGE_INTENT_PARSE
		|| intent == DNS_MESSAGE_INTENT_RENDER);

	m = isc_mem_get(mctx, sizeof(dns_message_t));
	if (m == NULL)
		return(DNS_R_NOMEMORY);

	m->magic = MESSAGE_MAGIC;
	m->from_to_wire = intent;
	msginit(m);
	for (i = 0 ; i < DNS_SECTION_MAX ; i++)
		ISC_LIST_INIT(m->sections[i]);
	m->mctx = mctx;
	ISC_LIST_INIT(m->scratchpad);
	ISC_LIST_INIT(m->names);
	ISC_LIST_INIT(m->rdatas);
	ISC_LIST_INIT(m->rdatalists);

	dynbuf = NULL;
	iresult = isc_dynbuffer_allocate(mctx, &dynbuf, SCRATCHPAD_SIZE,
					 ISC_BUFFERTYPE_BINARY);
	if (iresult != ISC_R_SUCCESS)
		goto cleanup1;
	ISC_LIST_APPEND(m->scratchpad, dynbuf, link);

	msgblock = msgblock_allocate(mctx, sizeof(dns_name_t),
				     NAME_COUNT);
	if (msgblock == NULL)
		goto cleanup2;
	ISC_LIST_APPEND(m->names, msgblock, link);

	msgblock = msgblock_allocate(mctx, sizeof(dns_rdata_t),
				     RDATA_COUNT);
	if (msgblock == NULL)
		goto cleanup3;
	ISC_LIST_APPEND(m->rdatas, msgblock, link);

	msgblock = msgblock_allocate(mctx, sizeof(dns_rdataset_t),
				     RDATASET_COUNT);
	if (msgblock == NULL)
		goto cleanup4;
	ISC_LIST_APPEND(m->rdatasets, msgblock, link);

	if (intent == DNS_MESSAGE_INTENT_PARSE) {
		msgblock = msgblock_allocate(mctx, sizeof(dns_rdatalist_t),
					     RDATALIST_COUNT);
		if (msgblock == NULL)
			goto cleanup5;
		ISC_LIST_APPEND(m->rdatalists, msgblock, link);
	}

	*msg = m;
	return (DNS_R_SUCCESS);

	/*
	 * Cleanup for error returns.
	 */
 cleanup5:
	msgblock = ISC_LIST_HEAD(m->rdatasets);
	msgblock_free(mctx, msgblock);
 cleanup4:
	msgblock = ISC_LIST_HEAD(m->rdatas);
	msgblock_free(mctx, msgblock);
 cleanup3:
	msgblock = ISC_LIST_HEAD(m->names);
	msgblock_free(mctx, msgblock);
 cleanup2:
	dynbuf = ISC_LIST_HEAD(m->scratchpad);
	isc_dynbuffer_free(mctx, &dynbuf);
 cleanup1:
	m->magic = 0;
	isc_mem_put(mctx, m, sizeof(dns_message_t));

	return (DNS_R_NOMEMORY);
}

void
dns_message_reset(dns_message_t *msg)
{
	msgreset(msg, ISC_FALSE);
}

void
dns_message_destroy(dns_message_t **xmsg)
{
	dns_message_t *msg;

	REQUIRE(xmsg != NULL);
	REQUIRE(VALID_MESSAGE(*xmsg));

	msg = *xmsg;
	*xmsg = NULL;

	msgreset(msg, ISC_TRUE);
	msg->magic = 0;
	isc_mem_put(msg->mctx, msg, sizeof(dns_message_t));
}

static dns_result_t
findname(dns_name_t **foundname, dns_name_t *target, dns_namelist_t *section)
{
	dns_name_t *curr;

	for (curr = ISC_LIST_TAIL(*section) ;
	     curr != NULL ;
	     curr = ISC_LIST_PREV(curr, link)) {
		if (dns_name_compare(curr, target) == 0) {
			if (foundname != NULL)
				*foundname = curr;
			return (DNS_R_SUCCESS);
		}
	}

	return (DNS_R_NOTFOUND);
}

static dns_result_t
findtype(dns_rdataset_t **rdataset, dns_name_t *name, dns_rdatatype_t type)
{
	dns_rdataset_t *curr;

	for (curr = ISC_LIST_TAIL(name->list) ;
	     curr != NULL ;
	     curr = ISC_LIST_PREV(curr, link)) {
		if (curr->type == type) {
			if (rdataset != NULL)
				*rdataset = curr;
			return (DNS_R_SUCCESS);
		}
	}

	return (DNS_R_NOTFOUND);
}

/*
 * Read a name from buffer "source".
 *
 * Assumes dns_name_init() was already called on this name.
 */
static dns_result_t
getname(dns_name_t *name, isc_buffer_t *source, dns_message_t *msg,
	dns_decompress_t *dctx)
{
	isc_buffer_t *scratch;
	dns_result_t result;
	unsigned int tries;

	scratch = currentbuffer(msg);

	if (dns_decompress_edns(dctx) > 1 || !dns_decompress_strict(dctx))
		dns_decompress_setmethods(dctx, DNS_COMPRESS_GLOBAL);
	else
		dns_decompress_setmethods(dctx, DNS_COMPRESS_GLOBAL14);

	tries = 0;
	while (tries < 2) {
		result = dns_name_fromwire(name, source, dctx, ISC_FALSE,
					   scratch);

		if (result == DNS_R_NOSPACE) {
			tries++;

			result = newbuffer(msg);
			if (result != DNS_R_SUCCESS)
				return (result);

			scratch = currentbuffer(msg);
		} else {
			return (result);
		}
	}

	return (DNS_R_UNEXPECTED);  /* should never get here... XXXMLG */
}

static dns_result_t
getrdata(dns_name_t *name, isc_buffer_t *source, dns_message_t *msg,
	 dns_decompress_t *dctx, dns_rdataclass_t rdclass,
	 dns_rdatatype_t rdtype, unsigned int rdatalen, dns_rdata_t *rdata)
{
	isc_buffer_t *scratch;
	dns_result_t result;
	unsigned int tries;

	scratch = currentbuffer(msg);

	isc_buffer_setactive(source, rdatalen);
	dns_decompress_localinit(dctx, name, source);

	tries = 0;
	while (tries < 2) {
		result = dns_rdata_fromwire(rdata, rdclass, rdtype,
					    source, dctx, ISC_FALSE,
					    scratch);

		if (result == DNS_R_NOSPACE) {
			tries++;

			result = newbuffer(msg);
			if (result != DNS_R_SUCCESS)
				return (result);

			scratch = currentbuffer(msg);
		} else {
			return (result);
		}
	}

	return (DNS_R_UNEXPECTED);  /* should never get here... XXXMLG */
}

static dns_result_t
getquestions(isc_buffer_t *source, dns_message_t *msg, dns_decompress_t *dctx)
{
	isc_region_t r;
	unsigned int count;
	dns_name_t *name;
	dns_name_t *name2;
	dns_rdataset_t *rdataset;
	dns_rdatalist_t *rdatalist;
	dns_result_t result;
	dns_rdatatype_t rdtype;
	dns_rdataclass_t rdclass;
	dns_namelist_t *section;

	section = &msg->sections[DNS_SECTION_QUESTION];

	for (count = 0 ; count < msg->counts[DNS_SECTION_QUESTION] ; count++) {
		name = newname(msg);
		if (name == NULL)
			return (DNS_R_NOMEMORY);

		/*
		 * Parse the name out of this packet.
		 */
		isc_buffer_remaining(source, &r);
		isc_buffer_setactive(source, r.length);
		result = getname(name, source, msg, dctx);
		if (result != DNS_R_SUCCESS)
			return (result);

		/*
		 * Run through the section, looking to see if this name
		 * is already there.  If it is found, put back the allocated
		 * name since we no longer need it, and set our name pointer
		 * to point to the name we found.
		 */
		result = findname(&name2, name, section);

		/*
		 * If it is the first name in the section, accept it.
		 *
		 * If it is not, but is not the same as the name already
		 * in the question section, append to the section.  Note that
		 * here in the question section this is illegal, so return
		 * FORMERR.  In the future, check the opcode to see if
		 * this should be legal or not.  In either case we no longer
		 * need this name pointer.
		 */
		if (result != DNS_R_SUCCESS) {
			if (ISC_LIST_EMPTY(*section)) {
				ISC_LIST_APPEND(*section, name, link);
			} else {
				return (DNS_R_FORMERR);
			}
		} else {
			name = name2;
		}

		/*
		 * Get type and class.
		 */
		isc_buffer_remaining(source, &r);
		if (r.length < 4)
			return (DNS_R_UNEXPECTEDEND);
		rdtype = isc_buffer_getuint16(source);
		rdclass = isc_buffer_getuint16(source);

		/*
		 * If this class is different than the one we alrady read,
		 * this is an error.
		 */
		if (msg->state == DNS_SECTION_ANY) {
			msg->state = DNS_SECTION_QUESTION;
			msg->rdclass = rdclass;
		} else if (msg->rdclass != rdclass)
			return (DNS_R_FORMERR);
		
		/*
		 * Search name for the particular type and class.
		 * If it was found, this is an error, return FORMERR.
		 */
		result = findtype(NULL, name, rdtype);

		if (result == DNS_R_SUCCESS)
			return (DNS_R_FORMERR);

		/*
		 * Allocate a new rdatalist.
		 */
		rdatalist = newrdatalist(msg);
		rdataset = newrdataset(msg);

		/*
		 * Convert rdatalist to rdataset, and attach the latter to
		 * the name.
		 */
		rdatalist->type = rdtype;
		rdatalist->rdclass = rdclass;
		rdatalist->ttl = 0;
		ISC_LIST_INIT(rdatalist->rdata);

		dns_rdataset_init(rdataset);
		result = dns_rdatalist_tordataset(rdatalist, rdataset);
		if (result != DNS_R_SUCCESS)
			return (result);

		ISC_LIST_APPEND(name->list, rdataset, link);
	}
	
	return (DNS_R_SUCCESS);
}

static dns_result_t
getsection(isc_buffer_t *source, dns_message_t *msg, dns_decompress_t *dctx,
	   dns_section_t sectionid)
{
	isc_region_t r;
	unsigned int count;
	unsigned int rdatalen;
	dns_name_t *name;
	dns_name_t *name2;
	dns_rdataset_t *rdataset;
	dns_rdatalist_t *rdatalist;
	dns_result_t result;
	dns_rdatatype_t rdtype;
	dns_rdataclass_t rdclass;
	dns_rdata_t *rdata;
	dns_ttl_t ttl;
	dns_namelist_t *section;

	section = &msg->sections[sectionid];

	for (count = 0 ; count < msg->counts[sectionid] ; count++) {
		name = newname(msg);
		if (name == NULL)
			return (DNS_R_NOMEMORY);

		/*
		 * Parse the name out of this packet.
		 */
		isc_buffer_remaining(source, &r);
		isc_buffer_setactive(source, r.length);
		result = getname(name, source, msg, dctx);
		if (result != DNS_R_SUCCESS)
			return (result);

		/*
		 * Run through the section, looking to see if this name
		 * is already there.  If it is found, put back the allocated
		 * name since we no longer need it, and set our name pointer
		 * to point to the name we found.
		 */
		result = findname(&name2, name, section);

		/*
		 * If it is a new name, append to the section.
		 */
		if (result == DNS_R_SUCCESS) {
			releasename(msg, name);
			name = name2;
		} else {
			ISC_LIST_APPEND(*section, name, link);
		}

		/*
		 * Get type, class, ttl, and rdatalen.  Verify that at least
		 * rdatalen bytes remain.  (Some of this is deferred to
		 * later.
		 */
		isc_buffer_remaining(source, &r);
		if (r.length < 10)
			return (DNS_R_UNEXPECTEDEND);
		rdtype = isc_buffer_getuint16(source);
		rdclass = isc_buffer_getuint16(source);

		/*
		 * If this class is different than the one we already read,
		 * this is an error.
		 */
		if (msg->state == DNS_SECTION_ANY) {
			msg->state = sectionid;
			msg->rdclass = rdclass;
		} else if (msg->rdclass != rdclass)
			return (DNS_R_FORMERR);
		
		/*
		 * ... now get ttl and rdatalen, and check buffer.
		 */
		ttl = isc_buffer_getuint32(source);
		rdatalen = isc_buffer_getuint16(source);
		r.length -= 10;
		if (r.length < rdatalen)
			return (DNS_R_UNEXPECTEDEND);

		/*
		 * Search name for the particular type and class.
		 * If it was found, this is an error, return FORMERR.
		 */
		result = findtype(&rdataset, name, rdtype);

		/*
		 * If we found an rdataset that matches, we need to
		 * append this rdata to that set.  If we did not, we need
		 * to create a new rdatalist, store the important bits there,
		 * convert it to an rdataset, and link the latter to the name.
		 * Yuck.
		 */
		if (result != DNS_R_SUCCESS) {
			rdataset = newrdataset(msg);
			if (rdataset == NULL)
				return (DNS_R_NOMEMORY);
			rdatalist = newrdatalist(msg);
			if (rdatalist == NULL)
				return (DNS_R_NOMEMORY);

			rdatalist->type = rdtype;
			rdatalist->rdclass = rdclass;
			rdatalist->ttl = ttl;
			ISC_LIST_INIT(rdatalist->rdata);

			dns_rdataset_init(rdataset);
			dns_rdatalist_tordataset(rdatalist, rdataset);

			ISC_LIST_APPEND(name->list, rdataset, link);
		}

		/*
		 * Read the rdata from the wire format.
		 */
		rdata = newrdata(msg);
		if (rdata == NULL)
			return (DNS_R_NOMEMORY);
		result = getrdata(name, source, msg, dctx,
				  rdclass, rdtype, rdatalen, rdata);
		if (result != DNS_R_SUCCESS)
			return (result);

		/*
		 * XXX Perform a totally ugly hack here to pull
		 * the rdatalist out of the private field in the rdataset,
		 * and append this rdata to the rdatalist's linked list
		 * of rdata.
		 */
		rdatalist = (dns_rdatalist_t *)(rdataset->private1);

		ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
	}
	
	return (DNS_R_SUCCESS);
}

dns_result_t
dns_message_parse(dns_message_t *msg, isc_buffer_t *source)
{
	isc_region_t r;
	dns_decompress_t dctx;
	dns_result_t ret;
	isc_uint16_t tmpflags;

	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(source != NULL);
	REQUIRE(msg->from_to_wire == DNS_MESSAGE_INTENT_PARSE);

	isc_buffer_remaining(source, &r);
	if (r.length < DNS_MESSAGE_HEADER_LEN)
		return (DNS_R_UNEXPECTEDEND);

	msg->id = isc_buffer_getuint16(source);
	tmpflags = isc_buffer_getuint16(source);
	msg->opcode = ((tmpflags & DNS_MESSAGE_OPCODE_MASK)
		       >> DNS_MESSAGE_OPCODE_SHIFT);
	msg->rcode = (tmpflags & DNS_MESSAGE_RCODE_MASK);
	msg->flags = (tmpflags & ~DNS_MESSAGE_FLAG_MASK);
	msg->counts[DNS_SECTION_QUESTION] = isc_buffer_getuint16(source);
	msg->counts[DNS_SECTION_ANSWER] = isc_buffer_getuint16(source);
	msg->counts[DNS_SECTION_AUTHORITY] = isc_buffer_getuint16(source);
	msg->counts[DNS_SECTION_ADDITIONAL] = isc_buffer_getuint16(source);

	dns_decompress_init(&dctx, -1, ISC_FALSE);

	ret = getquestions(source, msg, &dctx);
	if (ret != DNS_R_SUCCESS)
		return (ret);

	ret = getsection(source, msg, &dctx, DNS_SECTION_ANSWER);
	if (ret != DNS_R_SUCCESS)
		return (ret);

	ret = getsection(source, msg, &dctx, DNS_SECTION_AUTHORITY);
	if (ret != DNS_R_SUCCESS)
		return (ret);

	ret = getsection(source, msg, &dctx, DNS_SECTION_ADDITIONAL);
	if (ret != DNS_R_SUCCESS)
		return (ret);

	isc_buffer_remaining(source, &r);
	if (r.length != 0)
		return (DNS_R_FORMERR);

	/*
	 * XXXMLG Need to check the tsig(s) here...
	 */

	return (DNS_R_SUCCESS);
}

dns_result_t
dns_message_renderbegin(dns_message_t *msg, isc_buffer_t *buffer)
{
	isc_region_t r;
	dns_result_t result;

	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(buffer != NULL);
	REQUIRE(msg->buffer == NULL);
	REQUIRE(msg->from_to_wire == DNS_MESSAGE_INTENT_RENDER);

	/*
	 * Erase the contents of this buffer.
	 */
	isc_buffer_clear(buffer);

	/*
	 * Make certain there is enough for at least the header in this
	 * buffer.
	 */
	isc_buffer_available(buffer, &r);
	if (r.length < DNS_MESSAGE_HEADER_LEN)
		return (DNS_R_NOSPACE);

	result = dns_compress_init(&msg->cctx, -1, msg->mctx);
	if (result != DNS_R_SUCCESS)
		return (result);
	msg->need_cctx_cleanup = ISC_TRUE;

	/*
	 * Reserve enough space for the header in this buffer.
	 */
	isc_buffer_add(buffer, DNS_MESSAGE_HEADER_LEN);

	return (DNS_R_SUCCESS);
}

dns_result_t
dns_message_renderchangebuffer(dns_message_t *msg, isc_buffer_t *buffer)
{
	isc_region_t r, rn;

	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(buffer != NULL);
	REQUIRE(msg->buffer != NULL);

	/*
	 * ensure that the new buffer is empty, and has enough space to
	 * hold the current contents.
	 */
	isc_buffer_clear(buffer);

	isc_buffer_available(buffer, &rn);
	isc_buffer_used(msg->buffer, &r);
	if (rn.length < r.length)
		return (DNS_R_NOSPACE);

	/*
	 * Copy the contents from the old to the new buffer.
	 */
	isc_buffer_add(buffer, r.length);
	memcpy(rn.base, r.base, r.length);

	msg->buffer = buffer;

	return (DNS_R_SUCCESS);
}

dns_result_t
dns_message_renderrelease(dns_message_t *msg, unsigned int space)
{
	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(msg->buffer != NULL);

	if (msg->reserved < space)
		return (DNS_R_NOSPACE);

	msg->reserved -= space;

	return (DNS_R_SUCCESS);
}

dns_result_t
dns_message_renderreserve(dns_message_t *msg, unsigned int space)
{
	isc_region_t r;

	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(msg->buffer != NULL);

	/*
	 * "space" can be positive or negative.  If it is negative we are
	 * removing our reservation of space.  If it is positive, we are
	 * requesting more space to be reserved.
	 */

	isc_buffer_available(msg->buffer, &r);
	if (r.length < (space + msg->reserved))
		return (DNS_R_NOSPACE);

	msg->reserved += space;

	return (DNS_R_SUCCESS);
}

dns_result_t
dns_message_rendersection(dns_message_t *msg, dns_section_t sectionid,
			  unsigned int priority, unsigned int flags)
{
	isc_region_t r;
	unsigned int used;
	dns_namelist_t *section;
	dns_name_t *name, *next_name;
	dns_rdataset_t *rdataset, *next_rdataset;
	unsigned int count, total;
	isc_buffer_t subbuffer;
	isc_boolean_t no_render_rdata;
	dns_result_t result;

	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(msg->buffer != NULL);
	REQUIRE(VALID_NAMED_SECTION(sectionid));

	total = 0;
	section = &msg->sections[sectionid];
	if (sectionid == DNS_SECTION_QUESTION)
		no_render_rdata = ISC_TRUE;
	else
		no_render_rdata = ISC_FALSE;

	name = ISC_LIST_HEAD(*section);
	if (name == NULL)
		return (ISC_R_SUCCESS);

	/*
	 * Set up a temporary buffer to render into, since we want
	 * dns_rdataset_towire() to fail if it goes past the reserved
	 * size, too.
	 */
	isc_buffer_available(msg->buffer, &r);
	isc_buffer_init(&subbuffer, r.base, r.length - msg->reserved,
			ISC_BUFFERTYPE_BINARY);
	
	while (name != NULL) {
		used = subbuffer.used;

		next_name = ISC_LIST_NEXT(name, link);

		result = dns_name_towire(name, &msg->cctx, &subbuffer);
		if (result != DNS_R_SUCCESS) {
			subbuffer.used = used;
			msg->counts[sectionid] += total;
			isc_buffer_used(&subbuffer, &r);
			isc_buffer_add(msg->buffer, r.length);
			return (result);
		}

		rdataset = ISC_LIST_HEAD(name->list);
		while (rdataset != NULL) {
			next_rdataset = ISC_LIST_NEXT(rdataset, link);
			count = 0;

			result = dns_rdataset_towire(rdataset, name,
						     &msg->cctx,
						     no_render_rdata,
						     &subbuffer, &count);

			/*
			 * If out of space, record stats on what we rendered
			 * so far, and return that status.
			 */
			if (result != DNS_R_SUCCESS) {
				subbuffer.used = used;
				msg->counts[sectionid] += total;
				isc_buffer_used(&subbuffer, &r);
				isc_buffer_add(msg->buffer, r.length);
				return (result);
			}

			total += count;

			ISC_LIST_UNLINK(name->list, rdataset, link);
			rdataset = next_rdataset;
		}

		ISC_LIST_UNLINK(*section, name, link);
		name = next_name;
	}

	return (ISC_R_SUCCESS);
}

dns_result_t
dns_message_renderend(dns_message_t *msg)
{
	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(msg->buffer != NULL);

	msg->buffer = NULL;  /* forget about this buffer only on success XXX */

	dns_compress_invalidate(&msg->cctx);
	msg->need_cctx_cleanup = ISC_FALSE;

	/* XXX implement */
	return (ISC_R_NOTIMPLEMENTED);
}

dns_result_t
dns_message_firstname(dns_message_t *msg, dns_section_t section)
{
	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(VALID_NAMED_SECTION(section));

	msg->cursors[section] = ISC_LIST_HEAD(msg->sections[section]);

	if (msg->cursors[section] == NULL)
		return (DNS_R_NOMORE);

	return (ISC_R_SUCCESS);
}

dns_result_t
dns_message_nextname(dns_message_t *msg, dns_section_t section)
{
	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(VALID_NAMED_SECTION(section));
	REQUIRE(msg->cursors[section] != NULL);
	
	msg->cursors[section] = ISC_LIST_NEXT(msg->cursors[section], link);

	if (msg->cursors[section] == NULL)
		return (DNS_R_NOMORE);

	return (ISC_R_SUCCESS);
}

void
dns_message_currentname(dns_message_t *msg, dns_section_t section,
			dns_name_t **name)
{
	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(VALID_NAMED_SECTION(section));
	REQUIRE(name != NULL && *name == NULL);
	REQUIRE(msg->cursors[section] != NULL);

	*name = msg->cursors[section];
}

dns_result_t
dns_message_findname(dns_message_t *msg, dns_section_t section,
		     dns_name_t *target, dns_rdatatype_t type,
		     dns_name_t **name, dns_rdataset_t **rdataset)
{
	dns_name_t *foundname;
	dns_result_t result;

	/*
	 * XXX These requirements are probably too intensive, especially
	 * where things can be NULL, but as they are they ensure that if
	 * something is NON-NULL, indicating that the caller expects it
	 * to be filled in, that we can in fact fill it in.
	 */
	REQUIRE(msg != NULL);
	REQUIRE(VALID_SECTION(section));
	REQUIRE(target != NULL);
	if (name != NULL)
		REQUIRE(*name == NULL);
	if (type == dns_rdatatype_any) {
		REQUIRE(rdataset == NULL);
	} else {
		if (rdataset != NULL)
			REQUIRE(*rdataset == NULL);
	}

	/*
	 * Search through, looking for the name.
	 */
	result = findname(&foundname, target, &msg->sections[section]);
	if (result == DNS_R_NOTFOUND)
		return (DNS_R_NXDOMAIN);
	else if (result != DNS_R_SUCCESS)
		return (result);

	if (name != NULL)
		*name = foundname;

	/*
	 * And now look for the type.
	 */
	if (rdataset == NULL)
		return (DNS_R_SUCCESS);

	result = findtype(rdataset, foundname, type);
	if (result == DNS_R_NOTFOUND)
		return (DNS_R_NXRDATASET);

	return (result);
}

void
dns_message_movename(dns_message_t *msg, dns_name_t *name,
		     dns_section_t fromsection,
		     dns_section_t tosection)
{
	REQUIRE(msg != NULL);
	REQUIRE(msg->from_to_wire == DNS_MESSAGE_INTENT_RENDER);
	REQUIRE(name != NULL);
	REQUIRE(VALID_NAMED_SECTION(fromsection));
	REQUIRE(VALID_NAMED_SECTION(tosection));
	REQUIRE(fromsection != tosection);

	/*
	 * Unlink the name from the old section
	 */
	ISC_LIST_UNLINK(msg->sections[fromsection], name, link);
	ISC_LIST_APPEND(msg->sections[tosection], name, link);
}

void
dns_message_addname(dns_message_t *msg, dns_name_t *name,
		    dns_section_t section)
{
	REQUIRE(msg != NULL);
	REQUIRE(msg->from_to_wire == DNS_MESSAGE_INTENT_RENDER);
	REQUIRE(name != NULL);
	REQUIRE(VALID_NAMED_SECTION(section));

	ISC_LIST_APPEND(msg->sections[section], name, link);
}
