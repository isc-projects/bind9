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
#define SCRATCHPAD_SIZE		768
#define NAME_COUNT		 16
#define RDATA_COUNT		 32
#define RDATALIST_COUNT		 32

/*
 * internal state stuff.
 */
#define TO_FROM_UNKNOWN		0
#define TO_FROM_FROMWIRE	1
#define TO_FROM_TOWIRE		2

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
	(((type) *)msgblock_internalget(block, sizeof(type)))

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
 * Init elements to default state.  Used both when allocating a new element
 * and when resetting one.
 */
static inline void
msginit(dns_message_t *m)
{
	m->id = 0;
	m->flags = 0;
	m->rcode = 0;
	m->opcode = 0;
	m->class = 0;
	m->qcount = 0;
	m->ancount = 0;
	m->aucount = 0;
	m->adcount = 0;
	m->state = DNS_SECTION_ANY;  /* indicate nothing parsed or rendered */
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

	if (intent == DNS_MESSAGE_INTENT_PARSE) {
		msgblock = msgblock_allocate(mctx, sizeof(dns_rdatalist_t),
					     RDATALIST_COUNT);
		if (msgblock == NULL)
			goto cleanup4;
		ISC_LIST_APPEND(m->rdatalists, msgblock, link);
	}

	return (DNS_R_SUCCESS);

	/*
	 * Cleanup for error returns.
	 */
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

dns_result_t
dns_message_parse(dns_message_t *msg, void *buffer, size_t buflen)
{

	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(buffer != NULL);
	REQUIRE(buflen > 0); /* XXXMLG Should be >= header length... */

	/* XXX implement */
	return (ISC_R_NOTIMPLEMENTED);
}

dns_result_t
dns_message_renderbegin(dns_message_t *msg, isc_buffer_t *buffer)
{
	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(buffer != NULL);

	/* XXX implement */
	return (ISC_R_NOTIMPLEMENTED);
}

dns_result_t
dns_message_renderrelease(dns_message_t *msg, unsigned int space)
{
	REQUIRE(VALID_MESSAGE(msg));

	if (msg->reserved < space)
		return (DNS_R_NOSPACE);

	msg->reserved -= space;

	return (DNS_R_SUCCESS);
}

dns_result_t
dns_message_renderreserve(dns_message_t *msg, isc_buffer_t *buffer,
			  unsigned int space)
{
	isc_region_t r;

	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(buffer != NULL);

	/*
	 * "space" can be positive or negative.  If it is negative we are
	 * removing our reservation of space.  If it is positive, we are
	 * requesting more space to be reserved.
	 */

	isc_buffer_available(buffer, &r);
	if (r.length < (space + msg->reserved))
		return (DNS_R_NOSPACE);

	msg->reserved += space;

	return (DNS_R_SUCCESS);
}

dns_result_t
dns_message_rendersection(dns_message_t *msg, isc_buffer_t *buffer,
			  dns_section_t section, unsigned int priority,
			  unsigned int flags)
{
	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(buffer != NULL);
	REQUIRE(VALID_NAMED_SECTION(section));

	/* XXX implement */
	return (ISC_R_NOTIMPLEMENTED);
}

dns_result_t
dns_message_renderend(dns_message_t *msg, isc_buffer_t *buffer)
{
	REQUIRE(VALID_MESSAGE(msg));
	REQUIRE(buffer != NULL);

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
	REQUIRE(name != NULL && name == NULL);
	REQUIRE(msg->cursors[section] != NULL);

	*name = msg->cursors[section];
}

dns_result_t
dns_message_findname(dns_message_t *msg, dns_section_t section,
		     dns_name_t *target, dns_rdatatype_t type,
		     dns_name_t **name, dns_rdataset_t **rdataset)
{

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

	return (ISC_R_NOTIMPLEMENTED);
	/* XXX implement */
}

void
dns_message_movename(dns_message_t *msg, dns_name_t *name,
		     dns_section_t fromsection,
		     dns_section_t tosection)
{
	REQUIRE(msg != NULL);
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
	REQUIRE(name != NULL);
	REQUIRE(VALID_NAMED_SECTION(section));

	ISC_LIST_APPEND(msg->sections[section], name, link);
}
