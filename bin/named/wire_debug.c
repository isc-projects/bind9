#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/socket.h>
#include <isc/timer.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/compress.h>
#include <dns/db.h>

#define DNS_FLAG_QR		0x8000U
#define DNS_FLAG_AA		0x0400U
#define DNS_FLAG_TC		0x0200U
#define DNS_FLAG_RD		0x0100U
#define DNS_FLAG_RA		0x0080U

#define DNS_OPCODE_MASK		0x7000U
#define DNS_OPCODE_SHIFT	11
#define DNS_RCODE_MASK		0x000FU

/*
 * XXX All of the following is for debugging only, and will eventually
 * be in a library or removed when we really answer queries.
 */
typedef struct dns_message {
	unsigned int		id;
	unsigned int		flags;
	unsigned int		qcount;
	unsigned int		ancount;
	unsigned int		aucount;
	unsigned int		adcount;
	dns_namelist_t		question;
	dns_namelist_t		answer;
	dns_namelist_t		authority;
	dns_namelist_t		additional;
} dns_message_t;

/*
 * in wire_test.c
 */
void getmessage(dns_message_t *message, isc_buffer_t *source,
		isc_buffer_t *target);
dns_result_t printmessage(dns_message_t *message);

void
dump_packet(char *buf, u_int len)
{
	extern dns_decompress_t dctx;
	extern unsigned int rdcount, rlcount, ncount;
	char t[5000]; /* XXX */
	dns_message_t message;
	dns_result_t result;
	isc_buffer_t source, target;

	rdcount = 0;
	rlcount = 0;
	ncount = 0;

	dctx.allowed = DNS_COMPRESS_GLOBAL14;
	dns_name_init(&dctx.owner_name, NULL);

	isc_buffer_init(&source, buf, len, ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&source, len);
	isc_buffer_init(&target, t, sizeof(t), ISC_BUFFERTYPE_BINARY);

	getmessage(&message, &source, &target);
	result = printmessage(&message);
	if (result != DNS_R_SUCCESS)
		printf("printmessage() failed: %s\n",
		       dns_result_totext(result));
}

static isc_uint16_t
getshort(isc_buffer_t *buffer) {
	isc_region_t r;

	isc_buffer_remaining(buffer, &r);
	if (r.length < 2) {
		printf("not enough input\n");
		exit(5);
	}

	return (isc_buffer_getuint16(buffer));
}

dns_result_t
resolve_packet(dns_db_t *db, isc_buffer_t *source, isc_buffer_t *target)
{
	dns_decompress_t dctx;
	dns_compress_t cctx;
	dns_result_t result;
	unsigned int count;
	dns_message_t message;
	dns_name_t name;
	isc_uint16_t qtype;
	isc_uint16_t qclass;
	unsigned char t[256];
	isc_buffer_t tbuf;
	isc_uint16_t status;
	dns_dbnode_t *node;
	dns_rdataset_t rdataset;

	count = 0;
	status = 0;

	message.id = getshort(source);
	message.flags = getshort(source);
	message.qcount = getshort(source);
	message.ancount = getshort(source);
	message.aucount = getshort(source);
	message.adcount = getshort(source);

	INSIST(message.qcount == 1);
	INSIST(message.ancount == 0);
	INSIST(message.aucount == 0);
	INSIST(message.adcount == 0);

	dctx.allowed = DNS_COMPRESS_GLOBAL14;
	dns_name_init(&dctx.owner_name, NULL);

	cctx.allowed = DNS_COMPRESS_GLOBAL14;
	dns_name_init(&cctx.owner_name, NULL);

	/*
	 * Expand the name requested into buffer (tbuf)
	 */
	isc_buffer_init(&tbuf, t, sizeof(t), ISC_BUFFERTYPE_BINARY);
	dns_name_init(&name, NULL);
	result = dns_name_fromwire(&name, source, &dctx, ISC_FALSE, &tbuf);
	qtype = getshort(source);
	qclass = getshort(source);

	/*
	 * Look it up in the database.  XXX Uses many hard coded bits.
	 */

	node = NULL;
	result = dns_db_findnode(db, &name, ISC_FALSE, &node);
	if (result == DNS_R_NOTFOUND) {
		status = 3;  /* NXDOMAIN */
		goto out;
	}
	if (result != DNS_R_SUCCESS) {
		status = 2;  /* SERVFAIL */
		goto out;
	}

	dns_rdataset_init(&rdataset);
	result = dns_db_findrdataset(db, node, NULL, qtype, &rdataset);
	dns_db_detachnode(db, &node);
	if (result == DNS_R_NOTFOUND) {
		status = 3;  /* NXDOMAIN */
		goto out;
	}
	if (result != DNS_R_SUCCESS) {
		status = 2;  /* SERVFAIL */
		goto out;
	}

 out:
	/*
	 * XXX This should really use the buffer functions correctly, but...
	 */

	/*
	 * Write the header.
	 */
	isc_buffer_putuint16(target, message.id);

	message.flags |= DNS_FLAG_QR;
	message.flags &= ~(DNS_FLAG_AA | DNS_FLAG_TC | DNS_FLAG_RA);
	message.flags &= ~(DNS_RCODE_MASK);
	message.flags |= status;
	isc_buffer_putuint16(target, message.flags);

	isc_buffer_putuint16(target, message.qcount);
	isc_buffer_putuint16(target, message.ancount);  /* XXX fix up later */
	isc_buffer_putuint16(target, message.aucount);
	isc_buffer_putuint16(target, message.adcount);

	/*
	 * Write the question.  Note that we reconstruct it...
	 */
	dns_name_towire(&name, &cctx, target);
	isc_buffer_putuint16(target, qtype);
	isc_buffer_putuint16(target, qclass);

	/*
	 * Now, scribble out the answer.  If this works we will update the
	 * answer count.  If it fails, we will update the status instead.
	 */
	if (status == 0) {
		unsigned int oldused;

		count = 0;
		result = dns_rdataset_towire(&rdataset, &name, &cctx,
					     target, &count);
		if (result != DNS_R_SUCCESS) { /* Should just return fail? */
			oldused = target->used;
			target->used = 2;  /* Hack! XXX */
			message.flags &= ~(DNS_RCODE_MASK);
			message.flags |= 2; /* SERVFAIL */
			isc_buffer_putuint16(target, message.flags);
			target->used = oldused;
		} else {
			oldused = target->used;
			target->used = 6;  /* Another hack! XXX */
			isc_buffer_putuint16(target, count);
			target->used = oldused;
		}
	}

	return (DNS_R_SUCCESS);
}
