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
