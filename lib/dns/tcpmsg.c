
#include <config.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/socket.h>

#include <dns/events.h>
#include <dns/types.h>
#include <dns/result.h>
#include <dns/tcpmsg.h>

#include "../isc/util.h"

/*
 * If we cannot send to this task, the application is broken.
 */
#define ISC_TASK_SEND(a, b) do { \
	RUNTIME_CHECK(isc_task_send(a, b) == ISC_R_SUCCESS); \
} while (0)

#define TCPMSG_DEBUG

#ifdef TCPMSG_DEBUG
#define XDEBUG(x) printf x
#else
#define XDEBUG(x)
#endif

#define TCPMSG_MAGIC			0x5443506d	/* TCPm */

#define VALID_TCPMSG(foo) ((foo) != NULL && ((foo)->magic == TCPMSG_MAGIC))

static void recv_length(isc_task_t *, isc_event_t *);
static void recv_message(isc_task_t *, isc_event_t *);


static void
recv_length(isc_task_t *task, isc_event_t *ev_in)
{
	isc_socketevent_t *ev = (isc_socketevent_t *)ev_in;
	isc_event_t *dev;
	dns_tcpmsg_t *tcpmsg = ev_in->arg;
	isc_region_t region;
	isc_result_t result;

	INSIST(VALID_TCPMSG(tcpmsg));

	dev = &tcpmsg->event;

	if (ev->result != ISC_R_SUCCESS) {
		tcpmsg->result = ev->result;
		goto send_and_free;
	}

	/*
	 * success
	 */
	tcpmsg->size = ntohs(tcpmsg->size);
	if (tcpmsg->size == 0) {
		tcpmsg->result = DNS_R_UNEXPECTEDEND;
		goto send_and_free;
	}
	if (tcpmsg->size > 65536) {
		tcpmsg->result = DNS_R_RANGE;
		goto send_and_free;
	}

	region.base = isc_mem_get(tcpmsg->mctx, tcpmsg->size);
	region.length = tcpmsg->size;
	if (region.base == NULL) {
		tcpmsg->result = ISC_R_NOMEMORY;
		goto send_and_free;
	}

	isc_buffer_init(&tcpmsg->buffer, region.base, region.length,
			ISC_BUFFERTYPE_BINARY);
	result = isc_socket_recv(tcpmsg->sock, &region, ISC_FALSE,
				 task, recv_message, tcpmsg);
	if (result != ISC_R_SUCCESS) {
		tcpmsg->result = result;
		goto send_and_free;
	}

	isc_event_free(&ev_in);
	return;

 send_and_free:
	ISC_TASK_SEND(tcpmsg->task, &dev);
	tcpmsg->task = NULL;
	isc_event_free(&ev_in);
	return;
}

static void
recv_message(isc_task_t *task, isc_event_t *ev_in)
{
	isc_socketevent_t *ev = (isc_socketevent_t *)ev_in;
	isc_event_t *dev;
	dns_tcpmsg_t *tcpmsg = ev_in->arg;

	(void)task;

	INSIST(VALID_TCPMSG(tcpmsg));

	dev = &tcpmsg->event;

	if (ev->result != ISC_R_SUCCESS) {
		tcpmsg->result = ev->result;
		goto send_and_free;
	}

	tcpmsg->result = ISC_R_SUCCESS;
	isc_buffer_add(&tcpmsg->buffer, ev->n);

 send_and_free:
	ISC_TASK_SEND(tcpmsg->task, &dev);
	tcpmsg->task = NULL;
	isc_event_free(&ev_in);
}

void
dns_tcpmsg_initialize(isc_mem_t *mctx, isc_socket_t *sock,
		      dns_tcpmsg_t *tcpmsg)
{
	REQUIRE(mctx != NULL);
	REQUIRE(sock != NULL);
	REQUIRE(tcpmsg != NULL);
	REQUIRE(!VALID_TCPMSG(tcpmsg));

	tcpmsg->magic = TCPMSG_MAGIC;
	tcpmsg->size = 0;
	tcpmsg->buffer.base = NULL;
	tcpmsg->buffer.length = 0;
	tcpmsg->maxsize = 65536;  /* largest message possible */
	tcpmsg->mctx = mctx;
	tcpmsg->sock = sock;
	tcpmsg->task = NULL;  /* none yet */
	tcpmsg->result = ISC_R_UNEXPECTED;  /* none yet */
	/* Should probably initialize the event here, but it can wait. */
}


void
dns_tcpmsg_setmaxsize(dns_tcpmsg_t *tcpmsg, unsigned int maxsize)
{
	REQUIRE(VALID_TCPMSG(tcpmsg));
	REQUIRE(maxsize < 65536);

	tcpmsg->maxsize = maxsize;
}


dns_result_t
dns_tcpmsg_readmessage(dns_tcpmsg_t *tcpmsg,
		       isc_task_t *task, isc_taskaction_t action, void *arg)
{
	isc_result_t result;
	isc_region_t region;

	REQUIRE(VALID_TCPMSG(tcpmsg));
	REQUIRE(task != NULL);
	REQUIRE(tcpmsg->task == NULL);  /* not currently in use */

	if (tcpmsg->buffer.base != NULL) {
		isc_mem_put(tcpmsg->mctx, tcpmsg->buffer.base,
			    tcpmsg->buffer.length);
		tcpmsg->buffer.base = NULL;
		tcpmsg->buffer.length = 0;
	}

	tcpmsg->task = task;
	tcpmsg->action = action;
	tcpmsg->arg = arg;
	tcpmsg->result = ISC_R_UNEXPECTED;  /* unknown right now */

	ISC_EVENT_INIT(&tcpmsg->event, sizeof(isc_event_t), 0, 0,
		       DNS_EVENT_TCPMSG, action, arg, &tcpmsg,
		       NULL, NULL);

	region.base = (unsigned char *)&tcpmsg->size;
	region.length = 2;  /* u_int16_t */
	result = isc_socket_recv(tcpmsg->sock, &region, ISC_FALSE,
				 tcpmsg->task, recv_length, tcpmsg);

	if (result != ISC_R_SUCCESS)
		tcpmsg->task = NULL;

	return (result);
}

void
dns_tcpmsg_cancelread(dns_tcpmsg_t *tcpmsg)
{
	REQUIRE(VALID_TCPMSG(tcpmsg));

	isc_socket_cancel(tcpmsg->sock, tcpmsg->task, ISC_SOCKCANCEL_RECV);
}

void
dns_tcpmsg_keepbuffer(dns_tcpmsg_t *tcpmsg, isc_buffer_t *buffer)
{
	REQUIRE(VALID_TCPMSG(tcpmsg));
	REQUIRE(buffer != NULL);

	*buffer = tcpmsg->buffer;
	tcpmsg->buffer.base = 0;
	tcpmsg->buffer.length = 0;
}

void
dns_tcpmsg_invalidate(dns_tcpmsg_t *tcpmsg)
{
	REQUIRE(VALID_TCPMSG(tcpmsg));

	tcpmsg->magic = 0;

	if (tcpmsg->buffer.base != NULL) {
		isc_mem_put(tcpmsg->mctx, tcpmsg->buffer.base,
			    tcpmsg->buffer.length);
		tcpmsg->buffer.base = NULL;
		tcpmsg->buffer.length = 0;
	}
}
