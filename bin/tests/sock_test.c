/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/socket.h>
#include <isc/timer.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

isc_mem_t *mctx = NULL;
int sockets_active = 0;

static void my_send(isc_task_t *task, isc_event_t *event);
static void my_recv(isc_task_t *task, isc_event_t *event);

static void
my_callback(isc_task_t *task, isc_event_t *event)
{
	char *name = event->arg;

	printf("task %s (%p)\n", name, task);
	fflush(stdout);
	isc_event_free(&event);
}

static void
my_shutdown(isc_task_t *task, isc_event_t *event)
{
	char *name = event->arg;

	printf("shutdown %s (%p)\n", name, task);
	fflush(stdout);
	isc_event_free(&event);
}

static void
my_recv(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock;
	isc_socketevent_t *dev;
	isc_region_t region;
	char buf[1024];

	sock = event->sender;
	dev = (isc_socketevent_t *)event;

	printf("Socket %s (sock %p, base %p, length %d, n %d, result %d)\n",
	       (char *)(event->arg), sock,
	       dev->region.base, dev->region.length,
	       dev->n, dev->result);
	printf("\tFrom: %s port %d\n",
	       inet_ntoa(dev->address.type.sin.sin_addr),
	       ntohs(dev->address.type.sin.sin_port));

	if (dev->result != ISC_R_SUCCESS) {
		isc_socket_detach(&sock);

		isc_mem_put(event->mctx, dev->region.base,
			    dev->region.length);
		isc_event_free(&event);

		sockets_active--;
		if (sockets_active == 0)
			isc_task_shutdown(task);
		return;
	}

	/*
	 * Echo the data back
	 */
	if (strcmp(event->arg, "so2")) {
		region = dev->region;
		strcpy(buf, "\r\nReceived: ");
		strncat(buf, (char *)region.base, region.length);
		buf[32] = 0;  /* ensure termination */
		strcat(buf, "\r\n\r\n");
		region.base = isc_mem_get(event->mctx, strlen(buf) + 1);
		region.length = strlen(buf) + 1;
		strcpy((char *)region.base, buf);  /* strcpy is safe */
		isc_socket_send(sock, &region, task, my_send, event->arg);
	} else {
		region = dev->region;
		region.base[region.length - 1] = 0;
		printf("Received: %s\r\n", region.base);
	}

	isc_socket_recv(sock, &dev->region, ISC_FALSE,
			task, my_recv, event->arg);

	isc_event_free(&event);
}

static void
my_send(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock;
	isc_socketevent_t *dev;

	sock = event->sender;
	dev = (isc_socketevent_t *)event;

	printf("my_send: %s task %p\n\t(sock %p, base %p, length %d, n %d, result %d)\n",
	       (char *)(event->arg), task, sock,
	       dev->region.base, dev->region.length,
	       dev->n, dev->result);

	isc_mem_put(event->mctx, dev->region.base, dev->region.length);

	isc_event_free(&event);
}

static void
my_http_get(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock;
	isc_socketevent_t *dev;

	sock = event->sender;
	dev = (isc_socketevent_t *)event;

	printf("my_http_get: %s task %p\n\t(sock %p, base %p, length %d, n %d, result %d)\n",
	       (char *)(event->arg), task, sock,
	       dev->region.base, dev->region.length,
	       dev->n, dev->result);

	isc_socket_recv(sock, &dev->region, ISC_FALSE, task, my_recv,
			event->arg);

	isc_event_free(&event);
}

static void
my_connect(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock;
	isc_socket_connev_t *dev;
	isc_region_t region;
	char buf[1024];

	sock = event->sender;
	dev = (isc_socket_connev_t *)event;

	printf("%s: Connection result:  %d\n", (char *)(event->arg),
	       dev->result);

	if (dev->result != ISC_R_SUCCESS) {
		isc_socket_detach(&sock);
		isc_event_free(&event);
		return;
	}

	/*
	 * Send a GET string, and set up to receive (and just display)
	 * the result.
	 */
	strcpy(buf, "GET / HTTP/1.1\r\nHost: www.flame.org\r\nConnection: Close\r\n\r\n");
	region.base = isc_mem_get(event->mctx, strlen(buf) + 1);
	region.length = strlen(buf) + 1;
	strcpy((char *)region.base, buf);  /* strcpy is safe */

	isc_socket_send(sock, &region, task, my_http_get, event->arg);

	isc_event_free(&event);
}

static void
my_listen(isc_task_t *task, isc_event_t *event)
{
	char *name = event->arg;
	isc_socket_newconnev_t *dev;
	isc_region_t region;
	isc_socket_t *oldsock;

	dev = (isc_socket_newconnev_t *)event;

	printf("newcon %s (task %p, oldsock %p, newsock %p, result %d)\n",
	       name, task, event->sender, dev->newsocket, dev->result);
	fflush(stdout);

	if (dev->result == ISC_R_SUCCESS) {
		/*
		 * queue another listen on this socket
		 */
		isc_socket_accept(event->sender, task, my_listen, event->arg);

		region.base = isc_mem_get(event->mctx, 20);
		region.length = 20;

		/*
		 * queue up a read on this socket
		 */
		isc_socket_recv(dev->newsocket, &region, ISC_FALSE,
				task, my_recv, event->arg);
		sockets_active++;
	} else {
		printf("detaching from socket %p\n", event->sender);
		oldsock = event->sender;

		isc_socket_detach(&oldsock);

		sockets_active--;
		isc_event_free(&event);
		isc_task_shutdown(task);
		return;
	}

	isc_event_free(&event);
}

static void
timeout(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock = event->arg;

	printf("Timeout, canceling IO on socket %p (task %p)\n", sock, task);

	isc_socket_cancel(sock, NULL, ISC_SOCKCANCEL_ALL);
	isc_timer_detach((isc_timer_t **)&event->sender);
	isc_event_free(&event);
}

int
main(int argc, char *argv[])
{
	isc_taskmgr_t *manager = NULL;
	isc_task_t *t1 = NULL, *t2 = NULL;
	isc_timermgr_t *timgr = NULL;
	isc_time_t expires, now;
	isc_interval_t interval;
	isc_timer_t *ti1 = NULL;
	isc_event_t *event;
	unsigned int workers;
	isc_socketmgr_t *socketmgr;
	isc_socket_t *so1, *so2;
	isc_sockaddr_t sockaddr;
	unsigned int addrlen;

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_port = htons(5544);
	addrlen = sizeof(struct sockaddr_in);

	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 2;
	printf("%d workers\n", workers);

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_taskmgr_create(mctx, workers, 0, &manager) ==
		      ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_task_create(manager, NULL, 0, &t1) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_task_create(manager, NULL, 0, &t2) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_task_onshutdown(t1, my_shutdown, "1") ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_task_onshutdown(t2, my_shutdown, "2") ==
		      ISC_R_SUCCESS);

	printf("task 1 = %p\n", t1);
	printf("task 2 = %p\n", t2);

	/*
	 * create the timer we'll need
	 */
	RUNTIME_CHECK(isc_timermgr_create(mctx, &timgr) == ISC_R_SUCCESS);

	(void)isc_time_get(&now);

	socketmgr = NULL;
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);

	/*
	 * open up a listener socket
	 */
	sockets_active++;
	so1 = NULL;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_family = AF_INET;
	sockaddr.type.sin.sin_port = htons(5544);
	addrlen = sizeof(struct sockaddr_in);
	RUNTIME_CHECK(isc_socket_create(socketmgr, isc_socket_tcp, &so1) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socket_bind(so1, &sockaddr,
				      (int)addrlen) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socket_listen(so1, 0) == ISC_R_SUCCESS);

	/*
	 * queue up the first accept event
	 */
	RUNTIME_CHECK(isc_socket_accept(so1, t1, my_listen,
					"so1") == ISC_R_SUCCESS);
	isc_time_settoepoch(&expires);
	isc_interval_set(&interval, 10, 0);
	RUNTIME_CHECK(isc_timer_create(timgr, isc_timertype_once, &expires,
				       &interval, t1, timeout, so1, &ti1) ==
		      ISC_R_SUCCESS);

	/*
	 * open up a socket that will connect to www.flame.org, port 80.
	 * Why not.  :)
	 */
	sockets_active++;
	so2 = NULL;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_port = htons(80);
	sockaddr.type.sin.sin_family = AF_INET;
	sockaddr.type.sin.sin_addr.s_addr = inet_addr("204.152.184.97");
	addrlen = sizeof(struct sockaddr_in);
	RUNTIME_CHECK(isc_socket_create(socketmgr, isc_socket_tcp,
					&so2) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socket_connect(so2, &sockaddr, (int)addrlen, t1,
					 my_connect, "so2") == ISC_R_SUCCESS);

	sleep(1);

	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "2",
				   sizeof *event);
	isc_task_send(t2, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "2",
				   sizeof *event);
	isc_task_send(t2, &event);

	while (sockets_active > 0) {
		printf("Sockets active: %d\n", sockets_active);
		sleep (5);
	}

	isc_task_detach(&t1);
	isc_task_detach(&t2);

	printf("Destroying socket manager\n");
	isc_socketmgr_destroy(&socketmgr);

	printf("Destroying timer manager\n");
	isc_timermgr_destroy(&timgr);

	printf("Destroying task manager\n");
	isc_taskmgr_destroy(&manager);

	isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	return (0);
}
