
#include "attribute.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/memcluster.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/socket.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

isc_memctx_t mctx = NULL;

volatile int tasks_done = 0;

static isc_boolean_t
my_callback(isc_task_t task, isc_event_t event)
{
	char *name = event->arg;

	printf("task %s (%p)\n", name, task);
	fflush(stdout);
	isc_event_free(&event);

	return (ISC_FALSE);
}

static isc_boolean_t
my_shutdown(isc_task_t task, isc_event_t event)
{
	char *name = event->arg;

	printf("shutdown %s (%p)\n", name, task);
	fflush(stdout);
	isc_event_free(&event);

	return (ISC_TRUE);
}

static isc_boolean_t
my_send(isc_task_t task, isc_event_t event)
{
	isc_socket_t sock;
	isc_socketevent_t dev;

	sock = event->sender;
	dev = (isc_socketevent_t)event;

	printf("my_send: %s task %p\n\t(sock %p, base %p, length %d, n %d, result %d)\n",
	       (char *)(event->arg), task, sock,
	       dev->region.base, dev->region.length,
	       dev->n, dev->result);

	isc_mem_put(event->mctx, dev->region.base, dev->region.length);

	isc_event_free(&event);

	return (0);
}
static isc_boolean_t
my_recv(isc_task_t task, isc_event_t event)
{
	isc_socket_t sock;
	isc_socketevent_t dev;
	struct isc_region region;
	char buf[1024];

	sock = event->sender;
	dev = (isc_socketevent_t)event;

	printf("Socket %s (sock %p, base %p, length %d, n %d, result %d)\n",
	       (char *)(event->arg), sock,
	       dev->region.base, dev->region.length,
	       dev->n, dev->result);
	printf("\tFrom: %s port %d\n", inet_ntoa(dev->address.type.sin.sin_addr),
	       ntohs(dev->address.type.sin.sin_port));

	if (dev->result != ISC_R_SUCCESS) {
		isc_socket_detach(&sock);

		isc_event_free(&event);

		return (0);
	}

	/*
	 * Echo the data back
	 */
	region = dev->region;
	region.base[20] = 0;
	snprintf(buf, sizeof buf, "Received: %s\r\n", region.base);
	region.base = isc_mem_get(event->mctx, strlen(buf) + 1);
	region.length = strlen(buf) + 1;
	strcpy(region.base, buf);  /* strcpy is safe */
	isc_socket_send(sock, &region, task, my_send, event->arg);

	isc_socket_recv(sock, &dev->region, ISC_FALSE,
			task, my_recv, event->arg);


	isc_event_free(&event);

	return (0);
}

static isc_boolean_t
my_listen(isc_task_t task, isc_event_t event)
{
	char *name = event->arg;
	isc_socket_newconnev_t dev;
	struct isc_region region;

	dev = (isc_socket_newconnev_t)event;

	printf("newcon %s (task %p, oldsock %p, newsock %p, result %d)\n",
	       name, task, event->sender, dev->newsocket, dev->result);
	fflush(stdout);

	if (dev->result == ISC_R_SUCCESS) {
		/*
		 * queue another listen on this socket
		 */
		isc_socket_accept(event->sender, task, my_listen, event->arg);

		region.base = isc_mem_get(event->mctx, 21);
		region.length = 20;

		/*
		 * queue up a read on this socket
		 */
		isc_socket_recv(dev->newsocket, &region, ISC_FALSE,
				task, my_recv, event->arg);
	} else {
		/*
		 * Do something useful here
		 */
	}

	isc_event_free(&event);

	return 0;
}

int
main(int argc, char *argv[])
{
	isc_taskmgr_t manager = NULL;
	isc_task_t t1 = NULL, t2 = NULL;
	isc_event_t event;
	unsigned int workers;
	isc_socketmgr_t socketmgr;
	isc_socket_t so1, so2;
	struct isc_sockaddr sockaddr;
	unsigned int addrlen;

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_port = htons(5544);
	addrlen = sizeof(struct sockaddr_in);

	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 2;
	printf("%d workers\n", workers);

	INSIST(isc_memctx_create(0, 0, &mctx) == ISC_R_SUCCESS);

	INSIST(isc_taskmgr_create(mctx, workers, 0, &manager) ==
	       ISC_R_SUCCESS);

	INSIST(isc_task_create(manager, my_shutdown, "1", 0, &t1) ==
	       ISC_R_SUCCESS);
	INSIST(isc_task_create(manager, my_shutdown, "2", 0, &t2) ==
	       ISC_R_SUCCESS);

	printf("task 1 = %p\n", t1);
	printf("task 2 = %p\n", t2);

	socketmgr = NULL;
	INSIST(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);
	so1 = NULL;
	INSIST(isc_socket_create(socketmgr, isc_socket_tcp,
				 &so1) == ISC_R_SUCCESS);
	INSIST(isc_socket_bind(so1, &sockaddr, addrlen) == ISC_R_SUCCESS);
	INSIST(isc_socket_listen(so1, 0) == ISC_R_SUCCESS);

	INSIST(isc_socket_accept(so1, t1, my_listen,
				 "so1") == ISC_R_SUCCESS);

	so2 = NULL;
	INSIST(isc_socket_create(socketmgr, isc_socket_tcp,
				 &so2) == ISC_R_SUCCESS);

	sleep(2);

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

	/*
	 * Grr!  there is no way to say "wake me when it's over"
	 */
	while (tasks_done != 2) {
		fprintf(stderr, "Tasks done: %d\n", tasks_done);
		sleep(2);
	}
		
	isc_task_shutdown(t1);
	isc_task_shutdown(t2);
	isc_task_detach(&t1);
	isc_task_detach(&t2);

	printf("destroy\n");
	isc_socket_detach(&so1);
	isc_socket_detach(&so2);

	isc_socketmgr_destroy(&socketmgr);
	isc_taskmgr_destroy(&manager);
	printf("destroyed\n");
	
	isc_mem_stats(mctx, stdout);
	isc_memctx_destroy(&mctx);

	return (0);
}
