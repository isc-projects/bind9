#include <isc/mutex.h>
#include <isc/socket.h>
#include <isc/task.h>

typedef struct __tcp_listener tcp_listener_t;
typedef struct __tcp_cctx tcp_cctx_t;

struct __tcp_cctx {
	tcp_listener_t *parent;	/* controlling listener */
	isc_mem_t *mctx;	/* memory context used to allocate */
	u_int slot;		/* slot # in tasks[] (and ctxs[]) array */
	isc_socket_t *csock;	/* client's socket */
	unsigned char *buf;	/* input buffer */
	isc_uint16_t buflen;	/* length of buffer */
	u_int count; /* XXX debug */
};

struct __tcp_listener {
	isc_socket_t *sock;	/* the socket */
	u_int nwstart;		/* workers to start */
	u_int nwkeep;		/* workers to keep */
	u_int nwmax;		/* workers max */
	isc_mem_t *mctx;
	dns_result_t (*dispatch)(isc_mem_t *, isc_region_t *, unsigned int);
	isc_mutex_t lock;

	/* locked */
	isc_task_t **tasks;	/* list of tasks */
	u_int nwactive;		/* workers active */
	tcp_cctx_t **ctxs;	/* list of contexts */
};

tcp_listener_t *tcp_listener_allocate(isc_mem_t *mctx, u_int nwmax);

isc_result_t tcp_listener_start(tcp_listener_t *l,
				isc_socket_t *sock, isc_taskmgr_t *tmgr,
				u_int nwstart, u_int nwkeep, u_int nwtimeout,
				dns_result_t (*dispatch)(isc_mem_t *,
							 isc_region_t *,
							 unsigned int));
