/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/httpd.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/print.h>
#include <isc/refcount.h>
#include <isc/socket.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* ifdef HAVE_ZLIB */

#define CHECK(m)                               \
	do {                                   \
		result = (m);                  \
		if (result != ISC_R_SUCCESS) { \
			goto cleanup;          \
		}                              \
	} while (0)

#define HTTP_RECVLEN	 1024
#define HTTP_SENDGROW	 1024
#define HTTP_SEND_MAXLEN 10240

#define HTTPD_CLOSE	     0x0001 /* Got a Connection: close header */
#define HTTPD_FOUNDHOST	     0x0002 /* Got a Host: header */
#define HTTPD_KEEPALIVE	     0x0004 /* Got a Connection: Keep-Alive */
#define HTTPD_ACCEPT_DEFLATE 0x0008

#define HTTPD_MAGIC    ISC_MAGIC('H', 't', 'p', 'd')
#define VALID_HTTPD(m) ISC_MAGIC_VALID(m, HTTPD_MAGIC)

#define HTTPDMGR_MAGIC	  ISC_MAGIC('H', 'p', 'd', 'm')
#define VALID_HTTPDMGR(m) ISC_MAGIC_VALID(m, HTTPDMGR_MAGIC)

/*%
 * Client states.
 *
 * _RECV	The client is waiting for data after starting a read.
 * _SEND	All data for a response has completed, and a reply was
 *		sent via a send call.
 */

typedef enum { RECV, SEND } state_t;

/*%
 * HTTP methods.
 */
typedef enum { METHOD_UNKNOWN = 0, METHOD_GET = 1, METHOD_POST = 2 } method_t;

/*% http client */
struct isc_httpd {
	unsigned int magic; /* HTTPD_MAGIC */

	isc_httpdmgr_t *mgr; /*%< our parent */
	ISC_LINK(isc_httpd_t) link;

	isc_nmhandle_t *handle;
	state_t state;
	int flags;

	/*%
	 * Received data state.
	 */
	char recvbuf[HTTP_RECVLEN]; /*%< receive buffer */
	uint32_t recvlen;	    /*%< length recv'd */
	char *headers;		    /*%< set in process_request() */
	method_t method;
	char *url;
	char *querystring;
	char *protocol;

	/*%
	 * Transmit data state.
	 *
	 * This is the data buffer we will transmit.
	 *
	 * This free function pointer is filled in by the rendering function
	 * we call.  The free function is called after the data is transmitted
	 * to the client.
	 *
	 * The bufflist is the list of buffers we are currently transmitting.
	 * The headerbuffer is where we render our headers to.  If we run out
	 * of space when rendering a header, we will change the size of our
	 * buffer.  We will not free it until we are finished, and will
	 * allocate an additional HTTP_SENDGROW bytes per header space grow.
	 *
	 * We currently use three buffers total, one for the headers (which
	 * we manage), another for the client to fill in (which it manages,
	 * it provides the space for it, etc) -- we will pass that buffer
	 * structure back to the caller, who is responsible for managing the
	 * space it may have allocated as backing store for it.  This second
	 * buffer is bodybuffer, and we only allocate the buffer itself, not
	 * the backing store.
	 * The third buffer is compbuffer, managed by us, that contains the
	 * compressed HTTP data, if compression is used.
	 *
	 */
	isc_buffer_t headerbuffer;
	isc_buffer_t compbuffer;
	isc_buffer_t *sendbuffer;

	const char *mimetype;
	unsigned int retcode;
	const char *retmsg;
	isc_buffer_t bodybuffer;
	isc_httpdfree_t *freecb;
	void *freecb_arg;
};

struct isc_httpdmgr {
	unsigned int magic; /* HTTPDMGR_MAGIC */
	isc_refcount_t references;
	isc_mem_t *mctx;
	isc_nmsocket_t *sock;

	isc_httpdclientok_t *client_ok;	 /*%< client validator */
	isc_httpdondestroy_t *ondestroy; /*%< cleanup callback */
	void *cb_arg;			 /*%< argument for the above */

	unsigned int flags;
	ISC_LIST(isc_httpd_t) running; /*%< running clients */

	isc_mutex_t lock;

	ISC_LIST(isc_httpdurl_t) urls; /*%< urls we manage */
	isc_httpdaction_t *render_404;
	isc_httpdaction_t *render_500;
};

static isc_result_t
httpd_newconn(isc_nmhandle_t *, isc_result_t, void *);
static void
httpd_request(isc_nmhandle_t *, isc_result_t, isc_region_t *, void *);
static void
httpd_senddone(isc_nmhandle_t *, isc_result_t, void *);
static void
httpd_reset(void *);
static void
httpd_put(void *);

static isc_result_t
httpd_addheader(isc_httpd_t *, const char *, const char *);
static isc_result_t
httpd_addheaderuint(isc_httpd_t *, const char *, int);
static isc_result_t
httpd_endheaders(isc_httpd_t *);
static isc_result_t
httpd_response(isc_httpd_t *);

static isc_result_t
process_request(isc_httpd_t *, isc_region_t *);
static isc_result_t
grow_headerspace(isc_httpd_t *);

static isc_httpdaction_t render_404;
static isc_httpdaction_t render_500;

#if ENABLE_AFL
static void (*finishhook)(void) = NULL;
#endif /* ENABLE_AFL */

static void
destroy_httpdmgr(isc_httpdmgr_t *);

static void
httpdmgr_attach(isc_httpdmgr_t *, isc_httpdmgr_t **);
static void
httpdmgr_detach(isc_httpdmgr_t **);

static inline void
free_buffer(isc_mem_t *mctx, isc_buffer_t *buffer) {
	isc_region_t r;

	isc_buffer_region(buffer, &r);
	if (r.length > 0) {
		isc_mem_put(mctx, r.base, r.length);
	}
}

isc_result_t
isc_httpdmgr_create(isc_nm_t *nm, isc_mem_t *mctx, isc_sockaddr_t *addr,
		    isc_httpdclientok_t *client_ok,
		    isc_httpdondestroy_t *ondestroy, void *cb_arg,
		    isc_httpdmgr_t **httpdmgrp) {
	isc_result_t result;
	isc_httpdmgr_t *httpdmgr = NULL;

	REQUIRE(nm != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(httpdmgrp != NULL && *httpdmgrp == NULL);

	httpdmgr = isc_mem_get(mctx, sizeof(isc_httpdmgr_t));
	*httpdmgr = (isc_httpdmgr_t){ .client_ok = client_ok,
				      .ondestroy = ondestroy,
				      .cb_arg = cb_arg,
				      .render_404 = render_404,
				      .render_500 = render_500 };

	isc_mutex_init(&httpdmgr->lock);
	isc_mem_attach(mctx, &httpdmgr->mctx);

	ISC_LIST_INIT(httpdmgr->running);
	ISC_LIST_INIT(httpdmgr->urls);

	isc_refcount_init(&httpdmgr->references, 1);

	CHECK(isc_nm_listentcp(nm, (isc_nmiface_t *)addr, httpd_newconn,
			       httpdmgr, sizeof(isc_httpd_t), 5, NULL,
			       &httpdmgr->sock));

	httpdmgr->magic = HTTPDMGR_MAGIC;
	*httpdmgrp = httpdmgr;

	return (ISC_R_SUCCESS);

cleanup:
	httpdmgr->magic = 0;
	isc_refcount_decrementz(&httpdmgr->references);
	isc_refcount_destroy(&httpdmgr->references);
	isc_mem_detach(&httpdmgr->mctx);
	isc_mutex_destroy(&httpdmgr->lock);
	isc_mem_put(mctx, httpdmgr, sizeof(isc_httpdmgr_t));

	return (result);
}

static void
httpdmgr_attach(isc_httpdmgr_t *source, isc_httpdmgr_t **targetp) {
	REQUIRE(VALID_HTTPDMGR(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);

	*targetp = source;
}

static void
httpdmgr_detach(isc_httpdmgr_t **httpdmgrp) {
	isc_httpdmgr_t *httpdmgr = NULL;

	REQUIRE(httpdmgrp != NULL);
	REQUIRE(VALID_HTTPDMGR(*httpdmgrp));

	httpdmgr = *httpdmgrp;
	*httpdmgrp = NULL;

	if (isc_refcount_decrement(&httpdmgr->references) == 1) {
		destroy_httpdmgr(httpdmgr);
	}
}

static void
destroy_httpdmgr(isc_httpdmgr_t *httpdmgr) {
	isc_httpdurl_t *url;

	isc_refcount_destroy(&httpdmgr->references);

	LOCK(&httpdmgr->lock);

	REQUIRE((httpdmgr->flags & ISC_HTTPDMGR_SHUTTINGDOWN) != 0);
	REQUIRE(ISC_LIST_EMPTY(httpdmgr->running));

	httpdmgr->magic = 0;

	if (httpdmgr->sock != NULL) {
		isc_nmsocket_close(&httpdmgr->sock);
	}

	/*
	 * Clear out the list of all actions we know about.  Just free the
	 * memory.
	 */
	url = ISC_LIST_HEAD(httpdmgr->urls);
	while (url != NULL) {
		isc_mem_free(httpdmgr->mctx, url->url);
		ISC_LIST_UNLINK(httpdmgr->urls, url, link);
		isc_mem_put(httpdmgr->mctx, url, sizeof(isc_httpdurl_t));
		url = ISC_LIST_HEAD(httpdmgr->urls);
	}

	UNLOCK(&httpdmgr->lock);
	isc_mutex_destroy(&httpdmgr->lock);

	if (httpdmgr->ondestroy != NULL) {
		(httpdmgr->ondestroy)(httpdmgr->cb_arg);
	}
	isc_mem_putanddetach(&httpdmgr->mctx, httpdmgr, sizeof(isc_httpdmgr_t));
}

#define LENGTHOK(s) (httpd->recvbuf - (s) < (int)httpd->recvlen)
#define BUFLENOK(s) (httpd->recvbuf - (s) < HTTP_RECVLEN)

/*
 * Look for the given header in headers.
 * If value is specified look for it terminated with a character in eov.
 */
static bool
have_header(isc_httpd_t *httpd, const char *header, const char *value,
	    const char *eov) {
	char *cr, *nl, *h;
	size_t hlen, vlen = 0;

	h = httpd->headers;
	hlen = strlen(header);
	if (value != NULL) {
		INSIST(eov != NULL);
		vlen = strlen(value);
	}

	for (;;) {
		if (strncasecmp(h, header, hlen) != 0) {
			/*
			 * Skip to next line;
			 */
			cr = strchr(h, '\r');
			if (cr != NULL && cr[1] == '\n') {
				cr++;
			}
			nl = strchr(h, '\n');

			/* last header? */
			h = cr;
			if (h == NULL || (nl != NULL && nl < h)) {
				h = nl;
			}
			if (h == NULL) {
				return (false);
			}
			h++;
			continue;
		}

		if (value == NULL) {
			return (true);
		}

		/*
		 * Skip optional leading white space.
		 */
		h += hlen;
		while (*h == ' ' || *h == '\t') {
			h++;
		}
		/*
		 * Terminate token search on NULL or EOL.
		 */
		while (*h != 0 && *h != '\r' && *h != '\n') {
			if (strncasecmp(h, value, vlen) == 0) {
				if (strchr(eov, h[vlen]) != NULL) {
					return (true);
					/*
					 * Skip to next token.
					 */
				}
			}
			/*
			 * Skip to next token.
			 */
			h += strcspn(h, eov);
			if (h[0] == '\r' && h[1] == '\n') {
				h++;
			}
			if (h[0] != 0) {
				h++;
			}
		}

		return (false);
	}
}

static isc_result_t
process_request(isc_httpd_t *httpd, isc_region_t *region) {
	char *s = NULL, *p = NULL;
	int delim;

	memmove(httpd->recvbuf + httpd->recvlen, region->base, region->length);
	httpd->recvlen += region->length;
	httpd->recvbuf[httpd->recvlen] = 0;
	httpd->headers = NULL;

	/*
	 * If we don't find a blank line in our buffer, return that we need
	 * more data.
	 */
	s = strstr(httpd->recvbuf, "\r\n\r\n");
	delim = 2;
	if (s == NULL) {
		s = strstr(httpd->recvbuf, "\n\n");
		delim = 1;
	}
	if (s == NULL) {
		return (ISC_R_NOTFOUND);
	}

	/*
	 * NUL terminate request at the blank line.
	 */
	s[delim] = 0;

	/*
	 * Determine if this is a POST or GET method.  Any other values will
	 * cause an error to be returned.
	 */
	if (strncmp(httpd->recvbuf, "GET ", 4) == 0) {
		httpd->method = METHOD_GET;
		p = httpd->recvbuf + 4;
	} else if (strncmp(httpd->recvbuf, "POST ", 5) == 0) {
		httpd->method = METHOD_POST;
		p = httpd->recvbuf + 5;
	} else {
		return (ISC_R_RANGE);
	}

	/*
	 * From now on, p is the start of our buffer.
	 */

	/*
	 * Extract the URL.
	 */
	s = p;
	while (LENGTHOK(s) && BUFLENOK(s) &&
	       (*s != '\n' && *s != '\r' && *s != '\0' && *s != ' '))
	{
		s++;
	}
	if (!LENGTHOK(s)) {
		return (ISC_R_NOTFOUND);
	}
	if (!BUFLENOK(s)) {
		return (ISC_R_NOMEMORY);
	}
	*s = 0;

	/*
	 * Make the URL relative.
	 */
	if ((strncmp(p, "http:/", 6) == 0) || (strncmp(p, "https:/", 7) == 0)) {
		/* Skip first / */
		while (*p != '/' && *p != 0) {
			p++;
		}
		if (*p == 0) {
			return (ISC_R_RANGE);
		}
		p++;
		/* Skip second / */
		while (*p != '/' && *p != 0) {
			p++;
		}
		if (*p == 0) {
			return (ISC_R_RANGE);
		}
		p++;
		/* Find third / */
		while (*p != '/' && *p != 0) {
			p++;
		}
		if (*p == 0) {
			p--;
			*p = '/';
		}
	}

	httpd->url = p;
	p = s + 1;
	s = p;

	/*
	 * Now, see if there is a ? mark in the URL.  If so, this is
	 * part of the query string, and we will split it from the URL.
	 */
	httpd->querystring = strchr(httpd->url, '?');
	if (httpd->querystring != NULL) {
		*(httpd->querystring) = 0;
		httpd->querystring++;
	}

	/*
	 * Extract the HTTP/1.X protocol.  We will bounce on anything but
	 * HTTP/1.0 or HTTP/1.1 for now.
	 */
	while (LENGTHOK(s) && BUFLENOK(s) &&
	       (*s != '\n' && *s != '\r' && *s != '\0')) {
		s++;
	}
	if (!LENGTHOK(s)) {
		return (ISC_R_NOTFOUND);
	}
	if (!BUFLENOK(s)) {
		return (ISC_R_NOMEMORY);
	}
	/*
	 * Check that we have the expected eol delimiter.
	 */
	if (strncmp(s, delim == 1 ? "\n" : "\r\n", delim) != 0) {
		return (ISC_R_RANGE);
	}
	*s = 0;
	if ((strncmp(p, "HTTP/1.0", 8) != 0) &&
	    (strncmp(p, "HTTP/1.1", 8) != 0)) {
		return (ISC_R_RANGE);
	}
	httpd->protocol = p;
	p = s + delim; /* skip past eol */
	s = p;

	httpd->headers = s;

	if (have_header(httpd, "Connection:", "close", ", \t\r\n")) {
		httpd->flags |= HTTPD_CLOSE;
	}

	if (have_header(httpd, "Host:", NULL, NULL)) {
		httpd->flags |= HTTPD_FOUNDHOST;
	}

	if (strncmp(httpd->protocol, "HTTP/1.0", 8) == 0) {
		if (have_header(httpd, "Connection:", "Keep-Alive", ", \t\r\n"))
		{
			httpd->flags |= HTTPD_KEEPALIVE;
		} else {
			httpd->flags |= HTTPD_CLOSE;
		}
	}

	/*
	 * Check for Accept-Encoding:
	 */
#ifdef HAVE_ZLIB
	if (have_header(httpd, "Accept-Encoding:", "deflate", ";, \t\r\n")) {
		httpd->flags |= HTTPD_ACCEPT_DEFLATE;
	}
#endif /* ifdef HAVE_ZLIB */

	/*
	 * Standards compliance hooks here.
	 */
	if (strcmp(httpd->protocol, "HTTP/1.1") == 0 &&
	    ((httpd->flags & HTTPD_FOUNDHOST) == 0))
	{
		return (ISC_R_RANGE);
	}

	return (ISC_R_SUCCESS);
}

static void
httpd_reset(void *arg) {
	isc_httpd_t *httpd = (isc_httpd_t *)arg;
	isc_httpdmgr_t *httpdmgr = NULL;

	REQUIRE(VALID_HTTPD(httpd));

	httpdmgr = httpd->mgr;

	REQUIRE(VALID_HTTPDMGR(httpdmgr));

	LOCK(&httpdmgr->lock);
	ISC_LIST_UNLINK(httpdmgr->running, httpd, link);
	UNLOCK(&httpdmgr->lock);

	httpd->recvbuf[0] = 0;
	httpd->recvlen = 0;
	httpd->headers = NULL;
	httpd->method = METHOD_UNKNOWN;
	httpd->url = NULL;
	httpd->querystring = NULL;
	httpd->protocol = NULL;
	httpd->flags = 0;

	isc_buffer_clear(&httpd->headerbuffer);
	isc_buffer_clear(&httpd->compbuffer);
	isc_buffer_invalidate(&httpd->bodybuffer);

	httpdmgr_detach(&httpdmgr);
}

static void
httpd_put(void *arg) {
	isc_httpd_t *httpd = (isc_httpd_t *)arg;
	isc_httpdmgr_t *httpdmgr = NULL;

	REQUIRE(VALID_HTTPD(httpd));

	httpdmgr = httpd->mgr;
	REQUIRE(VALID_HTTPDMGR(httpdmgr));

	httpd->magic = 0;

	free_buffer(httpdmgr->mctx, &httpd->headerbuffer);
	free_buffer(httpdmgr->mctx, &httpd->compbuffer);

#if ENABLE_AFL
	if (finishhook != NULL) {
		finishhook();
	}
#endif /* ENABLE_AFL */
}

static isc_result_t
new_httpd(isc_httpdmgr_t *httpdmgr, isc_nmhandle_t *handle) {
	isc_result_t result;
	isc_httpd_t *httpd = NULL;
	char *headerdata = NULL;

	REQUIRE(VALID_HTTPDMGR(httpdmgr));

	httpd = isc_nmhandle_getdata(handle);
	if (httpd == NULL) {
		httpd = isc_nmhandle_getextra(handle);
		*httpd = (isc_httpd_t){ .handle = NULL };
	}

	if (httpd->handle == NULL) {
		isc_nmhandle_setdata(handle, httpd, httpd_reset, httpd_put);
	} else {
		INSIST(httpd->handle == handle);
	}

	httpdmgr_attach(httpdmgr, &httpd->mgr);

	/*
	 * Initialize the buffer for our headers.
	 */
	headerdata = isc_mem_get(httpdmgr->mctx, HTTP_SENDGROW);
	isc_buffer_init(&httpd->headerbuffer, headerdata, HTTP_SENDGROW);
	isc_buffer_clear(&httpd->headerbuffer);

	isc_buffer_initnull(&httpd->compbuffer);
	isc_buffer_clear(&httpd->compbuffer);

	isc_buffer_initnull(&httpd->bodybuffer);

	ISC_LINK_INIT(httpd, link);

	httpd->magic = HTTPD_MAGIC;
	httpd->state = RECV;

	LOCK(&httpdmgr->lock);
	ISC_LIST_APPEND(httpdmgr->running, httpd, link);
	UNLOCK(&httpdmgr->lock);

	isc_nmhandle_ref(handle);
	result = isc_nm_read(handle, httpd_request, httpdmgr);
	if (result != ISC_R_SUCCESS) {
		isc_nmhandle_unref(handle);
	}

	return (result);
}

static isc_result_t
httpd_newconn(isc_nmhandle_t *handle, isc_result_t result, void *arg) {
	isc_httpdmgr_t *httpdmgr = (isc_httpdmgr_t *)arg;
	isc_sockaddr_t peeraddr;

	REQUIRE(VALID_HTTPDMGR(httpdmgr));

	if ((httpdmgr->flags & ISC_HTTPDMGR_SHUTTINGDOWN) != 0) {
		return (ISC_R_CANCELED);
	} else if (result == ISC_R_CANCELED) {
		isc_httpdmgr_shutdown(&httpdmgr);
		return (result);
	} else if (result != ISC_R_SUCCESS) {
		return (result);
	}

	peeraddr = isc_nmhandle_peeraddr(handle);
	if (httpdmgr->client_ok != NULL &&
	    !(httpdmgr->client_ok)(&peeraddr, httpdmgr->cb_arg))
	{
		return (ISC_R_FAILURE);
	}

	return (new_httpd(httpdmgr, handle));
}

static isc_result_t
render_404(const char *url, isc_httpdurl_t *urlinfo, const char *querystring,
	   const char *headers, void *arg, unsigned int *retcode,
	   const char **retmsg, const char **mimetype, isc_buffer_t *b,
	   isc_httpdfree_t **freecb, void **freecb_args) {
	static char msg[] = "No such URL.\r\n";

	UNUSED(url);
	UNUSED(urlinfo);
	UNUSED(querystring);
	UNUSED(headers);
	UNUSED(arg);

	*retcode = 404;
	*retmsg = "No such URL";
	*mimetype = "text/plain";
	isc_buffer_reinit(b, msg, strlen(msg));
	isc_buffer_add(b, strlen(msg));
	*freecb = NULL;
	*freecb_args = NULL;

	return (ISC_R_SUCCESS);
}

static isc_result_t
render_500(const char *url, isc_httpdurl_t *urlinfo, const char *querystring,
	   const char *headers, void *arg, unsigned int *retcode,
	   const char **retmsg, const char **mimetype, isc_buffer_t *b,
	   isc_httpdfree_t **freecb, void **freecb_args) {
	static char msg[] = "Internal server failure.\r\n";

	UNUSED(url);
	UNUSED(urlinfo);
	UNUSED(querystring);
	UNUSED(headers);
	UNUSED(arg);

	*retcode = 500;
	*retmsg = "Internal server failure";
	*mimetype = "text/plain";
	isc_buffer_reinit(b, msg, strlen(msg));
	isc_buffer_add(b, strlen(msg));
	*freecb = NULL;
	*freecb_args = NULL;

	return (ISC_R_SUCCESS);
}

#ifdef HAVE_ZLIB
/*%<
 * Reallocates compbuffer to size, does nothing if compbuffer is already
 * larger than size.
 *
 * Requires:
 *\li	httpd a valid isc_httpd_t object
 *
 * Returns:
 *\li	#ISC_R_SUCCESS		-- all is well.
 *\li	#ISC_R_NOMEMORY		-- not enough memory to extend buffer
 */
static isc_result_t
alloc_compspace(isc_httpd_t *httpd, unsigned int size) {
	char *newspace;
	isc_region_t r;

	isc_buffer_region(&httpd->compbuffer, &r);
	if (size < r.length) {
		return (ISC_R_SUCCESS);
	}

	newspace = isc_mem_get(httpd->mgr->mctx, size);
	isc_buffer_reinit(&httpd->compbuffer, newspace, size);

	if (r.base != NULL) {
		isc_mem_put(httpd->mgr->mctx, r.base, r.length);
	}

	return (ISC_R_SUCCESS);
}

/*%<
 * Tries to compress httpd->bodybuffer to httpd->compbuffer, extending it
 * if necessary.
 *
 * Requires:
 *\li	httpd a valid isc_httpd_t object
 *
 * Returns:
 *\li	#ISC_R_SUCCESS	  -- all is well.
 *\li	#ISC_R_NOMEMORY	  -- not enough memory to compress data
 *\li	#ISC_R_FAILURE	  -- error during compression or compressed
 *			     data would be larger than input data
 */
static isc_result_t
httpd_compress(isc_httpd_t *httpd) {
	z_stream zstr;
	isc_region_t r;
	isc_result_t result;
	int ret;
	int inputlen;

	inputlen = isc_buffer_usedlength(&httpd->bodybuffer);
	result = alloc_compspace(httpd, inputlen);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}
	isc_buffer_region(&httpd->compbuffer, &r);

	/*
	 * We're setting output buffer size to input size so it fails if the
	 * compressed data size would be bigger than the input size.
	 */
	memset(&zstr, 0, sizeof(zstr));
	zstr.total_in = zstr.avail_in = zstr.total_out = zstr.avail_out =
		inputlen;

	zstr.next_in = isc_buffer_base(&httpd->bodybuffer);
	zstr.next_out = r.base;

	ret = deflateInit(&zstr, Z_DEFAULT_COMPRESSION);
	if (ret == Z_OK) {
		ret = deflate(&zstr, Z_FINISH);
	}
	deflateEnd(&zstr);
	if (ret == Z_STREAM_END) {
		isc_buffer_add(&httpd->compbuffer, inputlen - zstr.avail_out);
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_FAILURE);
	}
}
#endif /* ifdef HAVE_ZLIB */

static void
httpd_request(isc_nmhandle_t *handle, isc_result_t eresult,
	      isc_region_t *region, void *arg) {
	isc_result_t result;
	isc_httpd_t *httpd = NULL;
	isc_httpdmgr_t *mgr = (isc_httpdmgr_t *)arg;
	isc_buffer_t *databuffer = NULL;
	isc_httpdurl_t *url = NULL;
	isc_time_t now;
	isc_region_t r;
	bool is_compressed = false;
	char datebuf[ISC_FORMATHTTPTIMESTAMP_SIZE];

	httpd = isc_nmhandle_getdata(handle);

	REQUIRE(httpd->state == RECV);

	if (eresult != ISC_R_SUCCESS) {
		goto done;
	}

	result = process_request(httpd, region);
	if (result == ISC_R_NOTFOUND) {
		if (httpd->recvlen < HTTP_RECVLEN - 1) {
			/* don't unref, continue reading */
			return;
		}
		goto done;
	} else if (result != ISC_R_SUCCESS) {
		goto done;
	}

	isc_buffer_initnull(&httpd->bodybuffer);
	isc_time_now(&now);
	isc_time_formathttptimestamp(&now, datebuf, sizeof(datebuf));

	LOCK(&mgr->lock);
	url = ISC_LIST_HEAD(mgr->urls);
	while (url != NULL) {
		if (strcmp(httpd->url, url->url) == 0) {
			break;
		}
		url = ISC_LIST_NEXT(url, link);
	}
	UNLOCK(&mgr->lock);

	if (url == NULL) {
		result = mgr->render_404(
			httpd->url, NULL, httpd->querystring, NULL, NULL,
			&httpd->retcode, &httpd->retmsg, &httpd->mimetype,
			&httpd->bodybuffer, &httpd->freecb, &httpd->freecb_arg);
	} else {
		result = url->action(httpd->url, url, httpd->querystring,
				     httpd->headers, url->action_arg,
				     &httpd->retcode, &httpd->retmsg,
				     &httpd->mimetype, &httpd->bodybuffer,
				     &httpd->freecb, &httpd->freecb_arg);
	}
	if (result != ISC_R_SUCCESS) {
		result = mgr->render_500(
			httpd->url, url, httpd->querystring, NULL, NULL,
			&httpd->retcode, &httpd->retmsg, &httpd->mimetype,
			&httpd->bodybuffer, &httpd->freecb, &httpd->freecb_arg);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
	}

#ifdef HAVE_ZLIB
	if ((httpd->flags & HTTPD_ACCEPT_DEFLATE) != 0) {
		result = httpd_compress(httpd);
		if (result == ISC_R_SUCCESS) {
			is_compressed = true;
		}
	}
#endif /* ifdef HAVE_ZLIB */

	httpd_response(httpd);
	if ((httpd->flags & HTTPD_KEEPALIVE) != 0) {
		httpd_addheader(httpd, "Connection", "Keep-Alive");
	}
	httpd_addheader(httpd, "Content-Type", httpd->mimetype);
	httpd_addheader(httpd, "Date", datebuf);
	httpd_addheader(httpd, "Expires", datebuf);

	if (url != NULL && url->isstatic) {
		char loadbuf[ISC_FORMATHTTPTIMESTAMP_SIZE];
		isc_time_formathttptimestamp(&url->loadtime, loadbuf,
					     sizeof(loadbuf));
		httpd_addheader(httpd, "Last-Modified", loadbuf);
		httpd_addheader(httpd, "Cache-Control: public", NULL);
	} else {
		httpd_addheader(httpd, "Last-Modified", datebuf);
		httpd_addheader(httpd, "Pragma: no-cache", NULL);
		httpd_addheader(httpd, "Cache-Control: no-cache", NULL);
	}

	httpd_addheader(httpd, "Server: libisc", NULL);

	if (is_compressed) {
		httpd_addheader(httpd, "Content-Encoding", "deflate");
		httpd_addheaderuint(httpd, "Content-Length",
				    isc_buffer_usedlength(&httpd->compbuffer));
	} else {
		httpd_addheaderuint(httpd, "Content-Length",
				    isc_buffer_usedlength(&httpd->bodybuffer));
	}

	httpd_endheaders(httpd); /* done */

	/*
	 * Append either the compressed or the non-compressed response body to
	 * the response headers and store the result in httpd->sendbuffer.
	 */
	isc_buffer_dup(mgr->mctx, &httpd->sendbuffer, &httpd->headerbuffer);
	isc_buffer_setautorealloc(httpd->sendbuffer, true);
	databuffer = (is_compressed ? &httpd->compbuffer : &httpd->bodybuffer);
	isc_buffer_usedregion(databuffer, &r);
	result = isc_buffer_copyregion(httpd->sendbuffer, &r);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	/*
	 * Determine total response size.
	 */
	isc_buffer_usedregion(httpd->sendbuffer, &r);

	isc_nm_pauseread(handle);
	httpd->state = SEND;

	isc_nmhandle_ref(handle);
	result = isc_nm_send(handle, &r, httpd_senddone, httpd);
	if (result != ISC_R_SUCCESS) {
		isc_nm_resumeread(handle);
		isc_nmhandle_unref(handle);

		httpd->state = RECV;
	}

	return;
done:
	isc_nmhandle_unref(handle);
}

void
isc_httpdmgr_shutdown(isc_httpdmgr_t **httpdmgrp) {
	isc_httpdmgr_t *httpdmgr;
	isc_httpd_t *httpd;

	REQUIRE(httpdmgrp != NULL);
	REQUIRE(VALID_HTTPDMGR(*httpdmgrp));

	httpdmgr = *httpdmgrp;
	*httpdmgrp = NULL;

	isc_nm_stoplistening(httpdmgr->sock);

	LOCK(&httpdmgr->lock);
	httpdmgr->flags |= ISC_HTTPDMGR_SHUTTINGDOWN;

	httpd = ISC_LIST_HEAD(httpdmgr->running);
	while (httpd != NULL) {
		isc_nmhandle_unref(httpd->handle);
		httpd = ISC_LIST_NEXT(httpd, link);
	}
	UNLOCK(&httpdmgr->lock);

	httpdmgr_detach(&httpdmgr);
}

static isc_result_t
grow_headerspace(isc_httpd_t *httpd) {
	char *newspace = NULL;
	unsigned int newlen;
	isc_region_t r;

	isc_buffer_region(&httpd->headerbuffer, &r);
	newlen = r.length + HTTP_SENDGROW;
	if (newlen > HTTP_SEND_MAXLEN) {
		return (ISC_R_NOSPACE);
	}

	newspace = isc_mem_get(httpd->mgr->mctx, newlen);

	isc_buffer_reinit(&httpd->headerbuffer, newspace, newlen);

	isc_mem_put(httpd->mgr->mctx, r.base, r.length);

	return (ISC_R_SUCCESS);
}

static isc_result_t
httpd_response(isc_httpd_t *httpd) {
	isc_result_t result;
	unsigned int needlen;

	REQUIRE(VALID_HTTPD(httpd));

	needlen = strlen(httpd->protocol) + 1; /* protocol + space */
	needlen += 3 + 1; /* room for response code, always 3 bytes */
	needlen += strlen(httpd->retmsg) + 2; /* return msg + CRLF */

	while (isc_buffer_availablelength(&httpd->headerbuffer) < needlen) {
		result = grow_headerspace(httpd);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

	return (isc_buffer_printf(&httpd->headerbuffer, "%s %03u %s\r\n",
				  httpd->protocol, httpd->retcode,
				  httpd->retmsg));
}

static isc_result_t
httpd_addheader(isc_httpd_t *httpd, const char *name, const char *val) {
	isc_result_t result;
	unsigned int needlen;

	REQUIRE(VALID_HTTPD(httpd));

	needlen = strlen(name); /* name itself */
	if (val != NULL) {
		needlen += 2 + strlen(val); /* :<space> and val */
	}
	needlen += 2; /* CRLF */

	while (isc_buffer_availablelength(&httpd->headerbuffer) < needlen) {
		result = grow_headerspace(httpd);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

	if (val != NULL) {
		return (isc_buffer_printf(&httpd->headerbuffer, "%s: %s\r\n",
					  name, val));
	} else {
		return (isc_buffer_printf(&httpd->headerbuffer, "%s\r\n",
					  name));
	}
}

static isc_result_t
httpd_endheaders(isc_httpd_t *httpd) {
	isc_result_t result;

	REQUIRE(VALID_HTTPD(httpd));

	while (isc_buffer_availablelength(&httpd->headerbuffer) < 2) {
		result = grow_headerspace(httpd);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

	return (isc_buffer_printf(&httpd->headerbuffer, "\r\n"));
}

static isc_result_t
httpd_addheaderuint(isc_httpd_t *httpd, const char *name, int val) {
	isc_result_t result;
	unsigned int needlen;
	char buf[sizeof "18446744073709551616"];

	REQUIRE(VALID_HTTPD(httpd));

	snprintf(buf, sizeof(buf), "%d", val);

	needlen = strlen(name);	    /* name itself */
	needlen += 2 + strlen(buf); /* :<space> and val */
	needlen += 2;		    /* CRLF */

	while (isc_buffer_availablelength(&httpd->headerbuffer) < needlen) {
		result = grow_headerspace(httpd);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

	return (isc_buffer_printf(&httpd->headerbuffer, "%s: %s\r\n", name,
				  buf));
}

static void
httpd_senddone(isc_nmhandle_t *handle, isc_result_t result, void *arg) {
	isc_httpd_t *httpd = (isc_httpd_t *)arg;

	REQUIRE(VALID_HTTPD(httpd));
	REQUIRE(httpd->state == SEND);

	isc_buffer_free(&httpd->sendbuffer);

	/*
	 * We will always want to clean up our receive buffer, even if we
	 * got an error on send or we are shutting down.
	 */
	if (httpd->freecb != NULL) {
		isc_buffer_t *b = NULL;
		if (isc_buffer_length(&httpd->bodybuffer) > 0) {
			b = &httpd->bodybuffer;
			httpd->freecb(b, httpd->freecb_arg);
		}
	}

	if (result != ISC_R_SUCCESS) {
		return;
	}

	httpd->state = RECV;
	isc_nm_resumeread(handle);
	isc_nmhandle_unref(handle);
}

isc_result_t
isc_httpdmgr_addurl(isc_httpdmgr_t *httpdmgr, const char *url, bool isstatic,
		    isc_httpdaction_t *func, void *arg) {
	isc_httpdurl_t *item;

	REQUIRE(VALID_HTTPDMGR(httpdmgr));

	if (url == NULL) {
		httpdmgr->render_404 = func;
		return (ISC_R_SUCCESS);
	}

	item = isc_mem_get(httpdmgr->mctx, sizeof(isc_httpdurl_t));

	item->url = isc_mem_strdup(httpdmgr->mctx, url);

	item->action = func;
	item->action_arg = arg;
	item->isstatic = isstatic;
	isc_time_now(&item->loadtime);

	ISC_LINK_INIT(item, link);

	LOCK(&httpdmgr->lock);
	ISC_LIST_APPEND(httpdmgr->urls, item, link);
	UNLOCK(&httpdmgr->lock);

	return (ISC_R_SUCCESS);
}

void
isc_httpd_setfinishhook(void (*fn)(void)) {
#if ENABLE_AFL
	finishhook = fn;
#else  /* ENABLE_AFL */
	UNUSED(fn);
#endif /* ENABLE_AFL */
}
