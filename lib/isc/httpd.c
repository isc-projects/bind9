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
#include <isc/sockaddr.h>
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

#define HTTP_RECVLEN	 4096
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

	isc_nmhandle_t *handle;	    /* Permanent pointer to handle */
	isc_nmhandle_t *readhandle; /* Waiting for a read callback */
	isc_nmhandle_t *sendhandle; /* Waiting for a send callback */

	state_t state;
	int flags;

	/*%
	 * Received data state.
	 */
	char recvbuf[HTTP_RECVLEN]; /*%< receive buffer */
	uint32_t recvlen;	    /*%< length recv'd */
	uint32_t consume;	    /*%< length of last command */
	char *headers;		    /*%< set in process_request() */
	bool truncated;
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
process_request(isc_httpd_t *, isc_region_t *, size_t *);
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

static void
free_buffer(isc_mem_t *mctx, isc_buffer_t *buffer) {
	isc_region_t r;

	isc_buffer_region(buffer, &r);
	if (r.base != NULL) {
		isc_mem_put(mctx, r.base, r.length);
	}

	isc_buffer_initnull(buffer);
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

	CHECK(isc_nm_listentcp(nm, ISC_NM_LISTEN_ONE, addr, httpd_newconn,
			       httpdmgr, 5, NULL, &httpdmgr->sock));

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
 * If fvalue is specified and the header was found, then *fvalue will point to
 * the found header's value.
 */
static bool
have_header(isc_httpd_t *httpd, const char *header, const char *value,
	    const char *eov, const char **fvalue) {
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

		/*
		 * Skip optional leading white space.
		 */
		h += hlen;
		while (*h == ' ' || *h == '\t') {
			h++;
		}

		/*
		 * Set the found value.
		 */
		if (fvalue != NULL) {
			*fvalue = h;
		}

		if (value == NULL) {
			return (true);
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
process_request(isc_httpd_t *httpd, isc_region_t *region, size_t *buflen) {
	char *s = NULL, *p = NULL, *urlend = NULL;
	const char *content_length = NULL;
	size_t limit = sizeof(httpd->recvbuf) - httpd->recvlen - 1;
	size_t len = region->length;
	size_t clen = 0;
	int delim;
	bool truncated = false;

	if (len > limit) {
		len = limit;
		truncated = true;
	}

	if (len > 0U) {
		if (httpd->truncated) {
			return (ISC_R_NOSPACE);
		}
		memmove(httpd->recvbuf + httpd->recvlen, region->base, len);
		httpd->recvlen += len;
		httpd->recvbuf[httpd->recvlen] = 0;
		isc_region_consume(region, len);
	}
	if (truncated) {
		httpd->truncated = true;
	}
	httpd->headers = NULL;
	*buflen = httpd->recvlen;

	/*
	 * If we don't find a blank line in our buffer, return that we need
	 * more data.
	 */
	s = strstr(httpd->recvbuf, "\r\n\r\n");
	delim = 2;
	if (s == NULL) {
		s = strstr(httpd->recvbuf, "\n\n");
		delim = 1;
		if (s == NULL) {
			return (httpd->truncated ? ISC_R_NOSPACE
						 : ISC_R_NOTFOUND);
		}
		httpd->consume = s + 2 - httpd->recvbuf;
	} else {
		httpd->consume = s + 4 - httpd->recvbuf;
	}

	/*
	 * NULL terminate the request at the blank line.
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
	urlend = s;

	/*
	 * Make the URL relative.
	 */
	if (strncmp(p, "http://", 7) == 0 || strncmp(p, "https://", 8) == 0) {
		/* Skip first '/' */
		while (*p != '/' && *p != 0) {
			p++;
		}
		if (*p == 0) {
			return (ISC_R_RANGE);
		}
		p++;
		/* Skip second '/' */
		while (*p != '/' && *p != 0) {
			p++;
		}
		if (*p == 0) {
			return (ISC_R_RANGE);
		}
		p++;
		/* Find third '/' */
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
	 * Now, see if there is a question mark in the URL.  If so, this is
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

	if (!have_header(httpd, "Content-Length:", NULL, NULL, &content_length))
	{
		/* Require a Content-Length header for POST requests. */
		if (httpd->method == METHOD_POST) {
			return (ISC_R_BADNUMBER);
		}
	} else {
		INSIST(content_length != NULL);

		clen = (size_t)strtoul(content_length, NULL, 10);
		if (clen == ULONG_MAX) {
			/* Invalid number in the header value. */
			return (ISC_R_BADNUMBER);
		}
		if (httpd->recvlen < httpd->consume + clen) {
			/* The request data isn't complete yet. */
			return (ISC_R_NOTFOUND);
		}

		/* Consume the request's data, which we do not use. */
		httpd->consume += clen;
	}

	if (have_header(httpd, "Connection:", "close", ", \t\r\n", NULL)) {
		httpd->flags |= HTTPD_CLOSE;
	}

	if (have_header(httpd, "Host:", NULL, NULL, NULL)) {
		httpd->flags |= HTTPD_FOUNDHOST;
	}

	if (strncmp(httpd->protocol, "HTTP/1.0", 8) == 0) {
		if (have_header(httpd, "Connection:", "Keep-Alive", ", \t\r\n",
				NULL)) {
			httpd->flags |= HTTPD_KEEPALIVE;
		} else {
			httpd->flags |= HTTPD_CLOSE;
		}
	}

	/*
	 * Check for Accept-Encoding:
	 */
#ifdef HAVE_ZLIB
	if (have_header(httpd, "Accept-Encoding:", "deflate", ";, \t\r\n",
			NULL)) {
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

	/*
	 * Looks like a a valid request, so now we know we won't have
	 * to process this buffer again. We can NULL-terminate the
	 * URL for the caller's benefit, and set recvlen to 0 so
	 * the next read will overwrite this one instead of appending
	 * to the buffer.
	 */
	*urlend = 0;

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
	httpd->consume = 0;
	httpd->truncated = false;
	httpd->headers = NULL;
	httpd->method = METHOD_UNKNOWN;
	httpd->url = NULL;
	httpd->querystring = NULL;
	httpd->protocol = NULL;
	httpd->flags = 0;

	isc_buffer_clear(&httpd->headerbuffer);
	isc_buffer_clear(&httpd->compbuffer);
	isc_buffer_invalidate(&httpd->bodybuffer);
}

static void
httpd_put(void *arg) {
	isc_httpd_t *httpd = (isc_httpd_t *)arg;
	isc_httpdmgr_t *mgr = NULL;

	REQUIRE(VALID_HTTPD(httpd));

	mgr = httpd->mgr;
	REQUIRE(VALID_HTTPDMGR(mgr));

	httpd->magic = 0;
	httpd->mgr = NULL;

	free_buffer(mgr->mctx, &httpd->headerbuffer);
	free_buffer(mgr->mctx, &httpd->compbuffer);

	isc_mem_put(mgr->mctx, httpd, sizeof(*httpd));

	httpdmgr_detach(&mgr);

#if ENABLE_AFL
	if (finishhook != NULL) {
		finishhook();
	}
#endif /* ENABLE_AFL */
}

static void
new_httpd(isc_httpdmgr_t *httpdmgr, isc_nmhandle_t *handle) {
	isc_httpd_t *httpd = NULL;
	char *headerdata = NULL;

	REQUIRE(VALID_HTTPDMGR(httpdmgr));

	httpd = isc_nmhandle_getdata(handle);
	if (httpd == NULL) {
		httpd = isc_mem_get(httpdmgr->mctx, sizeof(*httpd));
		*httpd = (isc_httpd_t){ .handle = NULL };
		httpdmgr_attach(httpdmgr, &httpd->mgr);
	}

	if (httpd->handle == NULL) {
		isc_nmhandle_setdata(handle, httpd, httpd_reset, httpd_put);
		httpd->handle = handle;
	} else {
		INSIST(httpd->handle == handle);
	}

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

	isc_nmhandle_attach(httpd->handle, &httpd->readhandle);
	isc_nm_read(handle, httpd_request, httpdmgr);
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

	new_httpd(httpdmgr, handle);

	return (ISC_R_SUCCESS);
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
 * Reallocates compbuffer to size; does nothing if compbuffer is already
 * larger than size.
 */
static void
alloc_compspace(isc_httpd_t *httpd, unsigned int size) {
	char *newspace = NULL;
	isc_region_t r;

	if (size <= isc_buffer_length(&httpd->compbuffer)) {
		return;
	}

	isc_buffer_region(&httpd->compbuffer, &r);
	newspace = isc_mem_get(httpd->mgr->mctx, size);
	isc_buffer_reinit(&httpd->compbuffer, newspace, size);

	if (r.base != NULL) {
		isc_mem_put(httpd->mgr->mctx, r.base, r.length);
	}
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
	int ret, inputlen;

	/*
	 * We're setting output buffer size to input size so it fails if the
	 * compressed data size would be bigger than the input size.
	 */
	inputlen = isc_buffer_usedlength(&httpd->bodybuffer);
	alloc_compspace(httpd, inputlen);
	isc_buffer_clear(&httpd->compbuffer);

	zstr = (z_stream){
		.total_in = inputlen,
		.avail_out = inputlen,
		.avail_in = inputlen,
		.next_in = isc_buffer_base(&httpd->bodybuffer),
		.next_out = isc_buffer_base(&httpd->compbuffer),
	};

	ret = deflateInit(&zstr, Z_DEFAULT_COMPRESSION);
	if (ret == Z_OK) {
		ret = deflate(&zstr, Z_FINISH);
	}
	deflateEnd(&zstr);
	if (ret == Z_STREAM_END) {
		isc_buffer_add(&httpd->compbuffer, zstr.total_out);
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
	size_t buflen = 0;

	httpd = isc_nmhandle_getdata(handle);

	REQUIRE(httpd->handle == handle);

	if (eresult != ISC_R_SUCCESS) {
		goto cleanup_readhandle;
	}

	REQUIRE(httpd->state == RECV);

	result = process_request(
		httpd, region == NULL ? &(isc_region_t){ NULL, 0 } : region,
		&buflen);
	if (result == ISC_R_NOTFOUND) {
		if (buflen < HTTP_RECVLEN - 1) {
			if (region != NULL) {
				/* don't unref, keep reading */
				return;
			}

			/*
			 * We must have been called from httpd_senddone (as
			 * ISC_R_NOTFOUND is not returned from netmgr) and we
			 * need to resume reading.
			 */
			isc_nm_resumeread(httpd->readhandle);
			return;
		}
		goto cleanup_readhandle;
	} else if (result != ISC_R_SUCCESS) {
		goto cleanup_readhandle;
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
	isc_buffer_clear(&httpd->headerbuffer);
	isc_buffer_setautorealloc(httpd->sendbuffer, true);
	databuffer = (is_compressed ? &httpd->compbuffer : &httpd->bodybuffer);
	isc_buffer_putmem(httpd->sendbuffer, isc_buffer_base(databuffer),
			  isc_buffer_usedlength(databuffer));

	/* Consume the request from the recv buffer. */
	if (httpd->consume != 0U) {
		INSIST(httpd->consume <= httpd->recvlen);
		if (httpd->consume < httpd->recvlen) {
			memmove(httpd->recvbuf, httpd->recvbuf + httpd->consume,
				httpd->recvlen - httpd->consume);
		}
		httpd->recvlen -= httpd->consume;
		httpd->consume = 0;
		httpd->recvbuf[httpd->recvlen] = 0;
	}

	/*
	 * Determine total response size.
	 */
	isc_buffer_usedregion(httpd->sendbuffer, &r);

	isc_nm_pauseread(httpd->handle);
	httpd->state = SEND;

	isc_nmhandle_attach(httpd->handle, &httpd->sendhandle);
	isc_nm_send(httpd->sendhandle, &r, httpd_senddone, httpd);
	return;

cleanup_readhandle:
	isc_nmhandle_detach(&httpd->readhandle);
}

void
isc_httpdmgr_shutdown(isc_httpdmgr_t **httpdmgrp) {
	isc_httpdmgr_t *httpdmgr = NULL;
	isc_httpd_t *httpd = NULL;

	REQUIRE(httpdmgrp != NULL);
	REQUIRE(VALID_HTTPDMGR(*httpdmgrp));

	httpdmgr = *httpdmgrp;
	*httpdmgrp = NULL;

	isc_nm_stoplistening(httpdmgr->sock);

	LOCK(&httpdmgr->lock);
	httpdmgr->flags |= ISC_HTTPDMGR_SHUTTINGDOWN;

	httpd = ISC_LIST_HEAD(httpdmgr->running);
	while (httpd != NULL) {
		isc_nm_cancelread(httpd->readhandle);
		httpd = ISC_LIST_NEXT(httpd, link);
	}
	UNLOCK(&httpdmgr->lock);

	isc_nmsocket_close(&httpdmgr->sock);

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
	REQUIRE(httpd->handle == handle);

	/* Clean up buffers */
	isc_buffer_free(&httpd->sendbuffer);
	if (httpd->freecb != NULL && isc_buffer_length(&httpd->bodybuffer) > 0)
	{
		httpd->freecb(&httpd->bodybuffer, httpd->freecb_arg);
	}

	isc_nmhandle_detach(&httpd->sendhandle);

	if (result != ISC_R_SUCCESS) {
		goto cleanup_readhandle;
	}

	if ((httpd->flags & HTTPD_CLOSE) != 0) {
		goto cleanup_readhandle;
	}

	REQUIRE(httpd->state == SEND);

	httpd->state = RECV;
	httpd->sendhandle = NULL;

	if (httpd->recvlen != 0) {
		/*
		 * Outstanding requests still exist, start processing
		 * them.
		 */
		httpd_request(httpd->handle, ISC_R_SUCCESS, NULL, httpd->mgr);
	} else if (!httpd->truncated) {
		isc_nm_resumeread(httpd->readhandle);
	} else {
		/* Truncated request, don't resume */
		goto cleanup_readhandle;
	}

	return;

cleanup_readhandle:
	isc_nmhandle_detach(&httpd->readhandle);
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
