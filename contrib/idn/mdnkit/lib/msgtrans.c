#ifndef lint
static char *rcsid = "$Id: msgtrans.c,v 1.1 2002/01/02 02:46:45 marka Exp $";
#endif

/*
 * Copyright (c) 2000,2001 Japan Network Information Center.
 * All rights reserved.
 *  
 * By using this file, you agree to the terms and conditions set forth bellow.
 * 
 * 			LICENSE TERMS AND CONDITIONS 
 * 
 * The following License Terms and Conditions apply, unless a different
 * license is obtained from Japan Network Information Center ("JPNIC"),
 * a Japanese association, Kokusai-Kougyou-Kanda Bldg 6F, 2-3-4 Uchi-Kanda,
 * Chiyoda-ku, Tokyo 101-0047, Japan.
 * 
 * 1. Use, Modification and Redistribution (including distribution of any
 *    modified or derived work) in source and/or binary forms is permitted
 *    under this License Terms and Conditions.
 * 
 * 2. Redistribution of source code must retain the copyright notices as they
 *    appear in each source code file, this License Terms and Conditions.
 * 
 * 3. Redistribution in binary form must reproduce the Copyright Notice,
 *    this License Terms and Conditions, in the documentation and/or other
 *    materials provided with the distribution.  For the purposes of binary
 *    distribution the "Copyright Notice" refers to the following language:
 *    "Copyright (c) Japan Network Information Center.  All rights reserved."
 * 
 * 4. Neither the name of JPNIC may be used to endorse or promote products
 *    derived from this Software without specific prior written approval of
 *    JPNIC.
 * 
 * 5. Disclaimer/Limitation of Liability: THIS SOFTWARE IS PROVIDED BY JPNIC
 *    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *    PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL JPNIC BE LIABLE
 *    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *    OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *    ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * 6. Indemnification by Licensee
 *    Any person or entities using and/or redistributing this Software under
 *    this License Terms and Conditions shall defend indemnify and hold
 *    harmless JPNIC from and against any and all judgements damages,
 *    expenses, settlement liabilities, cost and other liabilities of any
 *    kind as a result of use and redistribution of this Software or any
 *    claim, suite, action, litigation or proceeding by any third party
 *    arising out of or relates to this License Terms and Conditions.
 * 
 * 7. Governing Law, Jurisdiction and Venue
 *    This License Terms and Conditions shall be governed by and and
 *    construed in accordance with the law of Japan. Any person or entities
 *    using and/or redistributing this Software under this License Terms and
 *    Conditions hereby agrees and consent to the personal and exclusive
 *    jurisdiction and venue of Tokyo District Court of Japan.
 */

#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#ifdef  WIN32
#include <windows.h>
#include <winsock.h>
#else   /* for normal systems */
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif
#endif

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/logmacro.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>
#include <mdn/res.h>
#include <mdn/msgheader.h>
#include <mdn/msgtrans.h>
#include <mdn/dn.h>
#include <mdn/debug.h>

#define DNS_HEADER_SIZE		12
#define DNAME_SIZE		512
#define RRFORMAT_HASH_SIZE	47

/*
 * Translation directions.
 */
enum {
	transdir_query = 0,
	transdir_reply = 1
};

/*
 * DNS opcodes.
 */
enum {
	opcode_query = 0,
	opcode_iquery = 1,
	opcode_status = 2,
	opcode_notify = 4,
	opcode_update = 5
};

/*
 * Resource record types.
 */
enum {
	rrtype_A = 1,
	rrtype_NS = 2,
	rrtype_MD = 3,
	rrtype_MF = 4,
	rrtype_CNAME = 5,
	rrtype_SOA = 6,
	rrtype_MB = 7,
	rrtype_MG = 8,
	rrtype_MR = 9,
	rrtype_NULL = 10,
	rrtype_WKS = 11,
	rrtype_PTR = 12,
	rrtype_HINFO = 13,
	rrtype_MINFO = 14,
	rrtype_MX = 15,
	rrtype_TXT = 16,
	rrtype_RP = 17,
	rrtype_AFSDB = 18,
	rrtype_X25 = 19,
	rrtype_ISDN = 20,
	rrtype_RT = 21,
	rrtype_AAAA = 28
};

/*
 * Resource record classes.
 */
enum {
	rrclass_IN = 1,
	rrclass_CS = 2,
	rrclass_CH = 3,
	rrclass_ANY = 255
};

typedef struct msgtrans_ctx {
	int transdir;		/* direction of translation */
	const char *in;		/* input message */
	size_t in_len;		/* length of it */
	const char *in_ptr;	/* current pointer */
	size_t in_remain;	/* # of remaining octets */
	char *out;		/* output (translated) message */
	char *out_ptr;		/* current pointer */
	size_t out_remain;	/* # of remaining (available) octets */
	mdn__dn_t dn_ctx;	/* for compression */
	mdn_resconf_t conf;	/* translation parameters */
} msgtrans_ctx_t;

static struct rrformat {
	unsigned int type;		/* RR type */
	unsigned int class;		/* RR class */
	const char *format;		/* RDATA format */
	struct rrformat *next;		/* hash chain */
} rrformats[] = {
	{ rrtype_CNAME,	rrclass_ANY,	"D" },
	{ rrtype_HINFO,	rrclass_ANY,	"TT" },
	{ rrtype_MB,	rrclass_ANY,	"D" },
	{ rrtype_MD,	rrclass_ANY,	"D" },
	{ rrtype_MF,	rrclass_ANY,	"D" },
	{ rrtype_MG,	rrclass_ANY,	"D" },
	{ rrtype_MINFO,	rrclass_ANY,	"DD" },
	{ rrtype_MR,	rrclass_ANY,	"D" },
	{ rrtype_MX,	rrclass_ANY,	"SD" },
	{ rrtype_NULL,	rrclass_ANY,	"R" },
	{ rrtype_NS,	rrclass_ANY,	"D" },
	{ rrtype_PTR,	rrclass_ANY,	"D" },
	{ rrtype_SOA,	rrclass_ANY,	"DDLLLLL" },
	{ rrtype_TXT,	rrclass_ANY,	"T" },
	{ rrtype_A,	rrclass_IN,	"L" },
	{ rrtype_WKS,	rrclass_IN,	"LCR" },
	{ rrtype_RP,	rrclass_ANY,	"DD" },
	{ rrtype_AFSDB,	rrclass_ANY,	"SD" },
	{ rrtype_X25,	rrclass_ANY,	"T" },
	{ rrtype_ISDN,	rrclass_ANY,	"TT" },
	{ rrtype_RT,	rrclass_ANY,	"SD" },
	{ rrtype_AAAA,	rrclass_IN,	"H" },
	{ 0,		0,		NULL },
};
static struct rrformat	*rrformathash[RRFORMAT_HASH_SIZE];

/*
 * Name translation instructions.
 *
 * For query, perform
 *   1. local encoding to UTF-8 conversion
 *   2. delimiter mapping
 *   3. local mapping
 *   4. nameprep
 *   5. UTF-8 to IDN encoding conversion
 *
 * For reply,
 *   1. IDN encoding to UTF-8 conversion
 *   2. UTF-8 to local encoding conversion
 *
 * See mdn/res.h for the mnemonic.
 */
static const char *trans_insn[] = {
	"ldMNI",	/* insn for QUERY (transdir_query) */
	"i!NL",		/* insn for REPLY (transdir_reply) */
};

/*
 * Labels of translation directions, used for log messages.
 */
static const char *trans_labels[] = {
	"QUERY",	/* QUERY (transdir_query) */
	"REPLY",	/* REPLY (transdir_reply) */
};

static mdn_result_t	copy_header(msgtrans_ctx_t *ctx);
static mdn_result_t	translate_question(msgtrans_ctx_t *ctx);
static mdn_result_t	translate_rr(msgtrans_ctx_t *ctx);
static mdn_result_t	translate_rdata(msgtrans_ctx_t *ctx,
					unsigned int rr_type,
					unsigned int rr_class,
					unsigned int rr_length);
static const char	*rdata_format(unsigned int rr_type,
				      unsigned int rr_class);
static mdn_result_t	translate_domain(msgtrans_ctx_t *ctx);
static mdn_result_t	get_domainname(msgtrans_ctx_t *ctx, char *buf,
				       size_t bufsize);
static mdn_result_t	put_domainname(msgtrans_ctx_t *ctx, char *name);
static void		ctx_init(msgtrans_ctx_t *ctx,
				 mdn_resconf_t conf, mdn_msgheader_t *header,
				 const char *msg, size_t msglen,
				 char *outbuf, size_t outbufsize);
static mdn_result_t	copy_rest(msgtrans_ctx_t *ctx);
static mdn_result_t	copy_message(msgtrans_ctx_t *ctx, size_t len);
static size_t		output_length(msgtrans_ctx_t *ctx);
static void		dump_message(const char *title, const char *p,
				     size_t length);


mdn_result_t
mdn_msgtrans_translate(mdn_resconf_t conf,
		       const char *msg, size_t msglen,
		       char *outbuf, size_t outbufsize, size_t *outmsglenp)
{
	mdn_result_t r;
	msgtrans_ctx_t ctx;
	mdn_msgheader_t header;
	int i, n;

	assert(conf != NULL && msg != NULL &&
	       outbuf != NULL && outbufsize > 0 && outmsglenp != NULL);

	TRACE(("mdn_msgtrans_translate(msg=<%s>,msglen=%d)\n",
	       mdn_debug_hexdata(msg, msglen, 64), msglen));

	if (LOGLEVEL >= mdn_log_level_dump)
		dump_message("before translation", msg, msglen);

	/*
	 * Check message length.
	 */
	if (msglen < DNS_HEADER_SIZE) {
		INFO(("mdn_msgtrans_translate: incoming packet too short "
		     "(%d octets)\n", msglen));
		return (mdn_invalid_message);
	}

	/*
	 * Parse message header.
	 */
	if ((r = mdn_msgheader_parse(msg, msglen, &header)) != mdn_success) {
		WARNING(("mdn_msgtrans_translate: message header "
			 "parsing failed: %s\n",
			 mdn_result_tostring(r)));
		return (r);
	}

	/*
	 * Create translation context.
	 */
	ctx_init(&ctx, conf, &header, msg, msglen, outbuf, outbufsize);

	/*
	 * We handle only query, notify and update messages.
	 * Do not process others.
	 */
	switch (header.opcode) {
	case opcode_query:
	case opcode_notify:
	case opcode_update:
		break;
	default:
		INFO(("mdn_msgtrans_translate: pass through message "
		     "whose opcode is %d", header.opcode));
		if ((r = copy_rest(&ctx)) == mdn_success)
			*outmsglenp = output_length(&ctx);
		return (mdn_success);
	}

	/*
	 * Copy header part verbatim.
	 */
	(void)copy_header(&ctx);

	/*
	 * Parse question/zone section.
	 */
	n = header.qdcount;
	for (i = 0; i < n; i++) {
		if ((r = translate_question(&ctx)) != mdn_success)
			return (r);
	}

	/*
	 * Translate other sections.
	 */
	n = header.ancount + header.nscount + header.arcount;
	for (i = 0; i < n; i++) {
		if ((r = translate_rr(&ctx)) != mdn_success)
			return (r);
	}

	if (LOGLEVEL >= mdn_log_level_dump)
		dump_message("after translation",
			     ctx.out, output_length(&ctx));

	/*
	 * Is there anything left out?
	 */
	if (ctx.in_remain != 0) {
		WARNING(("mdn_msgtrans_translate: garbage at the end "
			"(%d octets)\n", ctx.in_remain));
		/* don't consider this as an error. */
		/* return (mdn_invalid_message); */
	}

	*outmsglenp = output_length(&ctx);
	return (mdn_success);
}

static mdn_result_t
copy_header(msgtrans_ctx_t *ctx) {
	return (copy_message(ctx, DNS_HEADER_SIZE));
}

static mdn_result_t
translate_question(msgtrans_ctx_t *ctx) {
	mdn_result_t r;
	char qname[DNAME_SIZE], qname_translated[DNAME_SIZE];

	/* Get QNAME. */
	if ((r = get_domainname(ctx, qname, sizeof(qname))) != mdn_success)
		return (r);

	INFO(("request of QNAME %s translation: name=\"%s\"\n",
	      trans_labels[ctx->transdir], mdn_debug_xstring(qname, 256)));

	/* Translate QNAME. */
	r = mdn_res_nameconv(ctx->conf, trans_insn[ctx->transdir], qname,
			     qname_translated, sizeof(qname_translated));
	if (r != mdn_success)
		goto failure;
	r = put_domainname(ctx, qname_translated);
	if (r != mdn_success)
		goto failure;

	/* Copy QTYPE and QCLASS */
	r = copy_message(ctx, 4);
	if (r != mdn_success)
		goto failure;

	INFO(("result of QNAME %s translation: name=\"%s\"\n",
	      trans_labels[ctx->transdir],
	      mdn_debug_xstring(qname_translated, 256)));

	return (mdn_success);

failure:
	INFO(("QNAME %s translation failed, %s\n",
	      trans_labels[ctx->transdir], mdn_result_tostring(r)));
	return (r);
}

static mdn_result_t
translate_rr(msgtrans_ctx_t *ctx) {
	mdn_result_t r;
	unsigned char *p;
	unsigned int rr_type, rr_class, rr_length;
	char dname[DNAME_SIZE], dname_translated[DNAME_SIZE];
	size_t length_before;

	/* Get NAME. */
	if ((r = get_domainname(ctx, dname, sizeof(dname))) != mdn_success)
		return (r);

	INFO(("request of RR NAME %s translation: name=\"%s\"\n",
	      trans_labels[ctx->transdir], mdn_debug_xstring(dname, 256)));

	/* Translate NAME. */
	r = mdn_res_nameconv(ctx->conf, trans_insn[ctx->transdir], dname,
			     dname_translated, sizeof(dname_translated));
	if (r != mdn_success)
		goto failure;
	r = put_domainname(ctx, dname_translated);
	if (r != mdn_success)
		goto failure;

	/* Get TYPE and CLASS */
	if (ctx->in_remain < 10) {
		r = mdn_invalid_message;
		goto failure;
	}
	p = (unsigned char *)ctx->in_ptr;
#define GET16(off)	((p[off]<<8)+p[(off)+1])
	rr_type = GET16(0);
	rr_class = GET16(2);
	rr_length = GET16(8);
#undef GET16

	/* Copy TYPE, CLASS, TTL and RDLENGTH. */
	r = copy_message(ctx, 10);
	if (r != mdn_success)
		goto failure;

	/* Remember the current output length. */
	length_before = output_length(ctx);

	/* Translate RDATA. */
	r = translate_rdata(ctx, rr_type, rr_class, rr_length);
	if (r != mdn_success)
		goto failure;

	/* Reset RDLENGTH */
	rr_length = output_length(ctx) - length_before;
	ctx->out[length_before - 2] = (rr_length >> 8) & 0xff;
	ctx->out[length_before - 1] = rr_length & 0xff;

	INFO(("result of RR NAME %s translation: name=\"%s\"\n",
	      trans_labels[ctx->transdir],
	      mdn_debug_xstring(dname_translated, 256)));

	return (r);

failure:
	INFO(("RR NAME %s translation failed, %s\n",
	      trans_labels[ctx->transdir], mdn_result_tostring(r)));
	return (r);	
}

static mdn_result_t
translate_rdata(msgtrans_ctx_t *ctx, unsigned int rr_type,
		unsigned int rr_class, unsigned int rr_length)
{
	const char *format;
	int c;

	if ((format = rdata_format(rr_type, rr_class)) == NULL) {
		INFO(("mdn_msgtrans: unknown resource record type %d "
		     "pass through\n", rr_type));
		return (copy_message(ctx, rr_length));
	}

	while ((c = *format++) != '\0') {
		int copy_len;
		mdn_result_t r;

		switch (c) {
		case 'D':	/* domain name */
		{
			int remain_org = ctx->in_remain;

			if ((r = translate_domain(ctx)) != mdn_success)
				return (r);
			rr_length -= remain_org - ctx->in_remain;
			continue;
		}
		case 'T':	/* character string */
			copy_len = *((unsigned char *)ctx->in_ptr) + 1;
			break;
		case 'C':	/* 1-octet value */
			copy_len = 1;
			break;
		case 'S':	/* 2-octet value */
			copy_len = 2;
			break;
		case 'L':	/* 4-octet value */
			copy_len = 4;
			break;
		case 'H':	/* 16-octet value (AAAA) */
			copy_len = 16;
			break;
		case 'R':	/* the rest */
			copy_len = rr_length;
			break;
		default:
			copy_len = 0;	/* for gcc -Wall */
			FATAL(("mdn_msgtrans: internal error -- "
			      "unknown format character %c", c));
			/* NOTREACHED */
			break;
		}
		if ((r = copy_message(ctx, copy_len)) != mdn_success)
			return (r);
		rr_length -= copy_len;
	}
	return (mdn_success);
}

static const char *
rdata_format(unsigned int rr_type, unsigned int rr_class) {
	static int initialized;
	struct rrformat *rp;
	int h;

	if (!initialized) {
		/*
		 * Build hash table.
		 */
		for (rp = rrformats; rp->format != NULL; rp++) {
			h = rp->type % RRFORMAT_HASH_SIZE;
			rp->next = rrformathash[h];
			rrformathash[h] = rp;
		}
		initialized = 1;
	}

	/*
	 * Find the element with the specified type and class.
	 */
	h = rr_type % RRFORMAT_HASH_SIZE;
	for (rp = rrformathash[h]; rp != NULL; rp = rp->next) {
		if (rp->type == rr_type &&
		    (rp->class == rr_class || rp->class == rrclass_ANY))
			return (rp->format);
	}
	return (NULL);
}

static mdn_result_t
translate_domain(msgtrans_ctx_t *ctx) {
	mdn_result_t r;
	char dname[DNAME_SIZE], dname_translated[DNAME_SIZE];

	/* Get NAME. */
	if ((r = get_domainname(ctx, dname, sizeof(dname))) != mdn_success)
		return (r);

	INFO(("request of RDATA %s translation: name=\"%s\"\n",
	      trans_labels[ctx->transdir], mdn_debug_xstring(dname, 256)));

	/* Translate NAME. */
	r = mdn_res_nameconv(ctx->conf, trans_insn[ctx->transdir], dname,
			     dname_translated, sizeof(dname_translated));
	if (r != mdn_success)
		goto failure;
	if ((r = put_domainname(ctx, dname_translated)) != mdn_success)
		goto failure;

	INFO(("result of RDATA %s translation: name=\"%s\"\n",
	      trans_labels[ctx->transdir],
	      mdn_debug_xstring(dname_translated, 256)));

	return (mdn_success);

failure:
	INFO(("RDATA %s translation failed, %s\n",
	      trans_labels[ctx->transdir], mdn_result_tostring(r)));
	return (r);	
}

static mdn_result_t
get_domainname(msgtrans_ctx_t *ctx, char *buf, size_t bufsize) {
	mdn_result_t r;
	size_t n;

	r = mdn__dn_expand(ctx->in, ctx->in_len, ctx->in_ptr,
			   buf, bufsize, &n);
	if (r == mdn_success) {
		ctx->in_ptr += n;
		ctx->in_remain -= n;
	}
	return (r);
}

static mdn_result_t
put_domainname(msgtrans_ctx_t *ctx, char *name) {
	mdn_result_t r;
	size_t n;

	r = mdn__dn_compress(name, ctx->out_ptr, ctx->out_remain,
			     &ctx->dn_ctx, &n);
	if (r == mdn_success) {
		ctx->out_ptr += n;
		ctx->out_remain -= n;
	}
	return (r);
}

static void
ctx_init(msgtrans_ctx_t *ctx, mdn_resconf_t conf, mdn_msgheader_t *header,
	 const char *msg, size_t msglen, char *outbuf, size_t outbufsize)
{
	ctx->transdir = (header->qr == 0) ? transdir_query : transdir_reply;
	ctx->in = ctx->in_ptr = msg;
	ctx->in_len = ctx->in_remain = msglen;
	ctx->out = ctx->out_ptr = outbuf;
	ctx->out_remain = outbufsize;
	mdn__dn_initcompress(&ctx->dn_ctx, outbuf);
	ctx->conf = conf;
}

static mdn_result_t
copy_rest(msgtrans_ctx_t *ctx) {
	return (copy_message(ctx, ctx->in_remain));
}

static mdn_result_t
copy_message(msgtrans_ctx_t *ctx, size_t len) {
	assert(ctx != NULL);

	if (ctx->in_remain < len)
		return (mdn_invalid_message);

	if (ctx->out_remain < len)
		return (mdn_buffer_overflow);

	(void)memcpy(ctx->out_ptr, ctx->in_ptr, len);

	ctx->in_ptr += len;
	ctx->in_remain -= len;
	ctx->out_ptr += len;
	ctx->out_remain -= len;

	return (mdn_success);
}

static size_t
output_length(msgtrans_ctx_t *ctx) {
	return (ctx->out_ptr - ctx->out);
}

static void
dump_message(const char *title, const char *p, size_t length) {
	DUMP(("message (%s): length %d\n", title, length));
	while (length > 0) {
		int len = length < 16 ? length : 16;
		DUMP(("  %s\n", mdn_debug_hexdata(p, len, 16)));
		p += len;
		length -= len;
	}
}
