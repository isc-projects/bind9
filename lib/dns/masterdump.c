/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/boolean.h>
#include <isc/region.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/time.h>
#include <dns/ttl.h>
#include <dns/masterdump.h>

#define RETERR(x) do { \
	isc_result_t __r = (x); \
	if (__r != DNS_R_SUCCESS) \
		return (__r); \
	} while (0)

struct dns_master_style {
	unsigned int flags;		/* DNS_STYLEFLAG_* */
	unsigned int ttl_column;
	unsigned int class_column;
	unsigned int type_column;
	unsigned int rdata_column;
	unsigned int line_length;
	unsigned int tab_width;
};

/*
 * Flags affecting master file formatting.  Flags 0x0000FFFF
 * define the formatting of the rdata part and are defined in
 * rdata.h.
 */
 
/* Omit the owner name when possible. */
#define DNS_STYLEFLAG_OMIT_OWNER	0x00010000U

/*
 * Omit the TTL when possible.  If DNS_STYLEFLAG_TTL is 
 * also set, this means no TTLs are ever printed
 * because $TTL directives are generated before every
 * change in the TTL.  In this case, no columns need to 
 * be reserved for the TTL.  Master files generated with
 * these options will be rejected by BIND 4.x because it
 * does not recognize the $TTL directive.
 *
 * If DNS_STYLEFLAG_TTL is not also set, the TTL will be 
 * omitted when it is equal to the previous TTL.
 * This is correct according to RFC1035, but the 
 * TTLs may be silently misinterpreted by older 
 * versions of BIND which use the SOA MINTTL as a
 * default TTL value.
 */
#define DNS_STYLEFLAG_OMIT_TTL		0x00020000U

/* Omit the class when possible. */
#define DNS_STYLEFLAG_OMIT_CLASS	0x00040000U

/* Output $TTL directives. */
#define DNS_STYLEFLAG_TTL		0x00080000U

/*
 * Output $ORIGIN directives and print owner names relative to
 * the origin when possible.
 */
#define DNS_STYLEFLAG_REL_OWNER		0x00100000U

/* Print domain names in RR data in relative form when possible. 
   For this to take effect, DNS_STYLEFLAG_REL_OWNER must also be set. */
#define DNS_STYLEFLAG_REL_DATA		0x00200000U


/*
 * The maximum length of the newline+indentation that is output
 * when inserting a line break in an RR.  This effectively puts an 
 * upper limits on the value of "rdata_column", because if it is
 * very large, the tabs and spaces needed to reach it will not fit.
 */
#define DNS_TOTEXT_LINEBREAK_MAXLEN 100

/*
 * Context structure for a masterfile dump in progress.
 */
typedef struct dns_totext_ctx {
	dns_master_style_t	style;
	isc_boolean_t 		class_printed;
	char *			linebreak;
	char 			linebreak_buf[DNS_TOTEXT_LINEBREAK_MAXLEN];
	dns_name_t *		origin;
	dns_fixedname_t		origin_fixname;
	isc_uint32_t 		current_ttl;
	isc_boolean_t 		current_ttl_valid;
} dns_totext_ctx_t;

/*
 * The default master file style.
 *
 * Because the TTL is always omitted, and the class is almost always
 * omitted, neither is allocated any columns.
 */
const dns_master_style_t 
dns_master_style_default = {
	DNS_STYLEFLAG_OMIT_OWNER |
	DNS_STYLEFLAG_OMIT_CLASS |
	DNS_STYLEFLAG_REL_OWNER |
	DNS_STYLEFLAG_REL_DATA |
	DNS_STYLEFLAG_OMIT_TTL |
	DNS_STYLEFLAG_TTL |
	DNS_STYLEFLAG_COMMENT |
	DNS_STYLEFLAG_MULTILINE,
	24, 24, 24, 32, 80, 8 
};

/*
 * A style suitable for dns_rdataset_totext().
 */
dns_master_style_t 
dns_masterfile_style_debug = {
        DNS_STYLEFLAG_REL_OWNER,
	24, 32, 40, 48, 80, 8
};


#define N_SPACES 10
char spaces[N_SPACES+1] = "          ";

#define N_TABS 10
char tabs[N_TABS+1] = "\t\t\t\t\t\t\t\t\t\t";



/*
 * Output tabs and spaces to go from column '*current' to 
 * column 'to', and update '*current' to reflect the new
 * current column.
 */
static isc_result_t
indent(unsigned int *current, unsigned int to, int tabwidth,
       isc_buffer_t *target)
{
	isc_region_t r;
	unsigned char *p;
	unsigned int from;
	int ntabs, nspaces, t;

	from = *current;

	if (to < from + 1)
		to = from + 1;

	ntabs = to / tabwidth - from / tabwidth;
	if (ntabs < 0) 
		ntabs = 0;

	if (ntabs > 0) {
		isc_buffer_available(target, &r);
		if (r.length < (unsigned) ntabs)
			return (DNS_R_NOSPACE);
		p = r.base;
	
		t = ntabs;
		while (t) {
			int n = t;
			if (n > N_TABS)
				n = N_TABS;
			memcpy(p, tabs, n);
			p += n;
			t -= n;
		}
		isc_buffer_add(target, ntabs);
		from = (to / tabwidth) * tabwidth;
	}

	nspaces = to - from;
	INSIST(nspaces >= 0);

	isc_buffer_available(target, &r);
	if (r.length < (unsigned) nspaces)
		return (DNS_R_NOSPACE);
	p = r.base;

	t = nspaces;	
	while (t) {
		int n = t;
		if (n > N_SPACES)
			n = N_SPACES;
		memcpy(p, spaces, n);
		p += n;
		t -= n;
	}
	isc_buffer_add(target, nspaces);	

	*current = to;
	return (DNS_R_SUCCESS);
}

static isc_result_t
totext_ctx_init(const dns_master_style_t *style, dns_totext_ctx_t *ctx)
{
	isc_result_t result;
	
	ctx->style = *style;
	REQUIRE(style->tab_width != 0);
	dns_fixedname_init(&ctx->origin_fixname);

	/* Set up the line break string if needed. */
	if ((ctx->style.flags & DNS_STYLEFLAG_MULTILINE) != 0) {
		isc_buffer_t buf;
		isc_region_t r;
		unsigned int col = 0;

		isc_buffer_init(&buf, ctx->linebreak_buf,
				sizeof(ctx->linebreak_buf),
				ISC_BUFFERTYPE_TEXT);
		
		isc_buffer_available(&buf, &r);
		if (r.length < 1)
			return (DNS_R_TEXTTOOLONG);
		r.base[0] = '\n';
		isc_buffer_add(&buf, 1);

		result = indent(&col, ctx->style.rdata_column, 
				ctx->style.tab_width, &buf);
		/*
		 * Do not return DNS_R_NOSPACE if the line break string
		 * buffer is too small, because that would just make 
		 * dump_rdataset() retry indenfinitely with ever 
		 * bigger target buffers.  That's a different buffer,
		 * so it won't help.  Use DNS_R_TEXTTOOLONG as a substitute.
		 */
		if (result == DNS_R_NOSPACE)
			return (DNS_R_TEXTTOOLONG);
		if (result != DNS_R_SUCCESS)
			return (result);
		
		isc_buffer_available(&buf, &r);
		if (r.length < 1)
			return (DNS_R_TEXTTOOLONG);
		r.base[0] = '\0';
		isc_buffer_add(&buf, 1);
		ctx->linebreak = ctx->linebreak_buf;
	} else {
		ctx->linebreak = NULL;
	}

	ctx->class_printed = ISC_FALSE;
	ctx->origin = NULL;
	
	return (DNS_R_SUCCESS);
}

#define INDENT_TO(col) \
	do { \
		 if ((result = indent(&column, ctx->style.col, \
				      ctx->style.tab_width, target)) \
		     != DNS_R_SUCCESS) \
			    return (result); \
        } while (0)


/*
 * Convert 'rdataset' to master file text format according to 'ctx',
 * storing the result in 'target'.  If 'owner_name' is NULL, it
 * is omitted; otherwise 'owner_name' must be valid and have at least
 * one label.
 */

static isc_result_t
rdataset_totext(dns_rdataset_t *rdataset,
		dns_name_t *owner_name,
		dns_totext_ctx_t *ctx,
		isc_boolean_t omit_final_dot,
		isc_buffer_t *target)
{
	isc_result_t result;
	unsigned int column;
	isc_boolean_t first = ISC_TRUE;
	isc_uint32_t current_ttl;
	isc_boolean_t current_ttl_valid;
	
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	
	result = dns_rdataset_first(rdataset);
	REQUIRE(result == DNS_R_SUCCESS);

	current_ttl = ctx->current_ttl;
	current_ttl_valid = ctx->current_ttl_valid;

	do {
		column = 0;
		
		/* Owner name. */
		if (owner_name != NULL &&
		    ! ((ctx->style.flags & DNS_STYLEFLAG_OMIT_OWNER) != 0 &&
		       !first))
		{
			unsigned int name_start = target->used;
			RETERR(dns_name_totext(owner_name,
					       omit_final_dot,
					       target));
			column += target->used - name_start;
		}

		/* TTL. */
		if (! ((ctx->style.flags & DNS_STYLEFLAG_OMIT_TTL) != 0 &&
		       current_ttl_valid &&
		       rdataset->ttl == current_ttl))
		{
			char ttlbuf[64];
			isc_region_t r;
			unsigned int length;

			INDENT_TO(ttl_column);
			length = sprintf(ttlbuf, "%u", rdataset->ttl);
			INSIST(length <= sizeof ttlbuf);
			isc_buffer_available(target, &r);
			if (r.length < length)
				return (DNS_R_NOSPACE);
			memcpy(r.base, ttlbuf, length);
			isc_buffer_add(target, length);
			column += length;

			/*
			 * If the $TTL directive is not in use, the TTL we 
			 * just printed becomes the default for subsequent RRs.
			 */
			if ((ctx->style.flags & DNS_STYLEFLAG_TTL) == 0) {
				current_ttl = rdataset->ttl;
				current_ttl_valid = ISC_TRUE;
			}
		}

		/* Class. */
		if ((ctx->style.flags & DNS_STYLEFLAG_OMIT_CLASS) == 0 ||
		    ctx->class_printed == ISC_FALSE)
		{
			unsigned int class_start;
			INDENT_TO(class_column);
			class_start = target->used;
			result = dns_rdataclass_totext(rdataset->rdclass,
						       target);
			if (result != DNS_R_SUCCESS)
				return (result);
			column += (target->used - class_start);
		}

		/* Type. */
		{
			unsigned int type_start;
			INDENT_TO(type_column);
			type_start = target->used;
			result = dns_rdatatype_totext(rdataset->type, target);
			if (result != DNS_R_SUCCESS)
				return (result);
			column += (target->used - type_start);
		}

		/* Rdata. */ 
		{
			dns_rdata_t rdata;
			isc_region_t r;

			INDENT_TO(rdata_column);
			dns_rdataset_current(rdataset, &rdata);

			RETERR(dns_rdata_tofmttext(&rdata,
						   ctx->origin,
						   ctx->style.flags,
						   ctx->style.line_length -
						       ctx->style.rdata_column,
						   ctx->linebreak,
						   target));

			isc_buffer_available(target, &r);
			if (r.length < 1)
				return (DNS_R_NOSPACE);
			r.base[0] = '\n';
			isc_buffer_add(target, 1);
		}

		first = ISC_FALSE;
		result = dns_rdataset_next(rdataset);
	} while (result == DNS_R_SUCCESS);

	if (result != DNS_R_NOMORE)
		return (result);

	/*
	 * Update the ctx state to reflect what we just printed.
	 * This is done last, only when we are sure we will return 
	 * success, because this function may be called multiple 
	 * times with increasing buffer sizes until it succeeds,
	 * and failed attempts must not update the state prematurely. 
	 */
	ctx->class_printed = ISC_TRUE;
	ctx->current_ttl= current_ttl;
	ctx->current_ttl_valid = current_ttl_valid;

	return (DNS_R_SUCCESS);
}

/*
 * Print the name, type, and class of an empty rdataset,
 * such as those used to represent the question section
 * of a DNS message.
 */
static isc_result_t
question_totext(dns_rdataset_t *rdataset,
		dns_name_t *owner_name,
		dns_totext_ctx_t *ctx,
		isc_boolean_t omit_final_dot,
		isc_buffer_t *target)
{
	unsigned int column;
	isc_result_t result;
	isc_region_t r;

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	result = dns_rdataset_first(rdataset);
	REQUIRE(result == DNS_R_NOMORE);

	column = 0;

	/* Owner name */
	{
		unsigned int name_start = target->used;
		RETERR(dns_name_totext(owner_name,
				       omit_final_dot,
				       target));
		column += target->used - name_start;
	}

	/* Class */
	{
		unsigned int class_start;
		INDENT_TO(class_column);
		class_start = target->used;
		result = dns_rdataclass_totext(rdataset->rdclass, target);
		if (result != DNS_R_SUCCESS)
			return (result);
		column += (target->used - class_start);
	}

	/* Type */
	{
		unsigned int type_start;
		INDENT_TO(type_column);
		type_start = target->used;
		result = dns_rdatatype_totext(rdataset->type, target);
		if (result != DNS_R_SUCCESS)
			return (result);
		column += (target->used - type_start);
	}

	isc_buffer_available(target, &r);
	if (r.length < 1)
		return (DNS_R_NOSPACE);
	r.base[0] = '\n';
	isc_buffer_add(target, 1);

	return (DNS_R_SUCCESS);
}

/*
 * Provide a backwards compatible interface for printing a
 * single rdataset or question section.  This is now used 
 * only by wire_test.c.
 */
isc_result_t
dns_rdataset_totext(dns_rdataset_t *rdataset,
		    dns_name_t *owner_name,
		    isc_boolean_t omit_final_dot,
		    isc_boolean_t no_rdata_or_ttl,
		    isc_buffer_t *target)
{
	dns_totext_ctx_t ctx;
	isc_result_t result;
	result = totext_ctx_init(&dns_masterfile_style_debug, &ctx);
	if (result != DNS_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "could not set master file style");
		return (DNS_R_UNEXPECTED);
	}

	/*
	 * The caller might want to give us an empty owner
	 * name (e.g. if they are outputting into a master
	 * file and this rdataset has the same name as the
	 * previous one.)
	 */
	if (dns_name_countlabels(owner_name) == 0)
		owner_name = NULL;
	
	if (no_rdata_or_ttl)
		return (question_totext(rdataset, owner_name, &ctx, 
					omit_final_dot, target));
	else
		return (rdataset_totext(rdataset, owner_name, &ctx, 
					omit_final_dot, target));
}

/*
 * Print an rdataset.  'buffer' is a scratch buffer, which must have been
 * dynamically allocated by the caller.  It must be large enough to 
 * hold the result from dns_ttl_totext().  If more than that is needed,
 * the buffer will be grown automatically.
 */

static isc_result_t
dump_rdataset(isc_mem_t *mctx, dns_name_t *name, dns_rdataset_t *rdataset,
	      dns_totext_ctx_t *ctx, 
	      isc_buffer_t *buffer, FILE *f)
{
	isc_region_t r;
	isc_result_t result;
	size_t nwritten;
	
	REQUIRE(buffer->length > 0);

	/* Output a $TTL directive if needed. */
	
	if ((ctx->style.flags & DNS_STYLEFLAG_TTL) != 0) {
		if (ctx->current_ttl_valid == ISC_FALSE ||
		    ctx->current_ttl != rdataset->ttl)
		{
			if ((ctx->style.flags & DNS_STYLEFLAG_COMMENT) != 0)
			{
				isc_buffer_clear(buffer);
				result = dns_ttl_totext(rdataset->ttl,
							ISC_TRUE, buffer);
				INSIST(result == DNS_R_SUCCESS);
				isc_buffer_used(buffer, &r);
				fprintf(f, "$TTL %u\t; %.*s\n", rdataset->ttl,
					(int) r.length, (char *) r.base);
			} else {
				fprintf(f, "$TTL %u\n", rdataset->ttl);
			}
			ctx->current_ttl = rdataset->ttl;
			ctx->current_ttl_valid = ISC_TRUE;
		}
	}
	
	isc_buffer_clear(buffer);

	/*
	 * Generate the text representation of the rdataset into
	 * the buffer.  If the buffer is too small, grow it.
	 */ 
	for (;;) {
		int newlength;
		void *newmem;
		result = rdataset_totext(rdataset, name, ctx,
					 ISC_FALSE, buffer);
		if (result != DNS_R_NOSPACE)
			break;

		isc_mem_put(mctx, buffer->base, buffer->length);
		newlength = buffer->length * 2;
		newmem = isc_mem_get(mctx, newlength);
		if (newmem == NULL)
			return (DNS_R_NOMEMORY);
		isc_buffer_init(buffer, newmem, newlength,
				ISC_BUFFERTYPE_TEXT);
	}
	if (result != DNS_R_SUCCESS)
		return (result);

	/* Write the buffer contents to the master file. */
	isc_buffer_used(buffer, &r);
	nwritten = fwrite(r.base, 1, (size_t) r.length, f);

	if (nwritten != (size_t) r.length) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "master file write failed: %s",
				 strerror(errno));
		return (DNS_R_UNEXPECTED);
	}
	
	return (DNS_R_SUCCESS);
}

/*
 * Dump all the rdatasets of a domain name to a master file.
 */
static isc_result_t
dump_rdatasets(isc_mem_t *mctx, dns_name_t *name, dns_rdatasetiter_t *rdsiter, 
	       dns_totext_ctx_t *ctx,
	       isc_buffer_t *buffer, FILE *f)
{
	isc_result_t result;
	dns_rdataset_t rdataset;
	
	dns_rdataset_init(&rdataset);
	result = dns_rdatasetiter_first(rdsiter);
	while (result == DNS_R_SUCCESS) {
		dns_rdatasetiter_current(rdsiter, &rdataset);
		if (rdataset.type != 0) {
			/*
			 * XXX  We only dump the rdataset if it isn't a
			 * negative caching entry.  Maybe our dumping routines
			 * will learn how to usefully dump such an entry later
			 * on.
			 */
			result = dump_rdataset(mctx, name, &rdataset, ctx,
					       buffer, f);
		} else
			result = DNS_R_SUCCESS;
		dns_rdataset_disassociate(&rdataset);
		if (result != DNS_R_SUCCESS)
			return (result);
		result = dns_rdatasetiter_next(rdsiter);
		if ((ctx->style.flags & DNS_STYLEFLAG_OMIT_OWNER) != 0)
			name = NULL;
	}
	if (result != DNS_R_NOMORE)
		return (result);
	return (DNS_R_SUCCESS);
}


/*
 * Initial size of text conversion buffer.  The buffer is used
 * for several purposes: converting origin names, rdatasets, 
 * $DATE timestamps, and comment strings for $TTL directives.
 *
 * When converting rdatasets, it is dynamically resized, but
 * when converting origins, timestamps, etc it is not.  Therefore, 
 * the  initial size must large enough to hold the longest possible 
 * text representation of any domain name (for $ORIGIN).
 */
const int initial_buffer_length = 1200;

/*
 * Dump an entire database into a master file.
 */
isc_result_t
dns_master_dumptostream(isc_mem_t *mctx, dns_db_t *db,
			dns_dbversion_t *version,
			const dns_master_style_t *style,
			FILE *f)
{
	dns_fixedname_t fixname;
	dns_name_t *name;
	dns_dbiterator_t *dbiter = NULL;
	isc_result_t result;
	isc_buffer_t buffer;
	char *bufmem;
	isc_stdtime_t now;
	isc_region_t r;
	dns_totext_ctx_t ctx;

	result = totext_ctx_init(style, &ctx);
	if (result != DNS_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "could not set master file style");
		return (DNS_R_UNEXPECTED);
	}

	dns_fixedname_init(&fixname);
	name = dns_fixedname_name(&fixname);

	isc_stdtime_get(&now);

	bufmem = isc_mem_get(mctx, initial_buffer_length);
	if (bufmem == NULL)
		return (DNS_R_NOMEMORY);
	
	isc_buffer_init(&buffer, bufmem, initial_buffer_length,
			ISC_BUFFERTYPE_TEXT);

	/*
	 * If the database has cache semantics, output an RFC2540
	 * $DATE directive so that the TTLs can be adjusted when
	 * it is reloaded.  For zones it is not really needed, and 
	 * it would make the file incompatible with pre-RFC2540
	 * software, so we omit it in the zone case.
	 */
	if (dns_db_iscache(db)) {
		result = dns_time32_totext(now, &buffer);
		RUNTIME_CHECK(result == DNS_R_SUCCESS);
		isc_buffer_used(&buffer, &r);
		fprintf(f, "$DATE %.*s\n", (int) r.length, (char *) r.base);
	}

	result = dns_db_createiterator(db,
		       ((ctx.style.flags & DNS_STYLEFLAG_REL_OWNER) != 0) ? 
		           ISC_TRUE : ISC_FALSE,
		       &dbiter);
	if (result != DNS_R_SUCCESS)
		goto create_iter_failure;

	result = dns_dbiterator_first(dbiter);

	while (result == DNS_R_SUCCESS) {
		dns_rdatasetiter_t *rdsiter = NULL;
		dns_dbnode_t *node = NULL;
		result = dns_dbiterator_current(dbiter, &node, name);
		if (result != DNS_R_SUCCESS && result != DNS_R_NEWORIGIN)
			break;
		if (result == DNS_R_NEWORIGIN) {
			dns_name_t *origin =
				dns_fixedname_name(&ctx.origin_fixname);
			result = dns_dbiterator_origin(dbiter, origin);
			RUNTIME_CHECK(result == DNS_R_SUCCESS);
			isc_buffer_clear(&buffer);
			result = dns_name_totext(origin, ISC_FALSE, &buffer);
			RUNTIME_CHECK(result == DNS_R_SUCCESS);
			isc_buffer_used(&buffer, &r);
			fprintf(f, "$ORIGIN %.*s\n", (int) r.length,
				(char *) r.base);
			if ((ctx.style.flags & DNS_STYLEFLAG_REL_DATA) != 0)
				ctx.origin = origin;
		}
		result = dns_db_allrdatasets(db, node, version, now, &rdsiter);
		if (result != DNS_R_SUCCESS) {
			dns_db_detachnode(db, &node);
			goto iter_failure;
		}
		result = dump_rdatasets(mctx, name, rdsiter, &ctx,
					&buffer, f);
		if (result != DNS_R_SUCCESS) {
			dns_db_detachnode(db, &node);
			goto iter_failure;
		}
		dns_rdatasetiter_destroy(&rdsiter);
		dns_db_detachnode(db, &node);
		result = dns_dbiterator_next(dbiter);
	}
	if (result != DNS_R_NOMORE)
		goto iter_failure;

	result = DNS_R_SUCCESS;
	
 iter_failure:
	dns_dbiterator_destroy(&dbiter);
	
 create_iter_failure:
	isc_mem_put(mctx, buffer.base, buffer.length);
	return (result);
}


isc_result_t
dns_master_dump(isc_mem_t *mctx, dns_db_t *db, dns_dbversion_t *version,
		const dns_master_style_t *style, const char *filename)
{
	FILE *f;
	isc_result_t result;
	
	f = fopen(filename, "w");
	if (f == NULL) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "could not open %s",
				 filename);
		return (DNS_R_UNEXPECTED);
	}

	result = dns_master_dumptostream(mctx, db, version, style, f);

	if (fclose(f) != 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "error closing %s",
				 filename);
		return (DNS_R_UNEXPECTED);
	}

	return (result);
}
