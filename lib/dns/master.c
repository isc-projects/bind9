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

/* $Id: master.c,v 1.52 2000/05/08 14:34:42 tale Exp $ */

#include <config.h>

#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/stdtime.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/master.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/time.h>
#include <dns/ttl.h>

/*
 * Grow the number of dns_rdatalist_t (RDLSZ) and dns_rdata_t (RDSZ) structures
 * by these sizes when we need to.
 *
 * RDLSZ reflects the number of different types with the same name expected.
 * RDSZ reflects the number of rdata expected at a give name that can fit into
 * 64k. 
 */

#define RDLSZ 32
#define RDSZ 512

#define NBUFS 4
#define MAXWIRESZ 255

/*
 * Target buffer size and minimum target size.
 * MINTSIZ must be big enough to hold the largest rdata record.
 * 
 * TSIZ >= MINTSIZ
 */
#define TSIZ (128*1024)
/*
 * max message size - header - root - type - class - ttl - rdlen
 */
#define MINTSIZ (65535 - 12 - 1 - 2 - 2 - 4 - 2)
/* 
 * Size for tokens in the presentation format, 
 * The largest tokens are the base64 blocks in KEY and CERT records,
 * Largest key allowed is about 1372 bytes but 
 * there is no fixed upper bound on CERT records.
 * 2K is too small for some X.509s, 8K is overkill.
 */
#define TOKENSIZ (8*1024)

typedef ISC_LIST(dns_rdatalist_t) rdatalist_head_t;

/*
 * Master file loading state that persists across $INCLUDEs.
 */
typedef struct {
	isc_boolean_t 	ttl_known; 
	isc_boolean_t 	default_ttl_known;
	isc_uint32_t 	ttl;
	isc_uint32_t 	default_ttl;
	isc_boolean_t 	warn_1035;
} loadctx_t;

static isc_result_t
loadfile(const char *master_file, dns_name_t *top, dns_name_t *origin,
	 dns_rdataclass_t zclass, isc_boolean_t age_ttl, int *soacount,
	 int *nscount, dns_rdatacallbacks_t *callbacks, loadctx_t *ctx,
	 isc_mem_t *mctx);

static isc_result_t
commit(dns_rdatacallbacks_t *, isc_lex_t *, rdatalist_head_t *, dns_name_t *,
       dns_name_t *);

static isc_boolean_t
is_glue(rdatalist_head_t *, dns_name_t *);

static dns_rdatalist_t *
grow_rdatalist(int, dns_rdatalist_t *, int, rdatalist_head_t *,
		rdatalist_head_t *, isc_mem_t *mctx);

static dns_rdata_t *
grow_rdata(int, dns_rdata_t *, int, rdatalist_head_t *, rdatalist_head_t *,
	   isc_mem_t *);

static isc_boolean_t
on_list(dns_rdatalist_t *this, dns_rdata_t *rdata);

#define GETTOKEN(lexer, options, token, eol) \
	do { \
		result = gettoken(lexer, options, token, eol, callbacks); \
		switch (result) { \
		case ISC_R_SUCCESS: \
			break; \
		case ISC_R_UNEXPECTED: \
			goto cleanup; \
		default: \
			goto error_cleanup; \
		} \
	} while (0) \

static inline isc_result_t
gettoken(isc_lex_t *lex, unsigned int options, isc_token_t *token,
	 isc_boolean_t eol, dns_rdatacallbacks_t *callbacks)
{
	isc_result_t result;

	options |= ISC_LEXOPT_EOL | ISC_LEXOPT_EOF | ISC_LEXOPT_DNSMULTILINE |
		ISC_LEXOPT_ESCAPE;
	result = isc_lex_gettoken(lex, options, token);
	if (result != ISC_R_SUCCESS) {
		switch (result) {
		case ISC_R_NOMEMORY:
			return (ISC_R_NOMEMORY);
		default:
			UNEXPECTED_ERROR(__FILE__, __LINE__,
				"isc_lex_gettoken() failed: %s",
				isc_result_totext(result));
			return (ISC_R_UNEXPECTED);
		}
		/*NOTREACHED*/
	}
	if (eol != ISC_TRUE)
		if (token->type == isc_tokentype_eol ||
		    token->type == isc_tokentype_eof) {
			(*callbacks->error)(callbacks,
			    "dns_master_load: %s:%d: unexpected end of %s",
					    isc_lex_getsourcename(lex),
					    isc_lex_getsourceline(lex),
					    (token->type ==
					     isc_tokentype_eol) ?
					    "line" : "file");
			return (ISC_R_UNEXPECTEDEND);
		}
	return (ISC_R_SUCCESS);
}

static void
loadctx_init(loadctx_t *ctx) {
	ctx->ttl_known = ISC_FALSE;
	ctx->ttl = 0;
	ctx->default_ttl_known = ISC_FALSE;
	ctx->default_ttl = 0;
	ctx->warn_1035 = ISC_TRUE;	/* XXX Argument? */
}
	     
static isc_result_t
load(isc_lex_t *lex, dns_name_t *top, dns_name_t *origin,
     dns_rdataclass_t zclass, isc_boolean_t age_ttl,
     int *soacount, int *nscount, dns_rdatacallbacks_t *callbacks,
     loadctx_t *ctx, isc_mem_t *mctx)
{
	dns_rdataclass_t rdclass;
	dns_rdatatype_t type, covers;
	isc_uint32_t ttl_offset = 0;
	dns_name_t current_name;
	dns_name_t glue_name;
	dns_name_t new_name;
	dns_name_t origin_name = *origin;
	isc_boolean_t current_known = ISC_FALSE;
	isc_boolean_t in_glue = ISC_FALSE;
	isc_boolean_t current_has_delegation = ISC_FALSE;
	isc_boolean_t done = ISC_FALSE;
	isc_boolean_t finish_origin = ISC_FALSE;
	isc_boolean_t finish_include = ISC_FALSE;
	isc_boolean_t read_till_eol = ISC_FALSE;
	char *include_file = NULL;
	isc_token_t token;
	isc_result_t result = ISC_R_UNEXPECTED; 
	rdatalist_head_t glue_list;
	rdatalist_head_t current_list;
	dns_rdatalist_t *this;
	dns_rdatalist_t *rdatalist = NULL;
	dns_rdatalist_t *new_rdatalist;
	int rdlcount = 0;
	int rdlcount_save = 0;
	int rdatalist_size = 0;
	isc_buffer_t buffer;
	isc_buffer_t target;
	isc_buffer_t target_save;
	dns_rdata_t *rdata = NULL;
	dns_rdata_t *new_rdata;
	int rdcount = 0;
	int rdcount_save = 0;
	int rdata_size = 0;
	unsigned char *target_mem = NULL;
	int target_size = TSIZ;
	unsigned char name_buf[NBUFS][MAXWIRESZ];
	isc_boolean_t name_in_use[NBUFS];
	int glue_in_use = -1;
	int current_in_use = -1;
	int origin_in_use = -1;
	int new_in_use;
	isc_buffer_t name;
	isc_lexspecials_t specials;

	REQUIRE(lex != NULL);
	REQUIRE(dns_name_isabsolute(top));
	REQUIRE(dns_name_isabsolute(origin));
	REQUIRE(callbacks != NULL);
	REQUIRE(callbacks->add != NULL);
	REQUIRE(callbacks->error != NULL);
	REQUIRE(callbacks->warn != NULL);
	REQUIRE(nscount != NULL);
	REQUIRE(soacount != NULL);
	REQUIRE(mctx != NULL);

	dns_name_init(&current_name, NULL);
	dns_name_init(&glue_name, NULL);

	ISC_LIST_INIT(glue_list);
	ISC_LIST_INIT(current_list);

	memset(specials, 0, sizeof specials);
	specials['('] = 1;
	specials[')'] = 1;
	specials['"'] = 1;
	isc_lex_setspecials(lex, specials);
	isc_lex_setcomments(lex, ISC_LEXCOMMENT_DNSMASTERFILE);

	/*
	 * Allocate target_size of buffer space.  This is greater than twice
	 * the maximum individual RR data size.
	 */
	target_mem = isc_mem_get(mctx, target_size);
	if (target_mem == NULL) {
		result = ISC_R_NOMEMORY;
		goto error_cleanup;
	}
	isc_buffer_init(&target, target_mem, target_size);
	target_save = target;

	memset(name_in_use, 0, NBUFS * sizeof(isc_boolean_t));

	do {
		GETTOKEN(lex, ISC_LEXOPT_INITIALWS, &token, ISC_TRUE);

		if (token.type == isc_tokentype_eof) {
			done = ISC_TRUE;
			continue;
		}

		if (token.type == isc_tokentype_eol) {
			read_till_eol = ISC_FALSE;
			continue;		/* blank line */
		}

		if (read_till_eol)
			continue;

		if (token.type == isc_tokentype_initialws) {
			if (!current_known) {
				(*callbacks->error)(callbacks,
					"%s: %s:%d: No current owner name",
						"dns_master_load",
						isc_lex_getsourcename(lex),
						isc_lex_getsourceline(lex));
				result = DNS_R_NOOWNER;
				goto cleanup;
			}
			/*
			 * Still working on the same name.
			 */
		} else if (token.type == isc_tokentype_string) {

			/*
			 * "$" Support.
			 *
			 * "$ORIGIN" and "$INCLUDE" can both take domain names.
			 * The processing of "$ORIGIN" and "$INCLUDE" extends
			 * across the normal domain name processing.
			 */

			if (strcasecmp(token.value.as_pointer,
				       "$ORIGIN") == 0) {
				GETTOKEN(lex, 0, &token, ISC_FALSE);
				read_till_eol = ISC_TRUE;
				finish_origin = ISC_TRUE;
			} else if (strcasecmp(token.value.as_pointer,
				              "$TTL") == 0) {
				GETTOKEN(lex, 0, &token, ISC_FALSE);
				result =
				   dns_ttl_fromtext(&token.value.as_textregion,
						    &ctx->ttl);
				if (result != ISC_R_SUCCESS)
					goto cleanup;
				if (ctx->ttl > 0x7fffffffUL) {
					(callbacks->warn)(callbacks,
		"dns_master_load: %s:%d: $TTL %lu > MAXTTL, setting $TTL to 0",
						isc_lex_getsourcename(lex),
						isc_lex_getsourceline(lex),
						ctx->ttl);
					ctx->ttl = 0;
				}
				ctx->default_ttl = ctx->ttl;
				ctx->default_ttl_known = ISC_TRUE;
				read_till_eol = ISC_TRUE;
				continue;
			} else if (strcasecmp(token.value.as_pointer,
					      "$INCLUDE") == 0) {
				if (ttl_offset != 0) {
					(callbacks->error)(callbacks,
					   "dns_master_load: %s:%d: $INCLUDE "
					   "may not be used with $DATE", 
					   isc_lex_getsourcename(lex),
					   isc_lex_getsourceline(lex));
					goto cleanup;
				}
				GETTOKEN(lex, 0, &token, ISC_FALSE);
				if (include_file != NULL)
					isc_mem_free(mctx, include_file);
				include_file = isc_mem_strdup(mctx,
						token.value.as_pointer);
				if (include_file == NULL) {
					result = ISC_R_NOMEMORY;
					goto error_cleanup;
				}
				GETTOKEN(lex, 0, &token, ISC_TRUE);
				if (token.type == isc_tokentype_eol ||
				    token.type == isc_tokentype_eof) {
					/*
					 * No origin field.
					 */
					result = loadfile(include_file,
							  top,
							  &origin_name,
							  zclass,
							  age_ttl,
							  soacount,
							  nscount,
							  callbacks,
							  ctx,
							  mctx);
					if (result != ISC_R_SUCCESS)
						goto cleanup;
					isc_lex_ungettoken(lex, &token);
					continue;
				}
				/*
				 * There is an origin field.  Fall through
				 * to domain name processing code and do
				 * the actual inclusion later.
				 */
				read_till_eol = ISC_TRUE;
				finish_include = ISC_TRUE;
			} else if (strcasecmp(token.value.as_pointer,
					      "$DATE") == 0) {
				isc_int64_t dump_time64;
				isc_stdtime_t dump_time, current_time;
				GETTOKEN(lex, 0, &token, ISC_FALSE);
				isc_stdtime_get(&current_time);
				result = dns_time64_fromtext(token.value.
					     as_pointer, &dump_time64);
				if (result != ISC_R_SUCCESS)
					goto error_cleanup;
				dump_time = (isc_stdtime_t)dump_time64;
				if (dump_time != dump_time64) {
					UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "dns_master_load: %s:%d: "
					 "$DATE outside epoch",
					 isc_lex_getsourcename(lex),
					 isc_lex_getsourceline(lex));
					goto cleanup;
				}
				if (dump_time > current_time) {
					UNEXPECTED_ERROR(__FILE__, __LINE__,
					"dns_master_load: %s:%d: "
					"$DATE in future, using current date",
					isc_lex_getsourcename(lex),
					isc_lex_getsourceline(lex));
					dump_time = current_time;
				}
				ttl_offset = current_time - dump_time;
				read_till_eol = ISC_TRUE;
				continue;
			} else if (strncasecmp(token.value.as_pointer, 
					       "$", 1) == 0) {
				(callbacks->error)(callbacks, 
						   "dns_master_load: %s:%d: " 
						   "unknown $ directive '%s'",
						   isc_lex_getsourcename(lex),
						   isc_lex_getsourceline(lex),
						   token.value.as_pointer);
				goto cleanup;
			}

			/*
			 * Normal processing resumes.
			 *
			 * Find a free name buffer.
			 */
			for (new_in_use = 0; new_in_use < NBUFS ; new_in_use++)
				if (!name_in_use[new_in_use])
					break;
			INSIST(new_in_use < NBUFS);
			isc_buffer_init(&name, &name_buf[new_in_use][0],
					MAXWIRESZ);
			dns_name_init(&new_name, NULL);
			isc_buffer_init(&buffer, token.value.as_region.base,
					token.value.as_region.length);
			isc_buffer_add(&buffer, token.value.as_region.length);
			isc_buffer_setactive(&buffer,
					     token.value.as_region.length);
			result = dns_name_fromtext(&new_name, &buffer,
					  &origin_name, ISC_FALSE, &name);
			if (result != ISC_R_SUCCESS)
				goto error_cleanup;

			/*
			 * Finish $ORIGIN / $INCLUDE processing if required.
			 */
			if (finish_origin) {
				if (origin_in_use != -1)
					name_in_use[origin_in_use] = ISC_FALSE;
				origin_in_use = new_in_use;
				name_in_use[origin_in_use] = ISC_TRUE;
				origin_name = new_name;
				finish_origin = ISC_FALSE;
				continue;
			}
			if (finish_include) {
				result = loadfile(include_file,
						  top,
						  &new_name,
						  zclass,
						  age_ttl,
						  soacount,
						  nscount,
						  callbacks,
						  ctx,
						  mctx);
				if (result != ISC_R_SUCCESS)
					goto cleanup;
				finish_include = ISC_FALSE;
				continue;
			}

			/*
			 * "$" Processing Finished
			 */

			/*
			 * If we are processing glue and the new name does
			 * not match the current glue name, commit the glue
			 * and pop stacks leaving us in 'normal' processing
			 * state.  Linked lists are undone by commit().
			 */
			if (in_glue && dns_name_compare(&glue_name,
							&new_name) != 0) {
				result = commit(callbacks, lex, &glue_list,
						&glue_name, top);
				if (result != ISC_R_SUCCESS)
					goto cleanup;
				if (glue_in_use != -1)
					name_in_use[glue_in_use] = ISC_FALSE;
				glue_in_use = -1;
				dns_name_invalidate(&glue_name);
				in_glue = ISC_FALSE;
				rdcount = rdcount_save;
				rdlcount = rdlcount_save;
				target = target_save;
			}

			/*
			 * If we are in 'normal' processing state and the new
			 * name does not match the current name, see if the
			 * new name is for glue and treat it as such,
			 * otherwise we have a new name so commit what we
			 * have.
			 */
			if (!in_glue && (!current_known ||
			    dns_name_compare(&current_name, &new_name) != 0)) {
				if (current_has_delegation &&
					is_glue(&current_list, &new_name)) {
					in_glue = ISC_TRUE;
					rdcount_save = rdcount;
					rdlcount_save = rdlcount;
					target_save = target;
					glue_name = new_name;
					glue_in_use = new_in_use;
					name_in_use[glue_in_use] = ISC_TRUE;
				} else {
					result = commit(callbacks, lex,
							&current_list,
							&current_name, top);
					if (result != ISC_R_SUCCESS)
						goto cleanup;
					rdcount = 0;
					rdlcount = 0;
					if (current_in_use != -1)
						name_in_use[current_in_use]
							= ISC_FALSE;
					current_in_use = new_in_use;
					name_in_use[current_in_use] = ISC_TRUE;
					current_name = new_name;
					current_known = ISC_TRUE;
					current_has_delegation = ISC_FALSE;
					isc_buffer_init(&target, target_mem,
							target_size);
				}
			}
		} else {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
	     "%s:%d: isc_lex_gettoken() returned unexpeced token type (%d)",
					 isc_lex_getsourcename(lex),
					 isc_lex_getsourceline(lex),
					 token.type);
			result = ISC_R_UNEXPECTED;
			goto cleanup;
		}

		/*
		 * Find TTL, class and type.  Both TTL and class are optional
		 * and may occur in any order if they exist. TTL and class
		 * come before type which must exist.
		 *
		 * [<TTL>] [<class>] <type> <RDATA>
		 * [<class>] [<TTL>] <type> <RDATA>
		 */

		type = 0;
		rdclass = 0;

		GETTOKEN(lex, 0, &token, ISC_FALSE);

		if (dns_rdataclass_fromtext(&rdclass,
					    &token.value.as_textregion)
				== ISC_R_SUCCESS)
			GETTOKEN(lex, 0, &token, ISC_FALSE);

		if (dns_ttl_fromtext(&token.value.as_textregion, &ctx->ttl)
				== ISC_R_SUCCESS) {
			if (ctx->ttl > 0x7fffffffUL) {
				(callbacks->warn)(callbacks,
	"dns_master_load: %s:%d: TTL %lu > MAXTTL, setting TTL to 0",
					isc_lex_getsourcename(lex),
					isc_lex_getsourceline(lex),
					ctx->ttl);
				ctx->ttl = 0;
			}
			ctx->ttl_known = ISC_TRUE;
			GETTOKEN(lex, 0, &token, ISC_FALSE);
		} else if (!ctx->ttl_known && !ctx->default_ttl_known) {
			/*
			 * BIND 4 / 8 'USE_SOA_MINIMUM' could be set here.
			 */
			(*callbacks->error)(callbacks,
					    "%s: %s:%d: no TTL specified",
					    "dns_master_load",
					    isc_lex_getsourcename(lex),
					    isc_lex_getsourceline(lex));
			result = DNS_R_NOTTL;
			goto cleanup;
		} else if (ctx->default_ttl_known) {
			ctx->ttl = ctx->default_ttl;
		} else if (ctx->warn_1035) {
			(*callbacks->warn)(callbacks,
				   "%s: %s:%d: using RFC 1035 TTL semantics",
					   "dns_master_load",
					   isc_lex_getsourcename(lex),
					   isc_lex_getsourceline(lex));
			ctx->warn_1035 = ISC_FALSE;
		} 

		if (token.type != isc_tokentype_string) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
			"isc_lex_gettoken() returned unexpected token type");
			result = ISC_R_UNEXPECTED;
			goto cleanup;
		}
			
		if (rdclass == 0 &&
		    dns_rdataclass_fromtext(&rdclass,
					    &token.value.as_textregion)
				== ISC_R_SUCCESS)
			GETTOKEN(lex, 0, &token, ISC_FALSE);

		if (token.type !=  isc_tokentype_string) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
			"isc_lex_gettoken() returned unexpected token type");
			result = ISC_R_UNEXPECTED;
			goto cleanup;
		}

		result = dns_rdatatype_fromtext(&type,
						&token.value.as_textregion);
		if (result != ISC_R_SUCCESS)
			goto cleanup;

		/*
		 * If the class specified does not match the zone's class
		 * print out a error message and exit.
		 */
		if (rdclass != 0 && rdclass != zclass) {
			char buf1[32];
			char buf2[32];
			unsigned int len1, len2;
			isc_buffer_t buffer;
			isc_region_t region;

			isc_buffer_init(&buffer, buf1, sizeof(buf1));
			result = dns_rdataclass_totext(rdclass, &buffer);
			if (result != ISC_R_SUCCESS) {
				UNEXPECTED_ERROR(__FILE__, __LINE__,
					"dns_rdataclass_totext() failed: %s",
						 dns_result_totext(result));
				result = ISC_R_UNEXPECTED;
				goto cleanup;
			}
			isc_buffer_usedregion(&buffer, &region);
			len1 = region.length;
			isc_buffer_init(&buffer, buf2, sizeof(buf2));
			result = dns_rdataclass_totext(zclass, &buffer);
			if (result != ISC_R_SUCCESS) {
				UNEXPECTED_ERROR(__FILE__, __LINE__,
					"dns_rdataclass_totext() failed: %s",
						 dns_result_totext(result));
				result = ISC_R_UNEXPECTED;
				goto cleanup;
			}
			isc_buffer_usedregion(&buffer, &region);
			len2 = region.length;
			(*callbacks->error)(callbacks,
			       "%s: %s:%d: class (%.*s) != zone class (%.*s)",
					    "dns_master_load",
					    isc_lex_getsourcename(lex),
					    isc_lex_getsourceline(lex),
					    len1, buf1, len2, buf2);
			result = DNS_R_BADCLASS;
			goto cleanup;
		}

		if (type == dns_rdatatype_ns && !in_glue)
			current_has_delegation = ISC_TRUE;

		if (age_ttl) {
			/*
			 * Adjust the TTL for $DATE.  If the RR has already
			 * expired, ignore it without even parsing the rdata
			 * part (good for performance, bad for catching 
			 * syntax errors).
			 */
			if (ctx->ttl < ttl_offset) {
				read_till_eol = ISC_TRUE;
				continue;
			}
			ctx->ttl -= ttl_offset;
		}

		/*
		 * Find a rdata structure.
		 */
		if (rdcount == rdata_size) {
			new_rdata = grow_rdata(rdata_size + RDSZ, rdata,
					       rdata_size, &current_list,
					       &glue_list, mctx);
			if (new_rdata == NULL) {
				result = ISC_R_NOMEMORY;
				goto error_cleanup;
			}
			rdata_size += RDSZ;
			rdata = new_rdata;
		}

		/*
		 * Read rdata contents.
		 */
		result = dns_rdata_fromtext(&rdata[rdcount], zclass, type,
				   lex, &origin_name, ISC_FALSE, &target,
				   callbacks);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		if (type == dns_rdatatype_sig)
			covers = dns_rdata_covers(&rdata[rdcount]);
		else
			covers = 0;


		/*
		 * Find type in rdatalist.
		 * If it does not exist create new one and prepend to list
		 * as this will mimimise list traversal.
		 */
		if (in_glue)
			this = ISC_LIST_HEAD(glue_list);
		else
			this = ISC_LIST_HEAD(current_list);

		while (this != NULL) {
			if (this->type == type && this->covers == covers)
				break;
			this = ISC_LIST_NEXT(this, link);
		}

		if (this == NULL) {
			if (rdlcount == rdatalist_size) {
				new_rdatalist =
					grow_rdatalist(rdatalist_size + RDLSZ,
						       rdatalist,
						       rdatalist_size,
						       &current_list,
						       &glue_list,
						       mctx);
				if (new_rdatalist == NULL) {
					result = ISC_R_NOMEMORY;
					goto error_cleanup;
				}
				rdatalist = new_rdatalist;
				rdatalist_size += RDLSZ;
			}
			this = &rdatalist[rdlcount++];
			this->type = type;
			this->covers = covers;
			this->rdclass = zclass;
			this->ttl = ctx->ttl;
			ISC_LIST_INIT(this->rdata);
			ISC_LINK_INIT(this, link);
			if (in_glue)
				ISC_LIST_PREPEND(glue_list, this, link);
			else
				ISC_LIST_PREPEND(current_list, this, link);
		} else if (this->ttl != ctx->ttl) {
			(*callbacks->warn)(callbacks,
				   "%s: %s:%d: TTL set to prior TTL (%lu)",
					   "dns_master_load",
					   isc_lex_getsourcename(lex),
					   isc_lex_getsourceline(lex),
					   this->ttl);
			ctx->ttl = this->ttl;
		}

		/*
		 * If the new rdata is not on the list add it.
		 *
		 * If the new rdata is on the list do not worry about
		 * recovering the space it is using in target as it will be
		 * recovered when we next call commit.  The worst that can
		 * happen is that we make a few extra calls to commit.
		 */

		if (!on_list(this, &rdata[rdcount])) {
			ISC_LIST_APPEND(this->rdata, &rdata[rdcount], link);
			rdcount++;
		}

		/*
		 * We must have at least 64k as rdlen is 16 bits.
		 * If we don't commit everything we have so far.
		 */
		if ((target.length - target.used) < MINTSIZ) {
			result = commit(callbacks, lex, &current_list,
					&current_name, top);
			if (result != ISC_R_SUCCESS)
				goto cleanup;
			result = commit(callbacks, lex, &glue_list, &glue_name,
					top);
			if (result != ISC_R_SUCCESS)
				goto cleanup;
			rdcount = 0;
			rdlcount = 0;
			if (glue_in_use != -1)
				name_in_use[glue_in_use] = ISC_FALSE;
			glue_in_use = -1;
			in_glue = ISC_FALSE;
			current_has_delegation = ISC_FALSE;
			isc_buffer_init(&target, target_mem, target_size);
		}
	} while (!done);
	/*
	 * Commit what has not yet been committed.
	 */
	result = commit(callbacks, lex, &current_list, &current_name, top);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = commit(callbacks, lex, &glue_list, &glue_name, top);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	else
		result = ISC_R_SUCCESS;
	goto cleanup;

 error_cleanup:
	(*callbacks->error)(callbacks, "dns_master_load: %s",
			    dns_result_totext(result));

 cleanup:
	if (lex != NULL) {
		isc_lex_close(lex);
		isc_lex_destroy(&lex);
	}
	while ((this = ISC_LIST_HEAD(current_list)) != NULL) 
		ISC_LIST_UNLINK(current_list, this, link);
	while ((this = ISC_LIST_HEAD(glue_list)) != NULL) 
		ISC_LIST_UNLINK(glue_list, this, link);
	if (rdatalist != NULL)
		isc_mem_put(mctx, rdatalist,
			    rdatalist_size * sizeof *rdatalist);
	if (rdata != NULL)
		isc_mem_put(mctx, rdata, rdata_size * sizeof *rdata);
	if (target_mem != NULL)
		isc_mem_put(mctx, target_mem, target_size);
	if (include_file != NULL)
		isc_mem_free(mctx, include_file);
	return (result);
}

static isc_result_t
loadfile(const char *master_file, dns_name_t *top,
	 dns_name_t *origin,
	 dns_rdataclass_t zclass, isc_boolean_t age_ttl,
	 int *soacount, int *nscount,
	 dns_rdatacallbacks_t *callbacks,
	 loadctx_t *ctx,
	 isc_mem_t *mctx)
{
	isc_result_t result;
	isc_lex_t *lex = NULL;

	REQUIRE(master_file != NULL);

	result = isc_lex_create(mctx, TOKENSIZ, &lex);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = isc_lex_openfile(lex, master_file);
	if (result != ISC_R_SUCCESS) {
		isc_lex_destroy(&lex);
		return (result);
	}

	return (load(lex, top, origin, zclass, age_ttl, soacount, nscount,
		     callbacks, ctx, mctx));
}

isc_result_t
dns_master_loadfile(const char *master_file, dns_name_t *top,
		    dns_name_t *origin,
		    dns_rdataclass_t zclass, isc_boolean_t age_ttl,
		    int *soacount, int *nscount,
		    dns_rdatacallbacks_t *callbacks,
		    isc_mem_t *mctx)
{
	loadctx_t ctx;

	loadctx_init(&ctx);
	return (loadfile(master_file, top, origin, zclass, age_ttl,
			 soacount, nscount, callbacks, &ctx, mctx));
}


isc_result_t
dns_master_loadstream(FILE *stream, dns_name_t *top, dns_name_t *origin,
		      dns_rdataclass_t zclass, isc_boolean_t age_ttl,
		      int *soacount, int *nscount,
		      dns_rdatacallbacks_t *callbacks, isc_mem_t *mctx)
{
	isc_result_t result;
	isc_lex_t *lex = NULL;
	loadctx_t ctx;

	REQUIRE(stream != NULL);

	loadctx_init(&ctx);

	result = isc_lex_create(mctx, TOKENSIZ, &lex);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = isc_lex_openstream(lex, stream);
	if (result != ISC_R_SUCCESS) {
		isc_lex_destroy(&lex);
		return (result);
	}

	return (load(lex, top, origin, zclass, age_ttl, soacount, nscount,
		     callbacks, &ctx, mctx));
}

isc_result_t
dns_master_loadbuffer(isc_buffer_t *buffer, dns_name_t *top,
		      dns_name_t *origin, dns_rdataclass_t zclass,
		      isc_boolean_t age_ttl,
		      int *soacount, int *nscount,
		      dns_rdatacallbacks_t *callbacks, isc_mem_t *mctx)
{
	isc_result_t result;
	isc_lex_t *lex = NULL;
	loadctx_t ctx;

	REQUIRE(buffer != NULL);

	loadctx_init(&ctx);
	
	result = isc_lex_create(mctx, TOKENSIZ, &lex);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = isc_lex_openbuffer(lex, buffer);
	if (result != ISC_R_SUCCESS) {
		isc_lex_destroy(&lex);
		return (result);
	}

	return (load(lex, top, origin, zclass, age_ttl, soacount, nscount,
		     callbacks, &ctx, mctx));
}

/*
 * Grow the slab of dns_rdatalist_t structures.
 * Re-link glue and current list.
 */
static dns_rdatalist_t *
grow_rdatalist(int new_len, dns_rdatalist_t *old, int old_len,
	       rdatalist_head_t *current, rdatalist_head_t *glue,
	       isc_mem_t *mctx)
{
	dns_rdatalist_t *new;
	int rdlcount = 0;
	ISC_LIST(dns_rdatalist_t) save;
	dns_rdatalist_t *this;

	new = isc_mem_get(mctx, new_len * sizeof *new);
	if (new == NULL)
		return (NULL);

	ISC_LIST_INIT(save);
	this = ISC_LIST_HEAD(*current);
	while ((this = ISC_LIST_HEAD(*current)) != NULL) {
		ISC_LIST_UNLINK(*current, this, link);
		ISC_LIST_APPEND(save, this, link);
	}
	while ((this = ISC_LIST_HEAD(save)) != NULL) {
		ISC_LIST_UNLINK(save, this, link);
		new[rdlcount] = *this;
		ISC_LIST_APPEND(*current, &new[rdlcount], link);
		rdlcount++;
	}

	ISC_LIST_INIT(save);
	this = ISC_LIST_HEAD(*glue);
	while ((this = ISC_LIST_HEAD(*glue)) != NULL) {
		ISC_LIST_UNLINK(*glue, this, link);
		ISC_LIST_APPEND(save, this, link);
	}
	while ((this = ISC_LIST_HEAD(save)) != NULL) {
		ISC_LIST_UNLINK(save, this, link);
		new[rdlcount] = *this;
		ISC_LIST_APPEND(*glue, &new[rdlcount], link);
		rdlcount++;
	}

	INSIST(rdlcount == old_len);
	if (old != NULL)
		isc_mem_put(mctx, old, old_len * sizeof *old);
	return (new);
}

/*
 * Grow the slab of rdata structs.
 * Re-link the current and glue chains.
 */
static dns_rdata_t *
grow_rdata(int new_len, dns_rdata_t *old, int old_len,
	   rdatalist_head_t *current, rdatalist_head_t *glue,
	   isc_mem_t *mctx)
{
	dns_rdata_t *new;
	int rdcount = 0;
	ISC_LIST(dns_rdata_t) save;
	dns_rdatalist_t *this;
	dns_rdata_t *rdata;

	new = isc_mem_get(mctx, new_len * sizeof *new);
	if (new == NULL)
		return (NULL);
	memset(new, 0, new_len * sizeof *new);

	/*
	 * Copy current relinking.
	 */
	this = ISC_LIST_HEAD(*current);
	while (this != NULL) {
		ISC_LIST_INIT(save);
		while ((rdata = ISC_LIST_HEAD(this->rdata)) != NULL) {
			ISC_LIST_UNLINK(this->rdata, rdata, link);
			ISC_LIST_APPEND(save, rdata, link);
		}
		while ((rdata = ISC_LIST_HEAD(save)) != NULL) {
			ISC_LIST_UNLINK(save, rdata, link);
			new[rdcount] = *rdata;
			ISC_LIST_APPEND(this->rdata, &new[rdcount], link);
			rdcount++;
		}
		this = ISC_LIST_NEXT(this, link);
	}
	
	/*
	 * Copy glue relinking.
	 */
	this = ISC_LIST_HEAD(*glue);
	while (this != NULL) {
		ISC_LIST_INIT(save);
		while ((rdata = ISC_LIST_HEAD(this->rdata)) != NULL) {
			ISC_LIST_UNLINK(this->rdata, rdata, link);
			ISC_LIST_APPEND(save, rdata, link);
		}
		while ((rdata = ISC_LIST_HEAD(save)) != NULL) {
			ISC_LIST_UNLINK(save, rdata, link);
			new[rdcount] = *rdata;
			ISC_LIST_APPEND(this->rdata, &new[rdcount], link);
			rdcount++;
		}
		this = ISC_LIST_NEXT(this, link);
	}
	INSIST(rdcount == old_len);
	if (old != NULL)
		isc_mem_put(mctx, old, old_len * sizeof *old);
	return (new);
}

/*
 * Convert each element from a rdatalist_t to rdataset then call commit.
 * Unlink each element as we go.
 */

static isc_result_t
commit(dns_rdatacallbacks_t *callbacks, isc_lex_t *lex,
       rdatalist_head_t *head, dns_name_t *owner, dns_name_t *top)
{
	dns_rdatalist_t *this;
	dns_rdataset_t dataset;
	isc_result_t result;
	isc_boolean_t ignore = ISC_FALSE;

	this = ISC_LIST_HEAD(*head);
	if (this == NULL)
		return (ISC_R_SUCCESS);
	if (!dns_name_issubdomain(owner, top)) {
		/*
		 * Ignore out-of-zone data.
		 */
		(callbacks->warn)(callbacks,
		"dns_master_load: %s:%d: ignoring out-of-zone data",
				  isc_lex_getsourcename(lex),
				  isc_lex_getsourceline(lex));
		ignore = ISC_TRUE;
	}
	do {
		if (!ignore) {
			dns_rdataset_init(&dataset);
			dns_rdatalist_tordataset(this, &dataset);
			dataset.trust = dns_trust_ultimate;
			result = ((*callbacks->add)(callbacks->add_private,
						    owner,
						    &dataset));
			if (result != ISC_R_SUCCESS)
				return (result);
		}
		ISC_LIST_UNLINK(*head, this, link);
		this = ISC_LIST_HEAD(*head);
	} while (this != NULL);
	return (ISC_R_SUCCESS);
}

/*
 * Returns ISC_TRUE if one of the NS rdata's contains 'owner'.
 */

static isc_boolean_t
is_glue(rdatalist_head_t *head, dns_name_t *owner) {
	dns_rdatalist_t *this;
	dns_rdata_t *rdata;
	isc_region_t region;
	dns_name_t name;

	/*
	 * Find NS rrset.
	 */
	this = ISC_LIST_HEAD(*head);
	while (this != NULL) {
		if (this->type == dns_rdatatype_ns)
			break;
		this = ISC_LIST_NEXT(this, link);
	}
	if (this == NULL)
		return (ISC_FALSE);

	rdata = ISC_LIST_HEAD(this->rdata);
	while (rdata != NULL) {
		dns_name_init(&name, NULL);
		dns_rdata_toregion(rdata, &region);
		dns_name_fromregion(&name, &region);
		if (dns_name_compare(&name, owner) == 0)
			return (ISC_TRUE);
		rdata = ISC_LIST_NEXT(rdata, link);
	}
	return (ISC_FALSE);
}

/*
 * Returns ISC_TRUE if the 'rdata' is already on 'rdatalist'.
 */

static isc_boolean_t
on_list(dns_rdatalist_t *rdatalist, dns_rdata_t *rdata) {
	dns_rdata_t *rdata2;

	rdata2 = ISC_LIST_HEAD(rdatalist->rdata);
	while (rdata2 != NULL) {
		if (dns_rdata_compare(rdata, rdata2) == 0)
			return (ISC_TRUE);
		rdata2 = ISC_LIST_NEXT(rdata2, link);
	}
	return (ISC_FALSE);
}
