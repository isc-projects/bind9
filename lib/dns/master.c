/*
 * Copyright (C) 1999 Internet Software Consortium.
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

 /* $Id: master.c,v 1.6 1999/01/28 22:32:44 marka Exp $ */

#include <config.h>

#include <stdio.h>
#include <string.h>

#include <isc/lex.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/assertions.h>

#include <dns/master.h>
#include <dns/types.h>
#include <dns/result.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/rdata.h>

typedef ISC_LIST(dns_rdatalist_t) rdatalist_head_t;

static dns_result_t	commit(rdatalist_head_t *, dns_name_t *,
			       dns_result_t (*)(dns_name_t *,
						dns_rdataset_t *,
						void *),
				void *);
static isc_boolean_t	is_glue(rdatalist_head_t *, dns_name_t *);
static dns_rdatalist_t	*grow_rdatalist(int, dns_rdatalist_t *, int,
				        rdatalist_head_t *,
					rdatalist_head_t *,
					isc_mem_t *mctx);
static dns_rdata_t	*grow_rdata(int, dns_rdata_t *, int,
				    rdatalist_head_t *, rdatalist_head_t *,
				    isc_mem_t *);

#define GETTOKEN(lexer, options, token, eol) \
	do { \
		unsigned int __o; \
		isc_token_t *__t = (token); \
		__o = (options) | ISC_LEXOPT_EOL | ISC_LEXOPT_EOF | \
			ISC_LEXOPT_DNSMULTILINE; \
		if (isc_lex_gettoken(lexer, __o, __t) \
				!= ISC_R_SUCCESS) { \
			result = DNS_R_UNEXPECTED; \
			goto cleanup; \
		} \
		if (eol != ISC_TRUE) \
			if (__t->type == isc_tokentype_eol || \
			    __t->type == isc_tokentype_eof) { \
				result = DNS_R_UNEXPECTEDEND; \
				goto cleanup; \
			} \
	} while (0)



dns_result_t
dns_load_master(char *master_file, dns_name_t *top, dns_name_t *origin,
	    dns_rdataclass_t zclass, int *soacount, int *nscount,
	    dns_result_t (*callback)(dns_name_t *, dns_rdataset_t *,
				     void *private),
	    void *private, isc_mem_t *mctx)
{
	dns_rdataclass_t class;
	dns_rdatatype_t type;
	unsigned long ttl = 0;
	unsigned long default_ttl = 0;
	dns_name_t current_name;
	dns_name_t glue_name;
	dns_name_t new_name;
	dns_name_t origin_name = *origin;
	isc_boolean_t ttl_known = ISC_FALSE;
	isc_boolean_t default_ttl_known = ISC_FALSE;
	isc_boolean_t current_known = ISC_FALSE;
	isc_boolean_t in_glue = ISC_FALSE;
	isc_boolean_t current_has_delegation = ISC_FALSE;
	isc_boolean_t done = ISC_FALSE;
	isc_boolean_t finish_origin = ISC_FALSE;
	isc_boolean_t finish_include = ISC_FALSE;
	isc_boolean_t read_till_eol = ISC_FALSE;
	char *include_file = NULL;
	isc_token_t token;
	isc_lex_t *lex = NULL;
	dns_result_t result = DNS_R_UNEXPECTED; 
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
	int target_size = 128*1024;
	unsigned char name_buf[5][255];
	isc_boolean_t name_in_use[5];
	int glue_in_use = -1;
	int current_in_use = -1;
	int origin_in_use = -1;
	int new_in_use;
	isc_buffer_t name;
	isc_lexspecials_t specials;

	dns_name_init(&current_name, NULL);
	dns_name_init(&glue_name, NULL);

	ISC_LIST_INIT(glue_list);
	ISC_LIST_INIT(current_list);

	if (isc_lex_create(mctx, 256, &lex) != ISC_R_SUCCESS)
		goto cleanup;

	memset(specials, 0, sizeof specials);
	specials['('] = 1;
	specials[')'] = 1;
	specials['"'] = 1;
	isc_lex_setspecials(lex, specials);
	isc_lex_setcomments(lex, ISC_LEXCOMMENT_DNSMASTERFILE);

	if (isc_lex_openfile(lex, master_file) != ISC_R_SUCCESS)
		goto cleanup;


	target_mem = isc_mem_get(mctx, target_size);
	if (target_mem == NULL) {
		result = DNS_R_NOSPACE;
		goto cleanup;
	}
	isc_buffer_init(&target, target_mem, target_size,
			ISC_BUFFERTYPE_BINARY);
	target_save = target;
	memset(name_in_use, 0, 5 * sizeof(isc_boolean_t));
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
				result = DNS_R_UNKNOWN;
				goto cleanup;
			}
			/* still working on the same name */
		} else if (token.type == isc_tokentype_string) {

			/* "$" Support */
			if (strcasecmp(token.value.as_pointer,
				       "$ORIGIN") == 0) {
				GETTOKEN(lex, 0, &token, ISC_FALSE);
				read_till_eol = ISC_TRUE;
				finish_origin = ISC_TRUE;
			} else if (strcasecmp(token.value.as_pointer,
				              "$TTL") == 0) {
				GETTOKEN(lex, ISC_LEXOPT_NUMBER, &token,
					 ISC_FALSE);
				ttl = token.value.as_ulong;
				if (ttl > 0x7fffffff) {
					result = DNS_R_RANGE;
					goto cleanup;
				}
				default_ttl = ttl;
				ttl_known = ISC_TRUE;
				default_ttl_known = ISC_TRUE;
				read_till_eol = ISC_TRUE;
				continue;
			} else if (strcasecmp(token.value.as_pointer,
					      "$INCLUDE") == 0) {
				GETTOKEN(lex, 0, &token, ISC_FALSE);
				if (include_file != NULL)
					isc_mem_free(mctx, include_file);
				include_file = isc_mem_strdup(mctx,
						token.value.as_pointer);
				GETTOKEN(lex, 0, &token, ISC_TRUE);
				if (token.type == isc_tokentype_eol ||
				    token.type == isc_tokentype_eof) {
					result = dns_load_master(include_file,
								 top,
								 &origin_name,
								 zclass,
								 soacount,
								 nscount,
								 callback,
								 private,
								 mctx);
					if (result != DNS_R_SUCCESS)
						goto cleanup;
					isc_lex_ungettoken(lex, &token);
					continue;
				}
				read_till_eol = ISC_TRUE;
				finish_include = ISC_TRUE;
			}

			for (new_in_use = 0; new_in_use < 5 ; new_in_use++)
				if (!name_in_use[new_in_use])
					break;
			INSIST(new_in_use < 5);
			isc_buffer_init(&name, &name_buf[new_in_use][0], 255,
					ISC_BUFFERTYPE_BINARY);
			dns_name_init(&new_name, NULL);
			isc_buffer_init(&buffer, token.value.as_region.base,
					token.value.as_region.length,
					ISC_BUFFERTYPE_TEXT);
			isc_buffer_add(&buffer, token.value.as_region.length);
			isc_buffer_setactive(&buffer,
					     token.value.as_region.length);
			result = dns_name_fromtext(&new_name, &buffer,
					  &origin_name, ISC_FALSE, &name);

			if (result != DNS_R_SUCCESS)
				goto cleanup;
			if (finish_origin) {
				if (origin_in_use != -1)
					name_in_use[origin_in_use] = ISC_FALSE;
				origin_in_use = new_in_use;
				name_in_use[origin_in_use] = ISC_TRUE;
				origin_name = new_name;
				finish_origin =ISC_FALSE;
				continue;
			}
			if (finish_include) {
				result = dns_load_master(include_file,
							 top,
							 &new_name,
							 zclass,
							 soacount,
							 nscount,
							 callback,
							 private,
							 mctx);
				if (result != DNS_R_SUCCESS)
					goto cleanup;
				finish_include = ISC_FALSE;
				continue;
			}
			/*
			 * commit glue and pop stacks
			 */
			if (in_glue && dns_name_compare(&glue_name,
							&new_name) != 0) {
				result = commit(&glue_list,
						&glue_name, callback, private);
				if (result != DNS_R_SUCCESS)
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

			if (!current_known ||
			    dns_name_compare(&current_name, &new_name) != 0) {
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
					result = commit(&current_list,
							&current_name,
							callback, private);
					if (result != DNS_R_SUCCESS)
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
							target_size,
							ISC_BUFFERTYPE_BINARY);
				}
			}
		} else {
			result = DNS_R_UNEXPECTED;
			goto cleanup;
		}

		type = 0;
		class = 0;

		GETTOKEN(lex, ISC_LEXOPT_NUMBER, &token, ISC_FALSE);

		if (token.type == isc_tokentype_number) {
			ttl = token.value.as_ulong;
			if (ttl > 0x7fffffff) {
				result = DNS_R_RANGE;
				goto cleanup;
			}
			ttl_known = ISC_TRUE;
			GETTOKEN(lex, 0, &token, ISC_FALSE);
		} else if (!ttl_known && !default_ttl_known) {
			result = DNS_R_UNEXPECTED;
			goto cleanup;
		} else if (default_ttl_known)
			ttl = default_ttl;

		if (token.type != isc_tokentype_string) {
			result = DNS_R_UNEXPECTED;
			goto cleanup;
		}
			
		if (dns_rdataclass_fromtext(&class, &token.value.as_textregion)
				== DNS_R_SUCCESS)
			GETTOKEN(lex, 0, &token, ISC_FALSE);

		if (token.type !=  isc_tokentype_string) {
			result = DNS_R_UNEXPECTED;
			goto cleanup;
		}
			
		result = dns_rdatatype_fromtext(&type,
						&token.value.as_textregion);
		if (result != DNS_R_SUCCESS)
			goto cleanup;

		if (class != 0 && class != zclass) {
			result = DNS_R_UNEXPECTED;
			goto cleanup;
		}

		if (!in_glue && type == ns_t_soa &&
			dns_name_compare(top, &current_name) == 0) {
			(*soacount)++;
		}

		if (!in_glue && type == ns_t_ns &&
			dns_name_compare(top, &current_name) == 0) {
			(*nscount)++;
		}

		if (type == ns_t_ns && !in_glue)
			current_has_delegation = ISC_TRUE;

		if (in_glue)
			this = ISC_LIST_HEAD(glue_list);
		else
			this = ISC_LIST_HEAD(current_list);

		while (this != NULL) {
			if (this->type == type)
				break;
			this = ISC_LIST_NEXT(this, link);
		}
		if (this == NULL) {
			if (rdlcount == rdatalist_size) {
				new_rdatalist =
					grow_rdatalist(rdatalist_size + 32,
						       rdatalist,
						       rdatalist_size,
						       &current_list,
						       &glue_list,
						       mctx);
				if (new_rdatalist == NULL) {
					result = DNS_R_NOSPACE;
					goto cleanup;
				}
				rdatalist = new_rdatalist;
				rdatalist_size += 32;
			}
			this = &rdatalist[rdlcount++];
			this->type = type;
			this->class = zclass;
			this->ttl = ttl;
			ISC_LIST_INIT(this->rdata);
			ISC_LINK_INIT(this, link);
			if (in_glue)
				ISC_LIST_PREPEND(glue_list, this, link);
			else
				ISC_LIST_PREPEND(current_list, this, link);
		}
		if (rdcount == rdata_size) {
			new_rdata = grow_rdata(rdata_size + 512, rdata,
					       rdata_size, &current_list,
					       &glue_list, mctx);
			if (new_rdata == NULL) {
				result = DNS_R_NOSPACE;
				goto cleanup;
			}
			rdata_size += 512;
			rdata = new_rdata;
		}
		result = dns_rdata_fromtext(&rdata[rdcount], class, type,
				   lex, &origin_name, ISC_FALSE, &target);
		if (result != DNS_R_SUCCESS)
			goto cleanup;
		ISC_LIST_PREPEND(this->rdata, &rdata[rdcount], link);
		rdcount++;
		/* We must have at least 64k as rdlen is 16 bits. */
		if (target.used > (64*1024)) {
			result = commit(&current_list, &current_name,
					callback, private);
			if (result != DNS_R_SUCCESS)
				goto cleanup;
			result = commit(&glue_list, &glue_name,
					callback, private);
			if (result != DNS_R_SUCCESS)
				goto cleanup;
			rdcount = 0;
			rdlcount = 0;
			if (glue_in_use != -1)
				name_in_use[glue_in_use] = ISC_FALSE;
			glue_in_use = -1;
			in_glue = ISC_FALSE;
			current_has_delegation = ISC_FALSE;
			isc_buffer_init(&target, target_mem, target_size,
					ISC_BUFFERTYPE_BINARY);
		}
	} while (!done);
	result = commit(&current_list, &current_name, callback, private);
	if (result != DNS_R_SUCCESS)
		goto cleanup;
	result = commit(&glue_list, &glue_name, callback, private);
	if (result != DNS_R_SUCCESS)
		goto cleanup;
	result = DNS_R_SUCCESS;

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
	/* copy current relinking */
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
	/* copy glue relinking */
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

static dns_result_t
commit(rdatalist_head_t *head, dns_name_t *owner,
       dns_result_t (*callback)(dns_name_t *, dns_rdataset_t *, void *),
       void *private)
{
	dns_rdatalist_t *this;
	dns_rdataset_t dataset;
	dns_result_t result;

	while ((this = ISC_LIST_HEAD(*head)) != NULL) {
		
		dns_rdataset_init(&dataset);
		dns_rdatalist_tordataset(this, &dataset);
		result = ((*callback)(owner, &dataset, private));
		if (result != DNS_R_SUCCESS)
			return (result);
		ISC_LIST_UNLINK(*head, this, link);
	}
	return (DNS_R_SUCCESS);
}

static isc_boolean_t
is_glue(rdatalist_head_t *head, dns_name_t *owner) {
	dns_rdatalist_t *this;
	dns_rdata_t *rdata;
	isc_region_t region;
	dns_name_t name;

	/* find NS rrset */
	this = ISC_LIST_HEAD(*head);
	while (this != NULL) {
		if (this->type == ns_t_ns)
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
