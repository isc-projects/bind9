/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#include <string.h>

#include <isc/assertions.h>
#include <isc/magic.h>

#include <dns/result.h>
#include <dns/confkeys.h>
#include <dns/confcommon.h>

static isc_result_t keyid_delete(isc_log_t *lctx, dns_c_kid_t **ki);


isc_result_t
dns_c_kdeflist_new(isc_log_t *lctx,
		   isc_mem_t *mem, dns_c_kdeflist_t **list)
{
	dns_c_kdeflist_t *newlist;

	(void)lctx;

	REQUIRE(mem != NULL);
	REQUIRE(list != NULL);

	newlist = isc_mem_get(mem, sizeof *newlist);
	if (newlist == NULL) {
		return (ISC_R_NOMEMORY);
	}

	newlist->mem = mem;
	newlist->magic = DNS_C_KDEFLIST_MAGIC;
	
	ISC_LIST_INIT(newlist->keydefs);

	*list = newlist;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_kdeflist_delete(isc_log_t *lctx,
		      dns_c_kdeflist_t **list)
{
	dns_c_kdeflist_t *l;
	dns_c_kdef_t *kd;
	dns_c_kdef_t *tmpkd;
	isc_result_t res;
	
	REQUIRE(list != NULL);
	REQUIRE(DNS_C_KDEFLIST_VALID(*list));

	l = *list;

	kd = ISC_LIST_HEAD(l->keydefs);
	while (kd != NULL) {
		tmpkd = ISC_LIST_NEXT(kd, next);
		ISC_LIST_UNLINK(l->keydefs, kd, next);
		res = dns_c_kdef_delete(lctx, &kd);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
		kd = tmpkd;
	}

	l->magic = 0;
	isc_mem_put(l->mem, l, sizeof *l);

	*list = NULL;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_kdeflist_copy(isc_log_t *lctx,
		    isc_mem_t *mem, dns_c_kdeflist_t **dest,
		    dns_c_kdeflist_t *src)
{
	dns_c_kdeflist_t *newlist;
	dns_c_kdef_t *key;
	isc_result_t res;

	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_KDEFLIST_VALID(src));
	
	res = dns_c_kdeflist_new(lctx, mem, &newlist);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	key = ISC_LIST_HEAD(src->keydefs);
	while (key != NULL) {
		res = dns_c_kdeflist_append(lctx, newlist, key, ISC_TRUE);
		if (res != ISC_R_SUCCESS) {
			dns_c_kdeflist_delete(lctx, &newlist);
			return (res);
		}
		
		key = ISC_LIST_NEXT(key, next);
	}

	*dest = newlist;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_kdeflist_append(isc_log_t *lctx, dns_c_kdeflist_t *list,
		      dns_c_kdef_t *key, isc_boolean_t copy)
{
	dns_c_kdef_t *newe;
	isc_result_t res;
	
	REQUIRE(DNS_C_KDEFLIST_VALID(list));
	REQUIRE(DNS_C_KDEF_VALID(key));

	if (copy) {
		res = dns_c_kdef_copy(lctx, list->mem, &newe, key);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	} else {
		newe = key;
	}

	ISC_LIST_APPEND(list->keydefs, newe, next);

	return (ISC_R_SUCCESS);
}



isc_result_t
dns_c_kdeflist_undef(isc_log_t *lctx,
		     dns_c_kdeflist_t *list, const char *keyid)
{
	dns_c_kdef_t *kd;
	isc_result_t r;

	REQUIRE(DNS_C_KDEFLIST_VALID(list));
	REQUIRE(keyid != NULL);
	REQUIRE(strlen(keyid) > 0);

	kd = ISC_LIST_HEAD(list->keydefs);
	while (kd != NULL) {
		if (strcmp(kd->keyid, keyid) == 0) {
			break;
		}
		kd = ISC_LIST_NEXT(kd, next);
	}

	if (kd != NULL) {
		ISC_LIST_UNLINK(list->keydefs, kd, next);
		(void)dns_c_kdef_delete(lctx, &kd);
		r = ISC_R_SUCCESS;
	} else {
		r = ISC_R_NOTFOUND;
	}

	return (r);
}


isc_result_t
dns_c_kdeflist_find(isc_log_t *lctx,
		    dns_c_kdeflist_t *list, const char *keyid,
		    dns_c_kdef_t **retval)
{
	dns_c_kdef_t *kd;
	isc_result_t r;

	(void)lctx;

	REQUIRE(DNS_C_KDEFLIST_VALID(list));
	REQUIRE(keyid != NULL);
	REQUIRE(strlen(keyid) > 0);

	kd = ISC_LIST_HEAD(list->keydefs);
	while (kd != NULL) {
		if (strcmp(kd->keyid, keyid) == 0) {
			break;
		}
		kd = ISC_LIST_NEXT(kd, next);
	}

	if (kd != NULL) {
		*retval = kd;
		r = ISC_R_SUCCESS;
	} else {
		r = ISC_R_NOTFOUND;
	}

	return (r);
}



void
dns_c_kdeflist_print(isc_log_t *lctx,
		     FILE *fp, int indent, dns_c_kdeflist_t *list)
{
	dns_c_kdef_t *kd;

	REQUIRE(fp != NULL);
	REQUIRE(indent >= 0);
	REQUIRE(DNS_C_KDEFLIST_VALID(list));

	if (list == NULL) {
		return;
	}
	
	kd = ISC_LIST_HEAD(list->keydefs);
	while (kd != NULL) {
		dns_c_kdef_print(lctx, fp, indent, kd);
		fprintf(fp, "\n");
		kd = ISC_LIST_NEXT(kd, next);
	}
}


isc_result_t
dns_c_kdef_new(isc_log_t *lctx,
	       dns_c_kdeflist_t *list, const char *name,
	       dns_c_kdef_t **keyid)
{
	dns_c_kdef_t *kd;

	(void)lctx;

	REQUIRE(DNS_C_KDEFLIST_VALID(list));
	REQUIRE(keyid != NULL);
	REQUIRE(name != NULL);
	REQUIRE(strlen(name) > 0);
	
	kd = isc_mem_get(list->mem, sizeof *kd);
	if (kd == NULL) {
		return (ISC_R_NOMEMORY);
	}

	kd->keyid = isc_mem_strdup(list->mem, name);
	if (kd->keyid == NULL) {
		isc_mem_put(list->mem, kd, sizeof *kd);
	}

	kd->magic = DNS_C_KDEF_MAGIC;
	kd->mylist = list;
	kd->algorithm = NULL;
	kd->secret = NULL;

	ISC_LIST_APPEND(list->keydefs, kd, next);

	*keyid = kd;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_kdef_delete(isc_log_t *lctx, dns_c_kdef_t **keydef)
{
	dns_c_kdef_t *kd;
	isc_mem_t *mem;

	(void)lctx;

	REQUIRE(keydef != NULL);
	REQUIRE(DNS_C_KDEF_VALID(*keydef));

	kd = *keydef;

	mem = kd->mylist->mem;
	
	isc_mem_free(mem, kd->keyid);

	if (kd->algorithm != NULL) {
		isc_mem_free(mem, kd->algorithm);
	}

	if (kd->secret != NULL) {
		isc_mem_free(mem, kd->secret);
	}

	kd->magic = 0;
	kd->keyid = NULL;
	kd->mylist = NULL;
	kd->algorithm = NULL;
	kd->secret = NULL;

	ISC_LINK_INIT(kd,next);

	isc_mem_put(mem, kd, sizeof *kd);

	*keydef = NULL;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_kdef_copy(isc_log_t *lctx, isc_mem_t *mem,
		dns_c_kdef_t **dest, dns_c_kdef_t *src)
{
	dns_c_kdef_t *newk;

	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_KDEF_VALID(src));
	
	newk = isc_mem_get(mem, sizeof *newk);
	if (newk == NULL) {
		return (ISC_R_NOMEMORY);
	}
	newk->magic = DNS_C_KDEF_MAGIC;
	newk->secret = newk->algorithm = newk->keyid = NULL;
	
	newk->keyid = isc_mem_strdup(mem, src->keyid);
	if (newk->keyid == NULL) {
		dns_c_kdef_delete(lctx, &newk);
		return (ISC_R_NOMEMORY);
	}
	
	newk->algorithm = isc_mem_strdup(mem, src->algorithm);
	if (newk->algorithm == NULL) {
		dns_c_kdef_delete(lctx, &newk);
		return (ISC_R_NOMEMORY);
	}
		
	newk->secret = isc_mem_strdup(mem, src->secret);
	if (newk->secret == NULL) {
		dns_c_kdef_delete(lctx, &newk);
		return (ISC_R_NOMEMORY);
	}

	*dest = newk;

	return (ISC_R_SUCCESS);
}

		

void
dns_c_kdef_print(isc_log_t *lctx,
		 FILE *fp, int indent, dns_c_kdef_t *keydef)
{
	const char *quote = "";
	
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_KDEF_VALID(keydef));

	if (dns_c_need_quote(lctx, keydef->keyid)) {
		quote = "\"";
	}

	dns_c_printtabs(lctx, fp, indent);
	fprintf(fp, "key %s%s%s {\n",quote, keydef->keyid, quote);

	dns_c_printtabs(lctx, fp, indent + 1);
	fprintf(fp, "algorithm \"%s\";\n",keydef->algorithm);

	dns_c_printtabs(lctx, fp, indent + 1);
	fprintf(fp, "secret \"%s\";\n",keydef->secret);

	dns_c_printtabs(lctx, fp, indent);
	fprintf(fp, "};\n");
}


isc_result_t
dns_c_kdef_setalgorithm(isc_log_t *lctx,
			dns_c_kdef_t *keydef, const char *algorithm)
{
	(void)lctx;
	
	REQUIRE(DNS_C_KDEF_VALID(keydef));
	REQUIRE(algorithm != NULL);
	REQUIRE(strlen(algorithm) > 0);

	if (keydef->algorithm != NULL) {
		isc_mem_free(keydef->mylist->mem, keydef->algorithm);
	}
	
	keydef->algorithm = isc_mem_strdup(keydef->mylist->mem,
					   algorithm);
	if (keydef->algorithm == NULL) {
		return (ISC_R_NOMEMORY);
	}

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_kdef_setsecret(isc_log_t *lctx,
		     dns_c_kdef_t *keydef, const char *secret)
{
	(void)lctx;
	
	REQUIRE(DNS_C_KDEF_VALID(keydef));
	REQUIRE(secret != NULL);
	REQUIRE(strlen(secret) > 0);
	
	if (keydef->secret != NULL) {
		isc_mem_free(keydef->mylist->mem, keydef->secret);
	}
	
	keydef->secret = isc_mem_strdup(keydef->mylist->mem, secret);
	if (keydef->secret == NULL) {
		return (ISC_R_NOMEMORY);
	}

	return (ISC_R_SUCCESS);
}



isc_result_t
dns_c_kidlist_new(isc_log_t *lctx,
		  isc_mem_t *mem, dns_c_kidlist_t **list)
{
	dns_c_kidlist_t *l;

	(void)lctx;

	l = isc_mem_get(mem, sizeof *l);
	if (l == NULL) {
		return (ISC_R_NOMEMORY);
	}

	l->magic = DNS_C_KEYIDLIST_MAGIC;
	l->mem = mem;
	*list = l;
	
	ISC_LIST_INIT(l->keyids);

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_kidlist_delete(isc_log_t *lctx,
		     dns_c_kidlist_t **list)
{
	dns_c_kidlist_t *l;
	dns_c_kid_t *ki, *tmpki;
	isc_result_t r;

	REQUIRE(list != NULL);
	REQUIRE(DNS_C_KEYIDLIST_VALID(*list));
	
	l = *list;

	ki = ISC_LIST_HEAD(l->keyids);
	while (ki != NULL) {
		tmpki = ISC_LIST_NEXT(ki, next);
		ISC_LIST_UNLINK(l->keyids, ki, next);
		r = keyid_delete(lctx, &ki);
		if (r != ISC_R_SUCCESS) {
			return (r);
		}
		ki = tmpki;
	}

	l->magic = 0;
	isc_mem_put(l->mem, l, sizeof *l);

	*list = NULL;
	
	return (ISC_R_SUCCESS);
}


static isc_result_t
keyid_delete(isc_log_t *lctx,
	     dns_c_kid_t **keyid)
{
	dns_c_kid_t *ki;

	(void)lctx;

	REQUIRE(keyid != NULL);
	REQUIRE(DNS_C_KEYID_VALID(*keyid));
	
	ki = *keyid;

	isc_mem_free(ki->mylist->mem, ki->keyid);

	ki->magic = 0;
	isc_mem_put(ki->mylist->mem, ki, sizeof *ki);

	*keyid = NULL;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_kidlist_undef(isc_log_t *lctx,
		    dns_c_kidlist_t *list, const char *keyid)
{
	dns_c_kid_t *ki;
	isc_result_t r;

	REQUIRE(DNS_C_KEYIDLIST_VALID(list));
	REQUIRE(keyid != NULL);
	REQUIRE(strlen(keyid) > 0);
	
	dns_c_kidlist_find(lctx, list, keyid, &ki);
	
	if (ki != NULL) {
		ISC_LIST_UNLINK(list->keyids, ki, next);
		r = keyid_delete(lctx, &ki);
	} else {
		r = ISC_R_SUCCESS;
	}

	return (r);
}


isc_result_t
dns_c_kidlist_find(isc_log_t *lctx,
		   dns_c_kidlist_t *list, const char *keyid,
		   dns_c_kid_t **retval)
{
	dns_c_kid_t *iter;

	(void)lctx;

	REQUIRE(DNS_C_KEYIDLIST_VALID(list));
	REQUIRE(keyid != NULL);
	REQUIRE(strlen(keyid) > 0);
	REQUIRE(retval != NULL);
	
	iter = ISC_LIST_HEAD(list->keyids);
	while (iter != NULL) {
		if (strcmp(keyid, iter->keyid) == 0) {
			break;
		}

		iter = ISC_LIST_NEXT(iter, next);
	}

	*retval = iter;

	return (iter == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


void
dns_c_kidlist_print(isc_log_t *lctx, FILE *fp, int indent,
		    dns_c_kidlist_t *list)
{
	dns_c_kid_t *iter;
	const char *quote;

	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_KEYIDLIST_VALID(list));

	if (ISC_LIST_EMPTY(list->keyids)) {
		return;
	}

	dns_c_printtabs(lctx, fp, indent);
	fprintf(fp, "keys {\n");
	iter = ISC_LIST_HEAD(list->keyids);
	if (iter == NULL) {
		dns_c_printtabs(lctx, fp, indent + 1);
		fprintf(fp, "/* no keys defined */\n");
	} else {
		while (iter != NULL) {
			if (dns_c_need_quote(lctx, iter->keyid)) {
				quote = "\"";
			} else {
				quote = "";
			}
			dns_c_printtabs(lctx, fp, indent + 1);
			fprintf(fp, "%s%s%s;\n", quote, iter->keyid, quote);
			iter = ISC_LIST_NEXT(iter, next);
		}
	}
	
	dns_c_printtabs(lctx, fp, indent);
	fprintf(fp, "};\n");
}


isc_result_t
dns_c_kid_new(isc_log_t *lctx,
	      dns_c_kidlist_t *list, const char *name, dns_c_kid_t **keyid)
{
	dns_c_kid_t *ki;

	(void)lctx;

	REQUIRE(DNS_C_KEYIDLIST_VALID(list));
	REQUIRE(name != NULL);
	REQUIRE(strlen(name) > 0);
	REQUIRE(keyid != NULL);
	
	ki = isc_mem_get(list->mem, sizeof *ki);
	if (ki == NULL) {
		return (ISC_R_NOMEMORY);
	}

	ki->magic = DNS_C_KEYID_MAGIC;
	ki->mylist = list;
	ki->keyid = isc_mem_strdup(list->mem, name);

	ISC_LINK_INIT(ki, next);
	ISC_LIST_APPEND(list->keyids, ki, next);

	*keyid = ki;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_pklist_new(isc_log_t *lctx, isc_mem_t *mem, dns_c_pklist_t **pklist)
{
	dns_c_pklist_t *newl;

	(void) lctx;

	REQUIRE(pklist != NULL);

	newl = isc_mem_get(mem, sizeof *newl);
	if (newl == NULL) {
		return (ISC_R_NOMEMORY);
	}

	newl->mem = mem;
	newl->magic = DNS_C_PKLIST_MAGIC;

	ISC_LIST_INIT(newl->keylist);

	*pklist = newl;
	
	return (ISC_R_SUCCESS);
}

	
isc_result_t
dns_c_pklist_delete(isc_log_t *lctx, dns_c_pklist_t **list)
{
	dns_c_pklist_t *l;
	dns_c_pubkey_t *pk;
	dns_c_pubkey_t *tmppk;
	isc_result_t r;

	REQUIRE(list != NULL);
	REQUIRE(DNS_C_PKLIST_VALID(*list));

	l = *list;

	pk = ISC_LIST_HEAD(l->keylist);
	while (pk != NULL) {
		tmppk = ISC_LIST_NEXT(pk, next);
		ISC_LIST_UNLINK(l->keylist, pk, next);
		r = dns_c_pubkey_delete(lctx, &pk);
		if (r != ISC_R_SUCCESS) {
			return (r);
		}

		pk = tmppk;
	}

	l->magic = 0;
	isc_mem_put(l->mem, l, sizeof *l);

	return (ISC_R_SUCCESS);
}



void
dns_c_pklist_print(isc_log_t *lctx,
		   FILE *fp, int indent, dns_c_pklist_t *list)
{
	dns_c_pubkey_t *pk;

	REQUIRE(fp != NULL);
	REQUIRE(indent >= 0);

	if (list == NULL) {
		return;
	}

	REQUIRE(DNS_C_PKLIST_VALID(list));
	
	pk = ISC_LIST_HEAD(list->keylist);
	while (pk != NULL) {
		dns_c_pubkey_print(lctx, fp, indent, pk);
		pk = ISC_LIST_NEXT(pk, next);
	}
	fprintf(fp, "\n");
}



isc_result_t
dns_c_pklist_addpubkey(isc_log_t *lctx, dns_c_pklist_t *list,
		       dns_c_pubkey_t *pkey,
		       isc_boolean_t deepcopy)
{
	dns_c_pubkey_t *pk;
	isc_result_t r;

	REQUIRE(DNS_C_PKLIST_VALID(list));
	REQUIRE(DNS_C_PUBKEY_VALID(pkey));

	if (deepcopy) {
		r = dns_c_pubkey_copy(lctx, list->mem, &pk, pkey);
		if (r != ISC_R_SUCCESS) {
			return (r);
		}
	} else {
		pk = pkey;
	}

	ISC_LIST_APPEND(list->keylist, pk, next);

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_pklist_findpubkey(isc_log_t *lctx, dns_c_pklist_t *list,
			dns_c_pubkey_t **pubkey, isc_int32_t flags,
			isc_int32_t protocol, isc_int32_t algorithm,
			const char *key)
{
	dns_c_pubkey_t *pk;

	(void) lctx;
	
	REQUIRE(DNS_C_PKLIST_VALID(list));
	REQUIRE(pubkey != NULL);

	*pubkey = NULL;
	pk = ISC_LIST_HEAD(list->keylist);
	while (pk != NULL) {
		if (pk->flags == flags &&
		    pk->protocol == protocol &&
		    pk->algorithm == algorithm &&
		    strcmp(pk->key, key) == 0) {
			*pubkey = pk;
			pk = NULL;
		} else {
			pk = ISC_LIST_NEXT(pk, next);
		}
	}

	return (*pubkey == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}



isc_result_t
dns_c_pklist_rmpubkey(isc_log_t *lctx, dns_c_pklist_t *list,
		      isc_int32_t flags,
		      isc_int32_t protocol, isc_int32_t algorithm,
		      const char *key)
{
	dns_c_pubkey_t *pk;
	isc_result_t r;

	REQUIRE(DNS_C_PKLIST_VALID(list));
	REQUIRE(key != NULL);
	REQUIRE(strlen(key) > 0);

	r = dns_c_pklist_findpubkey(lctx, list, &pk, flags, protocol,
				    algorithm, key);
	if (r == ISC_R_SUCCESS) {
		ISC_LIST_UNLINK(list->keylist, pk, next);
		r = dns_c_pubkey_delete(lctx, &pk);
	}

	return (r);
}



isc_result_t
dns_c_pubkey_new(isc_log_t *lctx,
		 isc_mem_t *mem, isc_int32_t flags,
		 isc_int32_t protocol,
		 isc_int32_t algorithm,
		 const char *key, dns_c_pubkey_t **pubkey)
{
	dns_c_pubkey_t *pkey;

	(void)lctx;

	REQUIRE(pubkey != NULL);
	REQUIRE(key != NULL);
	REQUIRE(strlen(key) > 0);

	pkey = isc_mem_get(mem, sizeof *pkey);
	if (pkey == NULL) {
		return (ISC_R_NOMEMORY);
	}

	pkey->magic = DNS_C_PUBKEY_MAGIC;
	pkey->mem = mem;
	pkey->flags = flags;
	pkey->protocol = protocol;
	pkey->algorithm = algorithm;
	pkey->key = isc_mem_strdup(mem, key);
	if (pkey->key == NULL) {
		isc_mem_put(mem, pkey, sizeof *pkey);
		return (ISC_R_NOMEMORY);
	}
	
	*pubkey = pkey;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_pubkey_delete(isc_log_t *lctx,
		    dns_c_pubkey_t **pubkey)
{
	dns_c_pubkey_t *pkey;

	(void)lctx;

	REQUIRE(pubkey != NULL);
	REQUIRE(DNS_C_PUBKEY_VALID(*pubkey));

	pkey = *pubkey;

	if (pkey->key != NULL) {
		isc_mem_free(pkey->mem, pkey->key);
	}

	isc_mem_put(pkey->mem, pkey, sizeof *pkey);

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_pubkey_copy(isc_log_t *lctx,
		  isc_mem_t *mem, dns_c_pubkey_t **dest, dns_c_pubkey_t *src)
{
	dns_c_pubkey_t *k;
	isc_result_t res;

	REQUIRE(DNS_C_PUBKEY_VALID(src));
	REQUIRE(dest != NULL);
	
	res = dns_c_pubkey_new(lctx, mem, src->flags, src->protocol,
			       src->algorithm, src->key, &k);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	*dest = k;

	return (ISC_R_SUCCESS);
}

isc_boolean_t
dns_c_pubkey_equal(dns_c_pubkey_t *k1, dns_c_pubkey_t *k2) {

	REQUIRE(DNS_C_PUBKEY_VALID(k1));
	REQUIRE(DNS_C_PUBKEY_VALID(k2));

	return (ISC_TF(k1->flags == k2->flags &&
		k1->protocol == k2->protocol &&
		k1->algorithm == k2->algorithm &&
		strcmp(k1->key, k2->key) == 0));
}

void
dns_c_pubkey_print(isc_log_t *lctx,
		   FILE *fp, int indent, dns_c_pubkey_t *pubkey)
{
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_PUBKEY_VALID(pubkey));

	dns_c_printtabs(lctx, fp, indent);
	fprintf(fp, "pubkey %d %d %d \"%s\";\n",
		pubkey->flags, pubkey->protocol,
		pubkey->algorithm, pubkey->key);
}


isc_result_t
dns_c_tkeylist_new(isc_log_t *lctx,
		   isc_mem_t *mem, dns_c_tkeylist_t **newlist)
{
	dns_c_tkeylist_t *nl;

	(void)lctx;

	REQUIRE(newlist != NULL);

	nl = isc_mem_get(mem, sizeof *nl);
	if (nl == NULL) {
		return (ISC_R_NOMEMORY);
	}

	nl->magic = DNS_C_TKEYLIST_MAGIC;
	nl->mem = mem;
	ISC_LIST_INIT(nl->tkeylist);

	*newlist = nl;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkeylist_delete(isc_log_t *lctx,
		      dns_c_tkeylist_t **list)
{
	dns_c_tkeylist_t *l;
	dns_c_tkey_t *tkey, *tmptkey;
	isc_result_t res;

	REQUIRE(list != NULL);
	REQUIRE(DNS_C_TKEYLIST_VALID(*list));

	l = *list;
		
	tkey = ISC_LIST_HEAD(l->tkeylist);
	while (tkey != NULL) {
		tmptkey = ISC_LIST_NEXT(tkey, next);
		ISC_LIST_UNLINK(l->tkeylist, tkey, next);

		res = dns_c_tkey_delete(lctx, &tkey);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
		
		tkey = tmptkey;
	}

	l->magic = 0;
	isc_mem_put(l->mem, l, sizeof *l);

	*list = NULL;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkeylist_copy(isc_log_t *lctx,
		    isc_mem_t *mem, dns_c_tkeylist_t **dest,
		    dns_c_tkeylist_t *src)
{
	dns_c_tkeylist_t *newlist;
	dns_c_tkey_t *tkey, *tmptkey;
	isc_result_t res;

	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_TKEYLIST_VALID(src));
	
	res = dns_c_tkeylist_new(lctx, mem, &newlist);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	tkey = ISC_LIST_HEAD(src->tkeylist);
	while (tkey != NULL) {
		res = dns_c_tkey_copy(lctx, mem, &tmptkey, tkey);
		if (res != ISC_R_SUCCESS) {
			dns_c_tkeylist_delete(lctx, &newlist);
			return (res);
		}

		res = dns_c_tkeylist_append(lctx, newlist, tmptkey, ISC_FALSE);
		if (res != ISC_R_SUCCESS) {
			dns_c_tkey_delete(lctx, &tmptkey);
			dns_c_tkeylist_delete(lctx, &newlist);
			return (res);
		}
		
		tkey = ISC_LIST_NEXT(tkey, next);
	}

	*dest = newlist;

	return (ISC_R_SUCCESS);
}


void
dns_c_tkeylist_print(isc_log_t *lctx,
		     FILE *fp, int indent, dns_c_tkeylist_t *list)
{
	dns_c_tkey_t *tkey;
	
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_TKEYLIST_VALID(list));
	
	if (ISC_LIST_EMPTY(list->tkeylist)) {
		return;
	}

	dns_c_printtabs(lctx, fp, indent);
	fprintf(fp, "trusted-keys {\n");
	tkey = ISC_LIST_HEAD(list->tkeylist);
	while (tkey != NULL) {
		dns_c_tkey_print(lctx, fp, indent + 1, tkey);
		tkey = ISC_LIST_NEXT(tkey, next);
	}
	dns_c_printtabs(lctx, fp, indent);
	fprintf(fp,"};\n");
}


isc_result_t
dns_c_tkeylist_append(isc_log_t *lctx,
		      dns_c_tkeylist_t *list, dns_c_tkey_t *element,
		      isc_boolean_t copy)
{
	dns_c_tkey_t *newe;
	isc_result_t res;
	
	REQUIRE(DNS_C_TKEYLIST_VALID(list));
	REQUIRE(DNS_C_TKEY_VALID(element));

	if (copy) {
		res = dns_c_tkey_copy(lctx, list->mem, &newe, element);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	} else {
		newe = element;
	}

	ISC_LIST_APPEND(list->tkeylist, newe, next);

	return (ISC_R_SUCCESS);
}



isc_result_t
dns_c_tkey_new(isc_log_t *lctx,
	       isc_mem_t *mem, const char *domain, isc_int32_t flags,
	       isc_int32_t protocol, isc_int32_t algorithm,
	       const char *key, dns_c_tkey_t **newkey)
{
	dns_c_tkey_t *newk;
	dns_c_pubkey_t *pk;
	dns_result_t res;

	REQUIRE(domain != NULL);
	REQUIRE(strlen(domain) > 0);
	REQUIRE(key != NULL);
	REQUIRE(strlen(key) > 0);
	REQUIRE(newkey != NULL);

	newk = isc_mem_get(mem, sizeof *newk);
	if (newk == NULL) {
		return (ISC_R_NOMEMORY);
	}

	res = dns_c_pubkey_new(lctx, mem, flags, protocol,
			       algorithm, key, &pk);
	if (res != ISC_R_SUCCESS) {
		isc_mem_put(mem, newk, sizeof *newk);
		return (res);
	}

	newk->mem = mem;
	newk->magic = DNS_C_TKEY_MAGIC;

	newk->domain = isc_mem_strdup(mem, domain);
	if (newk->domain == NULL) {
		dns_c_pubkey_delete(lctx, &pk);
		isc_mem_put(mem, newk, sizeof *newk);
		return (ISC_R_NOMEMORY);
	}
	
	newk->pubkey = pk;

	ISC_LINK_INIT(newk, next);

	*newkey = newk;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkey_delete(isc_log_t *lctx,
		  dns_c_tkey_t **tkey)
{
	isc_result_t res;
	dns_c_tkey_t *tk;

	REQUIRE(tkey != NULL);
	REQUIRE(DNS_C_TKEY_VALID(*tkey));

	tk = *tkey;

	isc_mem_free(tk->mem, tk->domain);

	res = dns_c_pubkey_delete(lctx, &tk->pubkey);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	tk->magic = 0;
	isc_mem_put(tk->mem, tk, sizeof *tk);
	
	*tkey = NULL;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkey_copy(isc_log_t *lctx,
		isc_mem_t *mem, dns_c_tkey_t **dest, dns_c_tkey_t *src)
{
	dns_c_tkey_t *newk;
	dns_c_pubkey_t *newpk;
	isc_result_t res;

	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_TKEY_VALID(src));

	newk = isc_mem_get(mem, sizeof *newk);
	if (newk == NULL) {
		return (ISC_R_NOMEMORY);
	}

	newk->magic = DNS_C_TKEY_MAGIC;
	newk->domain = isc_mem_strdup(mem, src->domain);
	if (newk->domain == NULL) {
		isc_mem_put(mem, newk, sizeof *newk);
		return (ISC_R_NOMEMORY);
	}

	res = dns_c_pubkey_copy(lctx, mem, &newpk, src->pubkey);
	if (res != ISC_R_SUCCESS) {
		isc_mem_free(mem, newk->domain);
		isc_mem_put(mem, newk, sizeof *newk);
		return (res);
	}

	newk->pubkey = newpk;

	*dest = newk;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkey_getflags(isc_log_t *lctx,
		    dns_c_tkey_t *tkey, isc_int32_t *flags)
{
	(void)lctx;
	
	REQUIRE(DNS_C_TKEY_VALID(tkey));

	*flags = tkey->pubkey->flags;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkey_getprotocol(isc_log_t *lctx,
		       dns_c_tkey_t *tkey, isc_int32_t *protocol)
{
	(void)lctx;
	
	REQUIRE(DNS_C_TKEY_VALID(tkey));

	*protocol = tkey->pubkey->protocol;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkey_getalgorithm(isc_log_t *lctx,
			dns_c_tkey_t *tkey, isc_int32_t *algorithm)
{
	(void)lctx;
	
	REQUIRE(DNS_C_TKEY_VALID(tkey));

	*algorithm = tkey->pubkey->algorithm;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkey_getkey(isc_log_t *lctx,
		  dns_c_tkey_t *tkey, const char **key)
{
	(void)lctx;
	
	REQUIRE(key != NULL);
	REQUIRE(DNS_C_TKEY_VALID(tkey));
	
	*key = tkey->pubkey->key;

	return (ISC_R_SUCCESS);
}


void
dns_c_tkey_print(isc_log_t *lctx,
		 FILE *fp, int indent, dns_c_tkey_t *tkey)
{
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_TKEY_VALID(tkey));

	dns_c_printtabs(lctx, fp, indent);
	fprintf(fp, "\"%s\" %d %d %d \"%s\";\n",
		tkey->domain, tkey->pubkey->flags,
		tkey->pubkey->protocol, tkey->pubkey->algorithm,
		tkey->pubkey->key);

	return;
}

