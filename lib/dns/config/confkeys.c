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

#include <string.h>

#include <isc/assertions.h>
#include <isc/magic.h>

#include <dns/result.h>
#include <dns/confkeys.h>
#include <dns/confcommon.h>

static isc_result_t keyid_delete(dns_c_kid_t **ki);


isc_result_t
dns_c_kdeflist_new(isc_mem_t *mem, dns_c_kdeflist_t **list)
{
	dns_c_kdeflist_t *newlist;

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
dns_c_kdeflist_delete(dns_c_kdeflist_t **list)
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
		res = dns_c_kdef_delete(&kd);
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
dns_c_kdeflist_copy(isc_mem_t *mem, dns_c_kdeflist_t **dest,
		    dns_c_kdeflist_t *src)
{
	dns_c_kdeflist_t *newlist;
	dns_c_kdef_t *key;
	isc_result_t res;

	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_KDEFLIST_VALID(src));
	
	res = dns_c_kdeflist_new(mem, &newlist);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	key = ISC_LIST_HEAD(src->keydefs);
	while (key != NULL) {
		res = dns_c_kdeflist_append(newlist, key, ISC_TRUE);
		if (res != ISC_R_SUCCESS) {
			dns_c_kdeflist_delete(&newlist);
			return (res);
		}
		
		key = ISC_LIST_NEXT(key, next);
	}

	*dest = newlist;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_kdeflist_append(dns_c_kdeflist_t *list,
		      dns_c_kdef_t *key, isc_boolean_t copy)
{
	dns_c_kdef_t *newe;
	isc_result_t res;
	
	REQUIRE(DNS_C_KDEFLIST_VALID(list));
	REQUIRE(DNS_C_KDEF_VALID(key));

	if (copy) {
		res = dns_c_kdef_copy(list->mem, &newe, key);
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
dns_c_kdeflist_undef(dns_c_kdeflist_t *list, const char *keyid)
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
		(void)dns_c_kdef_delete(&kd);
		r = ISC_R_SUCCESS;
	} else {
		r = ISC_R_NOTFOUND;
	}

	return (r);
}


isc_result_t
dns_c_kdeflist_find(dns_c_kdeflist_t *list, const char *keyid,
		    dns_c_kdef_t **retval)
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
		*retval = kd;
		r = ISC_R_SUCCESS;
	} else {
		r = ISC_R_NOTFOUND;
	}

	return (r);
}



void
dns_c_kdeflist_print(FILE *fp, int indent, dns_c_kdeflist_t *list)
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
		dns_c_kdef_print(fp, indent, kd);
		fprintf(fp, "\n");
		kd = ISC_LIST_NEXT(kd, next);
	}
}


isc_result_t
dns_c_kdef_new(dns_c_kdeflist_t *list, const char *name,
	       dns_c_kdef_t **keyid)
{
	dns_c_kdef_t *kd;

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
dns_c_kdef_delete(dns_c_kdef_t **keydef)
{
	dns_c_kdef_t *kd;
	isc_mem_t *mem;

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
dns_c_kdef_copy(isc_mem_t *mem,
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
		dns_c_kdef_delete(&newk);
		return (ISC_R_NOMEMORY);
	}
	
	newk->algorithm = isc_mem_strdup(mem, src->algorithm);
	if (newk->algorithm == NULL) {
		dns_c_kdef_delete(&newk);
		return (ISC_R_NOMEMORY);
	}
		
	newk->secret = isc_mem_strdup(mem, src->secret);
	if (newk->secret == NULL) {
		dns_c_kdef_delete(&newk);
		return (ISC_R_NOMEMORY);
	}

	*dest = newk;

	return (ISC_R_SUCCESS);
}

		

void
dns_c_kdef_print(FILE *fp, int indent, dns_c_kdef_t *keydef)
{
	const char *quote = "";
	
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_KDEF_VALID(keydef));

	if (dns_c_need_quote(keydef->keyid)) {
		quote = "\"";
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "key %s%s%s {\n",quote, keydef->keyid, quote);

	dns_c_printtabs(fp, indent + 1);
	fprintf(fp, "algorithm \"%s\";\n",keydef->algorithm);

	dns_c_printtabs(fp, indent + 1);
	fprintf(fp, "secret \"%s\";\n",keydef->secret);

	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");
}


isc_result_t
dns_c_kdef_setalgorithm(dns_c_kdef_t *keydef, const char *algorithm)
{
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
dns_c_kdef_setsecret(dns_c_kdef_t *keydef, const char *secret)
{
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
dns_c_kidlist_new(isc_mem_t *mem, dns_c_kidlist_t **list)
{
	dns_c_kidlist_t *l;

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
dns_c_kidlist_delete(dns_c_kidlist_t **list)
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
		r = keyid_delete(&ki);
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
keyid_delete(dns_c_kid_t **keyid)
{
	dns_c_kid_t *ki;

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
dns_c_kidlist_undef(dns_c_kidlist_t *list, const char *keyid)
{
	dns_c_kid_t *ki;
	isc_result_t r;

	REQUIRE(DNS_C_KEYIDLIST_VALID(list));
	REQUIRE(keyid != NULL);
	REQUIRE(strlen(keyid) > 0);
	
	dns_c_kidlist_find(list, keyid, &ki);
	
	if (ki != NULL) {
		ISC_LIST_UNLINK(list->keyids, ki, next);
		r = keyid_delete(&ki);
	} else {
		r = ISC_R_SUCCESS;
	}

	return (r);
}


isc_result_t
dns_c_kidlist_find(dns_c_kidlist_t *list, const char *keyid,
		   dns_c_kid_t **retval)
{
	dns_c_kid_t *iter;

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
dns_c_kidlist_print(FILE *fp, int indent,
		    dns_c_kidlist_t *list)
{
	dns_c_kid_t *iter;
	const char *quote;

	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_KEYIDLIST_VALID(list));

	if (ISC_LIST_EMPTY(list->keyids)) {
		return;
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "keys {\n");
	iter = ISC_LIST_HEAD(list->keyids);
	if (iter == NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "/* no keys defined */\n");
	} else {
		while (iter != NULL) {
			if (dns_c_need_quote(iter->keyid)) {
				quote = "\"";
			} else {
				quote = "";
			}
			dns_c_printtabs(fp, indent + 1);
			fprintf(fp, "%s%s%s;\n", quote, iter->keyid, quote);
			iter = ISC_LIST_NEXT(iter, next);
		}
	}
	
	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");
}


isc_result_t
dns_c_kid_new(dns_c_kidlist_t *list, const char *name, dns_c_kid_t **keyid)
{
	dns_c_kid_t *ki;

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
dns_c_pklist_new(isc_mem_t *mem, dns_c_pklist_t **pklist)
{
	dns_c_pklist_t *newl;

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
dns_c_pklist_delete(dns_c_pklist_t **list)
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
		r = dns_c_pubkey_delete(&pk);
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
dns_c_pklist_print(FILE *fp, int indent, dns_c_pklist_t *list)
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
		dns_c_pubkey_print(fp, indent, pk);
		pk = ISC_LIST_NEXT(pk, next);
	}
	fprintf(fp, "\n");
}



isc_result_t
dns_c_pklist_addpubkey(dns_c_pklist_t *list,
		       dns_c_pubkey_t *pkey,
		       isc_boolean_t deepcopy)
{
	dns_c_pubkey_t *pk;
	isc_result_t r;

	REQUIRE(DNS_C_PKLIST_VALID(list));
	REQUIRE(DNS_C_PUBKEY_VALID(pkey));

	if (deepcopy) {
		r = dns_c_pubkey_copy(list->mem, &pk, pkey);
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
dns_c_pklist_findpubkey(dns_c_pklist_t *list,
			dns_c_pubkey_t **pubkey, isc_int32_t flags,
			isc_int32_t protocol, isc_int32_t algorithm,
			const char *key)
{
	dns_c_pubkey_t *pk;

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
dns_c_pklist_rmpubkey(dns_c_pklist_t *list,
		      isc_int32_t flags,
		      isc_int32_t protocol, isc_int32_t algorithm,
		      const char *key)
{
	dns_c_pubkey_t *pk;
	isc_result_t r;

	REQUIRE(DNS_C_PKLIST_VALID(list));
	REQUIRE(key != NULL);
	REQUIRE(strlen(key) > 0);

	r = dns_c_pklist_findpubkey(list, &pk, flags, protocol,
				    algorithm, key);
	if (r == ISC_R_SUCCESS) {
		ISC_LIST_UNLINK(list->keylist, pk, next);
		r = dns_c_pubkey_delete(&pk);
	}

	return (r);
}



isc_result_t
dns_c_pubkey_new(isc_mem_t *mem, isc_int32_t flags,
		 isc_int32_t protocol,
		 isc_int32_t algorithm,
		 const char *key, dns_c_pubkey_t **pubkey)
{
	dns_c_pubkey_t *pkey;

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
dns_c_pubkey_delete(dns_c_pubkey_t **pubkey)
{
	dns_c_pubkey_t *pkey;

	REQUIRE(pubkey != NULL);
	REQUIRE(DNS_C_PUBKEY_VALID(*pubkey));

	pkey = *pubkey;

	if (pkey->key != NULL) {
		isc_mem_free(pkey->mem, pkey->key);
	}

	pkey->magic = 0;
	isc_mem_put(pkey->mem, pkey, sizeof *pkey);

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_pubkey_copy(isc_mem_t *mem, dns_c_pubkey_t **dest, dns_c_pubkey_t *src)
{
	dns_c_pubkey_t *k;
	isc_result_t res;

	REQUIRE(DNS_C_PUBKEY_VALID(src));
	REQUIRE(dest != NULL);
	
	res = dns_c_pubkey_new(mem, src->flags, src->protocol,
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
dns_c_pubkey_print(FILE *fp, int indent, dns_c_pubkey_t *pubkey)
{
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_PUBKEY_VALID(pubkey));

	dns_c_printtabs(fp, indent);
	fprintf(fp, "pubkey %d %d %d \"%s\";\n",
		pubkey->flags, pubkey->protocol,
		pubkey->algorithm, pubkey->key);
}


isc_result_t
dns_c_tkeylist_new(isc_mem_t *mem, dns_c_tkeylist_t **newlist)
{
	dns_c_tkeylist_t *nl;

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
dns_c_tkeylist_delete(dns_c_tkeylist_t **list)
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

		res = dns_c_tkey_delete(&tkey);
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
dns_c_tkeylist_copy(isc_mem_t *mem, dns_c_tkeylist_t **dest,
		    dns_c_tkeylist_t *src)
{
	dns_c_tkeylist_t *newlist;
	dns_c_tkey_t *tkey, *tmptkey;
	isc_result_t res;

	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_TKEYLIST_VALID(src));
	
	res = dns_c_tkeylist_new(mem, &newlist);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}
	
	tkey = ISC_LIST_HEAD(src->tkeylist);
	while (tkey != NULL) {
		res = dns_c_tkey_copy(mem, &tmptkey, tkey);
		if (res != ISC_R_SUCCESS) {
			dns_c_tkeylist_delete(&newlist);
			return (res);
		}

		res = dns_c_tkeylist_append(newlist, tmptkey, ISC_FALSE);
		if (res != ISC_R_SUCCESS) {
			dns_c_tkey_delete(&tmptkey);
			dns_c_tkeylist_delete(&newlist);
			return (res);
		}
		
		tkey = ISC_LIST_NEXT(tkey, next);
	}

	*dest = newlist;

	return (ISC_R_SUCCESS);
}


void
dns_c_tkeylist_print(FILE *fp, int indent, dns_c_tkeylist_t *list)
{
	dns_c_tkey_t *tkey;
	
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_TKEYLIST_VALID(list));
	
	dns_c_printtabs(fp, indent);
	fprintf(fp, "trusted-keys {\n");
	tkey = ISC_LIST_HEAD(list->tkeylist);
	if (tkey == NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "/* empty list */\n");
	} else {
		while (tkey != NULL) {
			dns_c_tkey_print(fp, indent + 1, tkey);
			tkey = ISC_LIST_NEXT(tkey, next);
		}
	}
	dns_c_printtabs(fp, indent);
	fprintf(fp,"};\n");
}


isc_result_t
dns_c_tkeylist_append(dns_c_tkeylist_t *list, dns_c_tkey_t *element,
		      isc_boolean_t copy)
{
	dns_c_tkey_t *newe;
	isc_result_t res;
	
	REQUIRE(DNS_C_TKEYLIST_VALID(list));
	REQUIRE(DNS_C_TKEY_VALID(element));

	if (copy) {
		res = dns_c_tkey_copy(list->mem, &newe, element);
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
dns_c_tkey_new(isc_mem_t *mem, const char *domain, isc_int32_t flags,
	       isc_int32_t protocol, isc_int32_t algorithm,
	       const char *key, dns_c_tkey_t **newkey)
{
	dns_c_tkey_t *newk;
	dns_c_pubkey_t *pk;
	isc_result_t res;

	REQUIRE(domain != NULL);
	REQUIRE(strlen(domain) > 0);
	REQUIRE(key != NULL);
	REQUIRE(strlen(key) > 0);
	REQUIRE(newkey != NULL);

	newk = isc_mem_get(mem, sizeof *newk);
	if (newk == NULL) {
		return (ISC_R_NOMEMORY);
	}

	res = dns_c_pubkey_new(mem, flags, protocol,
			       algorithm, key, &pk);
	if (res != ISC_R_SUCCESS) {
		isc_mem_put(mem, newk, sizeof *newk);
		return (res);
	}

	newk->mem = mem;
	newk->magic = DNS_C_TKEY_MAGIC;

	newk->domain = isc_mem_strdup(mem, domain);
	if (newk->domain == NULL) {
		dns_c_pubkey_delete(&pk);
		isc_mem_put(mem, newk, sizeof *newk);
		return (ISC_R_NOMEMORY);
	}
	
	newk->pubkey = pk;

	ISC_LINK_INIT(newk, next);

	*newkey = newk;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkey_delete(dns_c_tkey_t **tkey)
{
	isc_result_t res;
	dns_c_tkey_t *tk;

	REQUIRE(tkey != NULL);
	REQUIRE(DNS_C_TKEY_VALID(*tkey));

	tk = *tkey;

	isc_mem_free(tk->mem, tk->domain);

	res = dns_c_pubkey_delete(&tk->pubkey);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	tk->magic = 0;
	isc_mem_put(tk->mem, tk, sizeof *tk);
	
	*tkey = NULL;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkey_copy(isc_mem_t *mem, dns_c_tkey_t **dest, dns_c_tkey_t *src)
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

	res = dns_c_pubkey_copy(mem, &newpk, src->pubkey);
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
dns_c_tkey_getflags(dns_c_tkey_t *tkey, isc_int32_t *flags)
{
	REQUIRE(DNS_C_TKEY_VALID(tkey));

	*flags = tkey->pubkey->flags;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkey_getprotocol(dns_c_tkey_t *tkey, isc_int32_t *protocol)
{
	REQUIRE(DNS_C_TKEY_VALID(tkey));

	*protocol = tkey->pubkey->protocol;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkey_getalgorithm(dns_c_tkey_t *tkey, isc_int32_t *algorithm)
{
	REQUIRE(DNS_C_TKEY_VALID(tkey));

	*algorithm = tkey->pubkey->algorithm;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_tkey_getkey(dns_c_tkey_t *tkey, const char **key)
{
	REQUIRE(key != NULL);
	REQUIRE(DNS_C_TKEY_VALID(tkey));
	
	*key = tkey->pubkey->key;

	return (ISC_R_SUCCESS);
}


void
dns_c_tkey_print(FILE *fp, int indent, dns_c_tkey_t *tkey)
{
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_TKEY_VALID(tkey));

	dns_c_printtabs(fp, indent);
	fprintf(fp, "\"%s\" %d %d %d \"%s\";\n",
		tkey->domain, tkey->pubkey->flags,
		tkey->pubkey->protocol, tkey->pubkey->algorithm,
		tkey->pubkey->key);

	return;
}

