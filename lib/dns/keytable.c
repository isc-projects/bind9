/*
 * Copyright (C) 2000  Internet Software Consortium.
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
#include <string.h>

#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/rwlock.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/keytable.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rbt.h>

struct dns_keytable {
	/* Unlocked. */
        unsigned int		magic;
	isc_mem_t		*mctx;
	isc_mutex_t		lock;
	isc_rwlock_t		rwlock;
	/* Locked by lock. */
	isc_uint32_t		active_nodes;
	/* Locked by rwlock. */
	isc_uint32_t		references;
	dns_rbt_t		*table; 
};

#define KEYTABLE_MAGIC			0x4b54626cU	/* KTbl */
#define VALID_KEYTABLE(kt)	 	ISC_MAGIC_VALID(kt, KEYTABLE_MAGIC)

struct dns_keynode {
        unsigned int		magic;
	dst_key_t *		key;
	struct dns_keynode *	next;
};

#define KEYNODE_MAGIC			0x4b4e6f64U	/* KNod */
#define VALID_KEYNODE(kn)	 	ISC_MAGIC_VALID(kn, KEYNODE_MAGIC)

isc_result_t
dns_keytable_create(isc_mem_t *mctx, dns_keytable_t **keytablep) {
	dns_keytable_t *keytable;
	isc_result_t result;

	/*
	 * Create a keytable.
	 */

	REQUIRE(keytablep != NULL && *keytablep == NULL);

	keytable = isc_mem_get(mctx, sizeof *keytable);
	if (keytable == NULL)
		return (DNS_R_NOMEMORY);

	keytable->table = NULL;
	result = dns_rbt_create(mctx, NULL, NULL, &keytable->table);
	if (result != ISC_R_SUCCESS)
		goto cleanup_keytable;

	result = isc_mutex_init(&keytable->lock);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed: %s",
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto cleanup_rbt;
	}

	result = isc_rwlock_init(&keytable->rwlock, 0, 0);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_rwlock_init() failed: %s",
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto cleanup_lock;
	}

	keytable->mctx = mctx;
	keytable->active_nodes = 0;
	keytable->references = 1;
	keytable->magic = KEYTABLE_MAGIC;
	*keytablep = keytable;

	return (ISC_R_SUCCESS);

   cleanup_lock:
	isc_mutex_destroy(&keytable->lock);

   cleanup_rbt:
	dns_rbt_destroy(&keytable->table);

   cleanup_keytable:
	isc_mem_put(mctx, keytable, sizeof *keytable);

	return (result);
}


void
dns_keytable_attach(dns_keytable_t *source, dns_keytable_t **targetp) {

	/*
	 * Attach *targetp to source.
	 */

	REQUIRE(VALID_KEYTABLE(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	RWLOCK(&source->rwlock, isc_rwlocktype_write);

	INSIST(source->references > 0);
	source->references++;
	INSIST(source->references != 0);

	RWUNLOCK(&source->rwlock, isc_rwlocktype_write);

	*targetp = source;
}

void
dns_keytable_detach(dns_keytable_t **keytablep) {
	isc_boolean_t destroy = ISC_FALSE;
	dns_keytable_t *keytable;

	/*
	 * Detach *keytablep from its keytable.
	 */

	REQUIRE(keytablep != NULL && VALID_KEYTABLE(*keytablep));

	keytable = *keytablep;

	RWLOCK(&keytable->rwlock, isc_rwlocktype_write);
	
	INSIST(keytable->references > 0);
	keytable->references--;
	LOCK(&keytable->lock);
	if (keytable->references == 0 && keytable->active_nodes == 0)
		destroy = ISC_TRUE;
	UNLOCK(&keytable->lock);

	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_write);

	if (destroy) {
		dns_rbt_destroy(&keytable->table);
		isc_rwlock_destroy(&keytable->rwlock);
		isc_mutex_destroy(&keytable->lock);
		keytable->magic = 0;
		isc_mem_put(keytable->mctx, keytable, sizeof *keytable);
	}

	*keytablep = NULL;
}

isc_result_t
dns_keytable_add(dns_keytable_t *keytable, dst_key_t **keyp) {
	isc_result_t result;
	dns_keynode_t *knode;
	dns_rbtnode_t *node;
	dns_fixedname_t fname;
	char *keyname;
	isc_buffer_t buffer;
	size_t len;

	/*
	 * Add '*keyp' to 'keytable'.
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(keyp != NULL);

	keyname = dst_key_name(*keyp);
	INSIST(keyname != NULL);
	len = strlen(keyname);
	isc_buffer_init(&buffer, keyname, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&buffer, len);
	dns_fixedname_init(&fname);
	result = dns_name_fromtext(dns_fixedname_name(&fname), &buffer,
				   dns_rootname, ISC_FALSE, NULL);
	if (result != ISC_R_SUCCESS)
		return (result);

	knode = isc_mem_get(keytable->mctx, sizeof *knode);
	if (knode == NULL)
		return (ISC_R_NOMEMORY);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_write);

	node = NULL;
	result = dns_rbt_addnode(keytable->table, dns_fixedname_name(&fname),
				 &node);

	if (result == ISC_R_SUCCESS || result == ISC_R_EXISTS) {
		knode->magic = KEYNODE_MAGIC;
		knode->key = *keyp;
		knode->next = node->data;
		node->data = knode;
		*keyp = NULL;
		knode = NULL;
	}

	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_write);

	if (knode != NULL)
		isc_mem_put(keytable->mctx, knode, sizeof *knode);

	return (result);
}

isc_result_t
dns_keytable_findkeynode(dns_keytable_t *keytable, dns_name_t *name,
			 dns_secalg_t algorithm, dns_keytag_t tag,
			 dns_keynode_t **keynodep)
{
	isc_result_t result;
	dns_keynode_t *knode;
	void *data;

	/*
	 * Search for a key named 'name', matching 'algorithm' and 'tag' in
	 * 'keytable'.
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(keynodep != NULL && *keynodep == NULL);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);

	knode = NULL;
	data = NULL;
	result = dns_rbt_findname(keytable->table, name, NULL, &data);

	if (result == ISC_R_SUCCESS) {
		INSIST(data != NULL);
		for (knode = data; knode != NULL; knode = knode->next) {
			if (algorithm == (dns_secalg_t)dst_key_alg(knode->key)
			    && tag == (dns_keytag_t)dst_key_id(knode->key))
				break;
		}
		if (knode != NULL) {
			LOCK(&keytable->lock);
			keytable->active_nodes++;
			UNLOCK(&keytable->lock);
			*keynodep = knode;
		} else
			result = ISC_R_NOTFOUND;
	} else if (result == DNS_R_PARTIALMATCH)
		result = ISC_R_NOTFOUND;

	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);

	return (result);
}

void
dns_keytable_detachkeynode(dns_keytable_t *keytable,
			   dns_keynode_t **keynodep)
{
	/*
	 * Give back a keynode found via dns_keytable_findkeynode().
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(keynodep != NULL && VALID_KEYNODE(*keynodep));

	LOCK(&keytable->lock);
	INSIST(keytable->active_nodes > 0);
	keytable->active_nodes--;
	UNLOCK(&keytable->lock);

	*keynodep = NULL;
}

isc_result_t
dns_keytable_issecuredomain(dns_keytable_t *keytable, dns_name_t *name,
			    isc_boolean_t *wantdnssecp)
{
	isc_result_t result;
	void *data;

	/*
	 * Is 'name' at or beneath a trusted key?
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(wantdnssecp != NULL);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);

	data = NULL;
	result = dns_rbt_findname(keytable->table, name, NULL, &data);

	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		INSIST(data != NULL);
		*wantdnssecp = ISC_TRUE;
		result = ISC_R_SUCCESS;
	} else if (result == ISC_R_NOTFOUND) {
		*wantdnssecp = ISC_FALSE;
		result = ISC_R_SUCCESS;
	}

	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);

	return (result);
}

dst_key_t *
dns_keynode_key(dns_keynode_t *keynode) {

	/*
	 * Get the DST key associated with keynode.
	 */

	REQUIRE(VALID_KEYNODE(keynode));

	return (keynode->key);
}
