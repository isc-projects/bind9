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

#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/print.h>
#include <isc/region.h>
#include <isc/stdtime.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dnssec.h>
#include <dns/events.h>
#include <dns/keytable.h>
#include <dns/keyvalues.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/nxt.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>
#include <dns/resolver.h>
#include <dns/result.h>
#include <dns/validator.h>
#include <dns/view.h>

#include <dst/dst.h>

/*
 * We don't use the SIG RR's _tostruct routine because it copies things.
 */
typedef struct dns_siginfo {
	dns_rdatatype_t			covers;
	dns_secalg_t			algorithm;
	isc_uint8_t			labels;
	dns_ttl_t			original_ttl;
	isc_stdtime_t			expiration;
	isc_stdtime_t			inception;
	dns_keytag_t			tag;
	dns_name_t			signer;
	isc_region_t			signature;
} dns_siginfo_t;

struct dns_validator {
	/* Unlocked. */
	unsigned int			magic;
	isc_mutex_t			lock;
	dns_view_t *			view;
	/* Locked by lock. */
	unsigned int			options;
	unsigned int			attributes;
	dns_validatorevent_t *		event;
	dns_fetch_t *			fetch;
	dns_validator_t *		keyvalidator;
	dns_keytable_t *		keytable;
	dns_keynode_t *			keynode;
	dst_key_t *			key;
	dns_siginfo_t *			siginfo;
	isc_task_t *			task;
	isc_taskaction_t		action;
	void *				arg;
	dns_name_t *			queryname;
	unsigned int			labels;
};

#define VALIDATOR_MAGIC			0x56616c3fU	/* Val?. */
#define VALID_VALIDATOR(v)	 	ISC_MAGIC_VALID(v, VALIDATOR_MAGIC)

#define VALATTR_SHUTDOWN		0x01
#define VALATTR_NEGATIVE		0x02
#define SHUTDOWN(v)		(((v)->attributes & VALATTR_SHUTDOWN) != 0)

static void nullkeyvalidated(isc_task_t *task, isc_event_t *event);
static inline isc_boolean_t containsnullkey(dns_validator_t *val,
					    dns_rdataset_t *rdataset);
static inline isc_result_t get_dst_key(dns_validator_t *val,
				       dns_siginfo_t *siginfo,
				       dns_rdataset_t *rdataset);
static inline isc_result_t validate(dns_validator_t *val, isc_boolean_t resume);
static inline isc_result_t nxtvalidate(dns_validator_t *val,
				       isc_boolean_t resume);
static inline isc_result_t proveunsecure(dns_validator_t *val,
					 isc_boolean_t resume);

static void validator_log(dns_validator_t *val, int level,
			  const char *fmt, ...);

static void
rdata_to_siginfo(dns_rdata_t *rdata, dns_siginfo_t *siginfo) {
	isc_buffer_t b;
	isc_region_t r;

	REQUIRE(rdata->type == 24);

	isc_buffer_init(&b, rdata->data, rdata->length);
	isc_buffer_add(&b, rdata->length);
	siginfo->covers = (dns_rdatatype_t)isc_buffer_getuint16(&b);
	siginfo->algorithm = (dns_secalg_t)isc_buffer_getuint8(&b);
	siginfo->labels = isc_buffer_getuint8(&b);
	siginfo->original_ttl = (dns_ttl_t)isc_buffer_getuint32(&b);
	siginfo->expiration = (isc_stdtime_t)isc_buffer_getuint32(&b);
	siginfo->inception = (isc_stdtime_t)isc_buffer_getuint32(&b);
	siginfo->tag = (dns_keytag_t)isc_buffer_getuint16(&b);
	dns_name_init(&siginfo->signer, NULL);
	isc_buffer_remainingregion(&b, &r);
	dns_name_fromregion(&siginfo->signer, &r);
	isc_buffer_forward(&b, siginfo->signer.length);
	isc_buffer_remainingregion(&b, &siginfo->signature);
}

static void
validator_done(dns_validator_t *val, isc_result_t result) {
	isc_task_t *task;

	REQUIRE(val->event != NULL);

	/*
	 * Caller must be holding the lock.
	 */

	val->event->result = result;
	task = val->event->ev_sender;
	val->event->ev_sender = val;
	val->event->ev_type = DNS_EVENT_VALIDATORDONE;
	val->event->ev_action = val->action;
	val->event->ev_arg = val->arg;
	if ((val->attributes & VALATTR_NEGATIVE) != 0) {
		val->event->rdataset = NULL;
		val->event->sigrdataset = NULL;
		if (val->queryname != NULL)
			val->event->name = val->queryname;
	}
	isc_task_sendanddetach(&task, (isc_event_t **)&val->event);
	
}

static void
fetch_callback_validator(isc_task_t *task, isc_event_t *event) {
	dns_fetchevent_t *devent;
	dns_validator_t *val;
	dns_rdataset_t *rdataset;
	isc_result_t result;

	UNUSED(task);
	INSIST(event->ev_type == DNS_EVENT_FETCHDONE);
	devent = (dns_fetchevent_t *)event;
	val = devent->ev_arg;
	rdataset = devent->rdataset;

	validator_log(val, ISC_LOG_DEBUG(3), "in fetch_callback_validator");
	if (devent->result == ISC_R_SUCCESS) {
		LOCK(&val->lock);
		result = get_dst_key(val, val->siginfo, rdataset);
		if (result != ISC_R_SUCCESS) {
			/* No matching key */
			validator_done(val, result);
			UNLOCK(&val->lock);
			goto free_event;
		}
		if (val->attributes & VALATTR_NEGATIVE)
			result = nxtvalidate(val, ISC_TRUE);
		else
			result = validate(val, ISC_TRUE);
		if (result != DNS_R_WAIT) {
			validator_done(val, result);
			UNLOCK(&val->lock);
			goto free_event;
		}
		UNLOCK(&val->lock);
	} else
		validator_log(val, ISC_LOG_DEBUG(3),
			      "fetch_callback_validator: got %s",
			      dns_result_totext(devent->result));

 free_event:
	dns_resolver_destroyfetch(&val->fetch);
	/* free stuff from the event */
	isc_mem_put(val->view->mctx, devent->rdataset, sizeof(dns_rdataset_t));
	isc_mem_put(val->view->mctx, devent->sigrdataset,
		    sizeof(dns_rdataset_t));
	isc_event_free(&event);
}


static void
fetch_callback_nullkey(isc_task_t *task, isc_event_t *event) {
	dns_fetchevent_t *devent;
	dns_validator_t *val;
	dns_rdataset_t *rdataset, *sigrdataset;
	isc_result_t result;

	UNUSED(task);
	INSIST(event->ev_type == DNS_EVENT_FETCHDONE);
	devent = (dns_fetchevent_t *)event;
	val = devent->ev_arg;
	rdataset = devent->rdataset;
	sigrdataset = devent->sigrdataset;

	validator_log(val, ISC_LOG_DEBUG(3), "in fetch_callback_nullkey");
	if (devent->result == ISC_R_SUCCESS) {
		LOCK(&val->lock);
		if (!containsnullkey(val, rdataset)) {
			/* No null key */
			validator_log(val, ISC_LOG_DEBUG(3),
				      "found a keyset, no null key");
			result = proveunsecure(val, ISC_TRUE);
			if (result != DNS_R_WAIT)
				validator_done(val, ISC_R_SUCCESS);
		} else {
			validator_log(val, ISC_LOG_DEBUG(3),
				      "found a keyset with a null key");
			if (rdataset->trust >= dns_trust_secure)
				validator_done(val, ISC_R_SUCCESS);
			else if (!dns_rdataset_isassociated(sigrdataset))
				validator_done(val, ISC_R_FAILURE);
			else {
				dns_name_t *tname;
				tname = dns_fixedname_name(&devent->foundname);
				result = dns_validator_create(val->view,
							      tname,
							      dns_rdatatype_key,
							      rdataset,
							      sigrdataset,
							      NULL,
							      0,
							      val->task,
							      nullkeyvalidated,
							      val,
							      &val->keyvalidator);
				if (result != ISC_R_SUCCESS)
					validator_done(val, result);
				/*
				 * don't free these, since they'll be
				 * freed in nullkeyvalidated.
				 */
				devent->rdataset = NULL;
				devent->sigrdataset = NULL;
			}
		}
		UNLOCK(&val->lock);
	} else if (devent->result ==  DNS_R_NCACHENXDOMAIN ||
		   devent->result == DNS_R_NCACHENXRRSET ||
		   devent->result == DNS_R_NXDOMAIN ||
		   devent->result == DNS_R_NXRRSET)
	{
		/* No keys */
		validator_log(val, ISC_LOG_DEBUG(3),
			      "no keys found");
		LOCK(&val->lock);
		result = proveunsecure(val, ISC_TRUE);
		if (result != DNS_R_WAIT)
			validator_done(val, result);
		UNLOCK(&val->lock);
	} else
		validator_log(val, ISC_LOG_DEBUG(3),
			      "fetch_callback_nullkey: got %s",
			      dns_result_totext(devent->result));

	dns_resolver_destroyfetch(&val->fetch);

	/* free stuff from the event */
	if (devent->rdataset != NULL)
		isc_mem_put(val->view->mctx, devent->rdataset,
			    sizeof(dns_rdataset_t));
	if (devent->sigrdataset != NULL)
		isc_mem_put(val->view->mctx, devent->sigrdataset,
			    sizeof(dns_rdataset_t));
	isc_event_free(&event);
}

static void
keyvalidated(isc_task_t *task, isc_event_t *event) {
	dns_validatorevent_t *devent;
	dns_validator_t *val;
	dns_rdataset_t *rdataset;
	isc_result_t result;

	UNUSED(task);
	INSIST(event->ev_type == DNS_EVENT_VALIDATORDONE);
	devent = (dns_validatorevent_t *)event;
	rdataset = devent->rdataset;
	val = devent->ev_arg;

	validator_log(val, ISC_LOG_DEBUG(3), "in keyvalidated");
	if (devent->result == ISC_R_SUCCESS) {
		LOCK(&val->lock);
		result = get_dst_key(val, val->siginfo, rdataset);
		if (result != ISC_R_SUCCESS) {
			/* No matching key */
			validator_done(val, result);
			UNLOCK(&val->lock);
			goto free_event;
		}
		if (val->attributes & VALATTR_NEGATIVE)
			result = nxtvalidate(val, ISC_TRUE);
		else
			result = validate(val, ISC_TRUE);
		if (result != DNS_R_WAIT) {
			validator_done(val, result);
			UNLOCK(&val->lock);
			goto free_event;
		}
		UNLOCK(&val->lock);
	} else
		validator_log(val, ISC_LOG_DEBUG(3), 
			      "keyvalidated: got %s",
			      dns_result_totext(devent->result));
 free_event:
	dns_validator_destroy(&val->keyvalidator);
	/* free stuff from the event */
	isc_mem_put(val->view->mctx, devent->rdataset, sizeof(dns_rdataset_t));
	isc_mem_put(val->view->mctx, devent->sigrdataset,
		    sizeof(dns_rdataset_t));
	isc_event_free(&event);
}

static void
nullkeyvalidated(isc_task_t *task, isc_event_t *event) {
	dns_validatorevent_t *devent;
	dns_validator_t *val;
	dns_rdataset_t *rdataset;
	isc_result_t result;

	UNUSED(task);
	INSIST(event->ev_type == DNS_EVENT_VALIDATORDONE);
	devent = (dns_validatorevent_t *)event;
	rdataset = devent->rdataset;
	val = devent->ev_arg;

	validator_log(val, ISC_LOG_DEBUG(3), "in nullkeyvalidated");
	if (devent->result == ISC_R_SUCCESS) {
		validator_log(val, ISC_LOG_DEBUG(3),
			      "proved that name is in an unsecure domain");
		LOCK(&val->lock);
		validator_done(val, ISC_R_SUCCESS);
		UNLOCK(&val->lock);
	} else {
		LOCK(&val->lock);
		result = proveunsecure(val, ISC_TRUE);
		if (result != DNS_R_WAIT)
			validator_done(val, result);
		UNLOCK(&val->lock);
	}

	dns_validator_destroy(&val->keyvalidator);

	/* free stuff from the event */
	isc_mem_put(val->view->mctx, devent->rdataset, sizeof(dns_rdataset_t));
	isc_mem_put(val->view->mctx, devent->sigrdataset,
		    sizeof(dns_rdataset_t));
	dns_name_free(devent->name, val->view->mctx);
	isc_mem_put(val->view->mctx, devent->name, sizeof(dns_name_t));
	isc_event_free(&event);
}

/*
 * Try to find a null zone key among those in 'rdataset'.  If found, build
 * a dst_key_t for it and point val->key at it.
 */
static inline isc_boolean_t 
containsnullkey(dns_validator_t *val, dns_rdataset_t *rdataset) {
	isc_result_t result;
	dst_key_t *key = NULL;
	isc_buffer_t b;
	dns_rdata_t rdata;
	isc_boolean_t found = ISC_FALSE;

	result = dns_rdataset_first(rdataset);
	if (result != ISC_R_SUCCESS)
		return (ISC_FALSE);
	while (result == ISC_R_SUCCESS && !found) {
		dns_rdataset_current(rdataset, &rdata);
		isc_buffer_init(&b, rdata.data, rdata.length);
		isc_buffer_add(&b, rdata.length);
		key = NULL;
		/*
		 * The key name is unimportant, so we can avoid any name/text
		 * conversion.
		 */
		result = dst_key_fromdns("", &b, val->view->mctx, &key);
		if (result != ISC_R_SUCCESS)
			continue;
		if (dst_key_isnullkey(key))
			found = ISC_TRUE;
		dst_key_free(key);
		result = dns_rdataset_next(rdataset);
	}
	return (found);
}

/*
 * Try to find a key that could have signed 'siginfo' among those
 * in 'rdataset'.  If found, build a dst_key_t for it and point
 * val->key at it.
 *
 * XXX does not handle key tag collisions.
 */
static inline isc_result_t 
get_dst_key(dns_validator_t *val, dns_siginfo_t *siginfo,
	    dns_rdataset_t *rdataset)
{
	isc_result_t result;
	isc_buffer_t b;
	dns_rdata_t rdata;
	char ntext[1024];

	result = dns_rdataset_first(rdataset);
	if (result != ISC_R_SUCCESS)
		return (result);
	do {
		dns_rdataset_current(rdataset, &rdata);
		/*
		 * We keep one byte of ntext in reserve so
		 * we're sure we can NUL terminate.
		 */
		isc_buffer_init(&b, ntext, sizeof(ntext) - 1);
		result = dns_name_totext(&siginfo->signer, ISC_FALSE, &b);
		if (result != ISC_R_SUCCESS)
			return (result);

		/*
		 * NUL-terminate the character string.
		 */
		isc_buffer_putuint8(&b, 0);

		isc_buffer_init(&b, rdata.data, rdata.length);
		isc_buffer_add(&b, rdata.length);
		INSIST(val->key == NULL);
		result = dst_key_fromdns(ntext, &b, val->view->mctx,
					 &val->key);
		if (result != ISC_R_SUCCESS)
			return (result);
		if (siginfo->algorithm ==
		    (dns_secalg_t)dst_key_alg(val->key) &&
		    siginfo->tag ==
		    (dns_keytag_t)dst_key_id(val->key) &&
		    dst_key_iszonekey(val->key))
		{
			/*
			 * This is the key we're looking for.
			 */
			return (ISC_R_SUCCESS);
		}
		dst_key_free(val->key);
		val->key = NULL;
		result = dns_rdataset_next(rdataset);
	} while (result == ISC_R_SUCCESS);
	if (result == ISC_R_NOMORE)
		result = ISC_R_NOTFOUND;

	return (result);
}

static inline isc_result_t
get_key(dns_validator_t *val, dns_siginfo_t *siginfo) {
	isc_result_t result;
	dns_validatorevent_t *event;
	unsigned int nbits, nlabels;
	int order;
	dns_namereln_t namereln;
	dns_rdataset_t rdataset, sigrdataset;

	event = val->event;

	/*
	 * Is the key used for the signature a security root?
	 */
	INSIST(val->keynode == NULL);
	val->keytable = val->view->secroots;
	result = dns_keytable_findkeynode(val->view->secroots,
					  &siginfo->signer,
					  siginfo->algorithm, siginfo->tag,
					  &val->keynode);
	if (result == ISC_R_NOTFOUND) {
		/*
		 * Is it a trusted key that is not a security root?
		 */
		val->keytable = val->view->trustedkeys;
		result = dns_keytable_findkeynode(val->view->trustedkeys,
						  &siginfo->signer,
						  siginfo->algorithm,
						  siginfo->tag,
						  &val->keynode);
		if (result == ISC_R_SUCCESS) {
			/*
			 * The key is trusted.
			 */
			val->key = dns_keynode_key(val->keynode);
			return (ISC_R_SUCCESS);
		} else if (result != ISC_R_NOTFOUND)
			return (result);
	} else if (result == ISC_R_SUCCESS) {
		/*
		 * The key is a security root.
		 */
		val->key = dns_keynode_key(val->keynode);
		return (ISC_R_SUCCESS);
	} else
		return (result);

	/*
	 * The signature was not made with a security root or trusted key.
	 */

	/*
	 * Is the key name appropriate for this signature?
	 */
	namereln = dns_name_fullcompare(event->name, &siginfo->signer,
					&order, &nlabels, &nbits);
	if (event->rdataset->type == dns_rdatatype_key &&
	    namereln != dns_namereln_subdomain) {
		/*
		 * We don't want a KEY RR to authenticate
		 * itself, so we ignore the signature if it
		 * was not made by an ancestor of the KEY.
		 */
		return (DNS_R_CONTINUE);
	} else if (namereln != dns_namereln_subdomain &&
		   namereln != dns_namereln_equal) {
		/*
		 * The key name is not at the same level
		 * as 'rdataset', nor is it closer to the
		 * DNS root.
		 */
		return (DNS_R_CONTINUE);
	}

	/*
	 * Do we know about this key?
	 */
	dns_rdataset_init(&rdataset);
	dns_rdataset_init(&sigrdataset);
	result = dns_view_simplefind(val->view, &siginfo->signer,
				     dns_rdatatype_key, 0,
				     DNS_DBFIND_PENDINGOK, ISC_FALSE,
				     &rdataset, &sigrdataset);
	if (result == ISC_R_SUCCESS) {
		/*
		 * We have an rrset for the given keyname.
		 */
		if (rdataset.trust == dns_trust_pending) {
			/*
			 * We know the key but haven't validated it yet.
			 */
			dns_rdataset_t *frdataset, *fsigrdataset;
			frdataset = isc_mem_get(val->view->mctx,
						sizeof *frdataset);
			if (frdataset == NULL)
				return (ISC_R_NOMEMORY);
			fsigrdataset = isc_mem_get(val->view->mctx,
						   sizeof *fsigrdataset);
			if (fsigrdataset == NULL) {
				isc_mem_put(val->view->mctx, frdataset,
					    sizeof *frdataset);
				return (ISC_R_NOMEMORY);
			}
			dns_rdataset_init(frdataset);
			dns_rdataset_init(fsigrdataset);
			dns_rdataset_clone(&rdataset, frdataset);
			dns_rdataset_clone(&sigrdataset, fsigrdataset);

			result = dns_validator_create(val->view,
						      &siginfo->signer,
						      dns_rdatatype_key,
						      frdataset,
						      fsigrdataset,
						      NULL,
						      0,
						      val->task,
						      keyvalidated,
						      val,
						      &val->keyvalidator);
			if (result != ISC_R_SUCCESS)
				return (result);
			return (DNS_R_WAIT);
		} else {
			/*
			 * XXXRTH  What should we do if this is an untrusted
			 *         rdataset?
			 */
			/*
			 * See if we've got the key used in the signature.
			 */
			result = get_dst_key(val, siginfo, &rdataset);
			if (result != ISC_R_SUCCESS) {
				/*
				 * Either the key we're looking for is not
				 * in the rrset, or something bad happened.
				 * Give up.
				 */
				result = DNS_R_CONTINUE;
			}
		}
	} else if (result == ISC_R_NOTFOUND) {
		/*
		 * We don't know anything about this key.
		 */
		dns_rdataset_t *frdataset, *fsigrdataset;
		frdataset = isc_mem_get(val->view->mctx, sizeof *frdataset);
		if (frdataset == NULL)
			return (ISC_R_NOMEMORY);
		fsigrdataset = isc_mem_get(val->view->mctx,
					   sizeof *fsigrdataset);
		if (fsigrdataset == NULL) {
			isc_mem_put(val->view->mctx, frdataset,
				    sizeof *frdataset);
			return (ISC_R_NOMEMORY);
		}
		dns_rdataset_init(frdataset);
		dns_rdataset_init(fsigrdataset);
		val->fetch = NULL;
		result = dns_resolver_createfetch(val->view->resolver,
						  &siginfo->signer,
						  dns_rdatatype_key,
						  NULL, NULL, NULL, 0,
						  val->event->ev_sender,
						  fetch_callback_validator,
						  val,
						  frdataset,
						  fsigrdataset,
						  &val->fetch);
		if (result != ISC_R_SUCCESS)
			return (result);
		return (DNS_R_WAIT);
	} else if (result ==  DNS_R_NCACHENXDOMAIN ||
		   result == DNS_R_NCACHENXRRSET ||
		   result == DNS_R_NXDOMAIN ||
		   result == DNS_R_NXRRSET) {
		/*
		 * This key doesn't exist.
		 */
		result = DNS_R_CONTINUE;
	}

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	if (dns_rdataset_isassociated(&sigrdataset))
		dns_rdataset_disassociate(&sigrdataset);

	return (result);
}

static inline isc_result_t
validate(dns_validator_t *val, isc_boolean_t resume) {
	isc_result_t result;
	dns_validatorevent_t *event;
	dns_rdata_t rdata;

	/*
	 * Caller must be holding the validator lock.
	 */

	event = val->event;

	if (resume) {
		/* We alraedy have a sigrdataset. */
		result = ISC_R_SUCCESS;
	} else {
		result = dns_rdataset_first(event->sigrdataset);
	}

	for (;
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(event->sigrdataset))
	{
		dns_rdataset_current(event->sigrdataset, &rdata);
		if (val->siginfo != NULL)
			isc_mem_put(val->view->mctx, val->siginfo,
				    sizeof *val->siginfo);
		val->siginfo = isc_mem_get(val->view->mctx,
					   sizeof *val->siginfo);
		if (val->siginfo == NULL)
			return (ISC_R_NOMEMORY);
		rdata_to_siginfo(&rdata, val->siginfo);
		
		/*
		 * At this point we could check that the signature algorithm
		 * was known and "sufficiently good".  For now, any algorithm
		 * is acceptable.
		 */
		
		if (!resume) {
			result = get_key(val, val->siginfo);
			if (result == DNS_R_CONTINUE)
				continue; /* Try the next SIG RR. */
			if (result != ISC_R_SUCCESS)
				return (result);
		}
		INSIST(val->key != NULL);

		result = dns_dnssec_verify(event->name, event->rdataset,
					   val->key, ISC_FALSE, val->view->mctx,
					   &rdata);
		if (val->keynode != NULL)
			dns_keytable_detachkeynode(val->keytable,
						   &val->keynode);
		else if (val->key != NULL)
			dst_key_free(val->key);
		val->key = NULL;
		if (result == ISC_R_SUCCESS) {
			event->rdataset->trust = dns_trust_secure;
			event->sigrdataset->trust = dns_trust_secure;
			validator_log(val, ISC_LOG_DEBUG(3),
				      "marking as secure");
			return (result);
		}
		else
			validator_log(val, ISC_LOG_DEBUG(3),
				      "verify failure: %s",
				      dns_result_totext(result));
	}
	if (result == ISC_R_NOMORE)
		result = ISC_R_NOTFOUND;
	return (result);
}


static inline isc_result_t
nxtvalidate(dns_validator_t *val, isc_boolean_t resume) {
	dns_name_t *name;
	dns_rdata_t rdata;
	dns_message_t *message = val->event->message;
	isc_result_t result;
	int order;
	isc_region_t r;
	dns_name_t nextname;
	isc_boolean_t firstname = ISC_TRUE;

	if (!resume) {
		val->attributes |= VALATTR_NEGATIVE;
		result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
		if (result != ISC_R_SUCCESS)
			validator_done(val, ISC_R_NOTFOUND);
	} else
		result = ISC_R_SUCCESS;

	for (;
	     result == ISC_R_SUCCESS;
	     result = dns_message_nextname(message, DNS_SECTION_AUTHORITY))
	{
		dns_rdataset_t *rdataset, *sigrdataset = NULL;

		name = NULL;
		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &name);
		if (!resume || !firstname) {
			for (rdataset = ISC_LIST_HEAD(name->list);
			     rdataset != NULL;
			     rdataset = ISC_LIST_NEXT(rdataset, link))
			{
				if (rdataset->type != dns_rdatatype_nxt)
					continue;
				if (dns_rdataset_count(rdataset) != 1)
					return (DNS_R_FORMERR);
				for (sigrdataset = ISC_LIST_HEAD(name->list);
				     sigrdataset != NULL;
				     sigrdataset = ISC_LIST_NEXT(sigrdataset,
								 link))
				{
					if (sigrdataset->type ==
					    dns_rdatatype_sig
					    &&
					    sigrdataset->covers ==
					    dns_rdatatype_nxt)
						break;
				}
				if (sigrdataset != NULL)
					break;
			}
			if (rdataset == NULL)
				continue;
			val->event->rdataset = rdataset;
			val->event->sigrdataset = sigrdataset;
			val->queryname = val->event->name;
			val->event->name = name;
		}
		firstname = ISC_FALSE;
		order = dns_name_compare(val->queryname, val->event->name);
		if (order == 0) {
			if (val->event->type >= 128) {
				validator_log(val, ISC_LOG_DEBUG(3),
					      "invalid type %d",
					       val->event->type);
				continue;
			}
			result = dns_rdataset_first(val->event->rdataset);
			INSIST(result == ISC_R_SUCCESS);
			dns_rdataset_current(val->event->rdataset, &rdata);
			if (dns_nxt_typepresent(&rdata, val->event->type)) {
				validator_log(val, ISC_LOG_DEBUG(3),
					      "type should not be present");
				continue;
			}
			validator_log(val, ISC_LOG_DEBUG(3),
			      "nxt bitmask ok");
		} else if (order > 0) {
			result = dns_rdataset_first(val->event->rdataset);
			INSIST(result == ISC_R_SUCCESS);
			dns_rdataset_current(val->event->rdataset, &rdata);
			dns_rdata_toregion(&rdata, &r);
			dns_name_init(&nextname, NULL);
			dns_name_fromregion(&nextname, &r);
			order = dns_name_compare(val->queryname, &nextname);
			if (order >= 0) {
				if (val->siginfo == NULL) {
					dns_rdataset_t *sigset;
					dns_rdata_t sigrdata;

					sigset = val->event->sigrdataset;
					result = dns_rdataset_first(sigset);
					INSIST(result == ISC_R_SUCCESS);
					dns_rdata_init(&sigrdata);
					dns_rdataset_current(sigset, &sigrdata);
					val->siginfo = isc_mem_get(
							  val->view->mctx,
							  sizeof *val->siginfo);
					if (val->siginfo == NULL)
						return (ISC_R_NOMEMORY);
					rdata_to_siginfo(&sigrdata,
							 val->siginfo);
				}
				if (!dns_name_equal(&val->siginfo->signer,
						    &nextname))
				{
					validator_log(val, ISC_LOG_DEBUG(3),
						"next name is not greater");
					continue;
				}
				validator_log(val, ISC_LOG_DEBUG(3),
					      "nxt points to zone apex, ok");
			}
			validator_log(val, ISC_LOG_DEBUG(3),
				      "nxt range ok");
		} else {
			validator_log(val, ISC_LOG_DEBUG(3),
				"nxt owner name is not less");
			continue;
		}

		/*
		 * We found a NXT with acceptable contents; now check
		 * its signature.
		 */
		result = validate(val, resume);
		if (result != ISC_R_SUCCESS)
			return (result);

		return (ISC_R_SUCCESS);
	}
	validator_log(val, ISC_LOG_DEBUG(3),
		      "no relevant NXT found");
	return (result);
}

static inline isc_result_t
proveunsecure(dns_validator_t *val, isc_boolean_t resume) {
	isc_result_t result;
	dns_fixedname_t secroot, tfname;
	dns_name_t *tname;

	dns_fixedname_init(&secroot);
	dns_fixedname_init(&tfname);
	result = dns_keytable_finddeepestmatch(val->view->secroots,
					       val->event->name,
					       dns_fixedname_name(&secroot));
	if (result != ISC_R_SUCCESS)
		return (result);
	validator_log(val, ISC_LOG_DEBUG(3), "%s proveunsecure",
		      resume ? "resuming" : "in");

	if (!resume)
		val->labels = dns_name_depth(dns_fixedname_name(&secroot)) + 1;
	else
		val->labels++;
	for (;
	     val->labels <= dns_name_depth(val->event->name);
	     val->labels++)
	{
		dns_rdataset_t rdataset, sigrdataset;

		if (val->labels == dns_name_depth(val->event->name))
			tname = val->event->name;
		else {
			tname = dns_fixedname_name(&tfname);
			result = dns_name_splitatdepth(val->event->name,
						       val->labels,
						       NULL, tname);
			if (result != ISC_R_SUCCESS)
				return (result);
		}
		dns_rdataset_init(&rdataset);
		dns_rdataset_init(&sigrdataset);
		result = dns_view_simplefind(val->view, tname,
					     dns_rdatatype_key, 0,
					     DNS_DBFIND_PENDINGOK, ISC_FALSE,
					     &rdataset, &sigrdataset);
		if (result == ISC_R_SUCCESS) {
			dns_rdataset_t *frdataset = NULL, *fsigrdataset = NULL;
			dns_name_t *fname = NULL;

			if (!dns_rdataset_isassociated(&sigrdataset))
				return (ISC_R_FAILURE);
			validator_log(val, ISC_LOG_DEBUG(3),
				      "found keyset, looking for null key");
			if (!containsnullkey(val, &rdataset))
				continue;
		
			if (rdataset.trust >= dns_trust_secure)
				return (ISC_R_SUCCESS);

			frdataset = isc_mem_get(val->view->mctx,
						sizeof *frdataset);
			if (frdataset == NULL)
				return (ISC_R_NOMEMORY);
			fsigrdataset = isc_mem_get(val->view->mctx,
						  sizeof *fsigrdataset);
			if (fsigrdataset == NULL) {
				isc_mem_put(val->view->mctx, frdataset,
					    sizeof *frdataset);
				return (ISC_R_NOMEMORY);
			}
			fname = isc_mem_get(val->view->mctx, sizeof *fname);
			if (fname == NULL) {
				isc_mem_put(val->view->mctx, fsigrdataset,
					    sizeof *frdataset);
				isc_mem_put(val->view->mctx, frdataset,
					    sizeof *fsigrdataset);
				return (ISC_R_NOMEMORY);
			}
			dns_name_init(fname, NULL);
			result = dns_name_dup(tname, val->view->mctx, fname);
			if (result != ISC_R_SUCCESS) {
				isc_mem_put(val->view->mctx, fsigrdataset,
					    sizeof *frdataset);
				isc_mem_put(val->view->mctx, frdataset,
					    sizeof *fsigrdataset);
				return (ISC_R_NOMEMORY);
			}
			dns_rdataset_init(frdataset);
			dns_rdataset_init(fsigrdataset);
			dns_rdataset_clone(&rdataset, frdataset);
			dns_rdataset_clone(&sigrdataset, fsigrdataset);

			result = dns_validator_create(val->view,
						      fname,
						      dns_rdatatype_key,
						      frdataset,
						      fsigrdataset,
						      NULL,
						      0,
						      val->task,
						      nullkeyvalidated,
						      val,
						      &val->keyvalidator);
			return (DNS_R_WAIT);
		} else if (result == ISC_R_NOTFOUND) {
			dns_rdataset_t *frdataset = NULL, *fsigrdataset = NULL;

			frdataset = isc_mem_get(val->view->mctx,
						sizeof *frdataset);
			if (frdataset == NULL)
				return (ISC_R_NOMEMORY);
			fsigrdataset = isc_mem_get(val->view->mctx,
						  sizeof *fsigrdataset);
			if (fsigrdataset == NULL) {
				isc_mem_put(val->view->mctx, frdataset,
					    sizeof *frdataset);
				return (ISC_R_NOMEMORY);
			}
			dns_rdataset_init(frdataset);
			dns_rdataset_init(fsigrdataset);
			result = dns_resolver_createfetch(val->view->resolver,
							  tname,
							  dns_rdatatype_key,
							  NULL, NULL, NULL, 0,
							  val->event->ev_sender,
							  fetch_callback_nullkey,
							  val,
							  frdataset,
							  fsigrdataset,
							  &val->fetch);
			if (result != ISC_R_SUCCESS)
				return (result);
			return (DNS_R_WAIT);
		} else if (result == DNS_R_NCACHENXDOMAIN ||
			 result == DNS_R_NCACHENXRRSET ||
			 result == DNS_R_NXDOMAIN ||
			 result == DNS_R_NXRRSET)
		{
			continue;
		} else
			return (result);
	}
	return (ISC_R_FAILURE); /* Didn't find a null key */
}

static void
validator_start(isc_task_t *task, isc_event_t *event) {
	dns_validator_t *val;
	dns_validatorevent_t *vevent;
	isc_result_t result;

	UNUSED(task);
	REQUIRE(event->ev_type == DNS_EVENT_VALIDATORSTART);
	vevent = (dns_validatorevent_t *) event;
	val = vevent->validator;

	LOCK(&val->lock);

	if (val->event->rdataset != NULL && val->event->sigrdataset != NULL) {
		/*
		 * This looks like a simple validation.  We say "looks like"
		 * because we don't know if wildcards are involved yet so it
		 * could still get complicated.
		 */
		result = validate(val, ISC_FALSE);
	} else if (val->event->rdataset != NULL) {
		/*
		 * This is either an unsecure subdomain or a response from
		 * a broken server.
		 */
		result = proveunsecure(val, ISC_FALSE);
	} else if (val->event->rdataset == NULL &&
		 val->event->sigrdataset == NULL)
	{
		/*
		 * This is a nonexistence validation.
		 */
		result = nxtvalidate(val, ISC_FALSE);
	} else {
		/* This shouldn't happen */
		result = ISC_R_FAILURE; /* Keep compiler happy. */
		INSIST(0);
	}

	if (result != DNS_R_WAIT)
		validator_done(val, result);

	UNLOCK(&val->lock);
}

isc_result_t
dns_validator_create(dns_view_t *view, dns_name_t *name, dns_rdatatype_t type,
		     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset,
		     dns_message_t *message, unsigned int options,
		     isc_task_t *task, isc_taskaction_t action, void *arg,
		     dns_validator_t **validatorp)
{
	isc_result_t result;
	dns_validator_t *val;
	isc_task_t *tclone;
	dns_validatorevent_t *event;

	REQUIRE(name != NULL);
	REQUIRE(rdataset != NULL ||
		(rdataset == NULL && sigrdataset == NULL && message != NULL));
	REQUIRE(options == 0);
	REQUIRE(validatorp != NULL && *validatorp == NULL);

	tclone = NULL;
	result = ISC_R_FAILURE;

	val = isc_mem_get(view->mctx, sizeof *val);
	if (val == NULL)
		return (ISC_R_NOMEMORY);
	val->view = NULL;
	dns_view_attach(view, &val->view);
	event = (dns_validatorevent_t *)
		isc_event_allocate(view->mctx, task,
				   DNS_EVENT_VALIDATORSTART,
				   validator_start, NULL,
				   sizeof (dns_validatorevent_t));
	if (event == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup_val;
	}
	isc_task_attach(task, &tclone);
	event->validator = val;
	event->result = ISC_R_FAILURE;
	event->name = name;
	event->type = type;
	event->rdataset = rdataset;
	event->sigrdataset = sigrdataset;
	event->message = message;
	result = isc_mutex_init(&val->lock);
	if (result != ISC_R_SUCCESS)
		goto cleanup_event;
	val->event = event;
	val->options = options;
	val->attributes = 0;
	val->fetch = NULL;
	val->keyvalidator = NULL;
	val->keynode = NULL;
	val->key = NULL;
	val->siginfo = NULL;
	val->task = task;
	val->action = action;
	val->arg = arg;
	val->queryname = NULL;
	val->labels = 0;
	val->magic = VALIDATOR_MAGIC;

	isc_task_send(task, (isc_event_t **)&event);

	*validatorp = val;

	return (ISC_R_SUCCESS);

 cleanup_event:
	isc_task_detach(&tclone);
	isc_event_free((isc_event_t **)&val->event);

 cleanup_val:
	dns_view_detach(&val->view);
	isc_mem_put(view->mctx, val, sizeof *val);
	
	return (result);
}

void
dns_validator_cancel(dns_validator_t *validator) {
	isc_task_t *task;

	REQUIRE(VALID_VALIDATOR(validator));

	LOCK(&validator->lock);

	if (validator->event != NULL) {
		validator->event->result = ISC_R_CANCELED;
		task = validator->event->ev_sender;
		validator->event->ev_sender = validator;
		isc_task_sendanddetach(&task,
				       (isc_event_t **)&validator->event);

		if (validator->fetch != NULL)
			dns_resolver_cancelfetch(validator->fetch);

		if (validator->keyvalidator != NULL)
			dns_validator_cancel(validator->keyvalidator);
	}
	UNLOCK(&validator->lock);
}

static void
destroy(dns_validator_t *val) {
	isc_mem_t *mctx;

	REQUIRE(SHUTDOWN(val));
	REQUIRE(val->event == NULL);
	REQUIRE(val->fetch == NULL);

	if (val->keynode != NULL)
		dns_keytable_detachkeynode(val->keytable, &val->keynode);
	else if (val->key != NULL)
		dst_key_free(val->key);
	if (val->keyvalidator != NULL)
		dns_validator_destroy(&val->keyvalidator);
	mctx = val->view->mctx;
	if (val->siginfo != NULL)
		isc_mem_put(mctx, val->siginfo, sizeof *val->siginfo);
	isc_mutex_destroy(&val->lock);
	dns_view_detach(&val->view);
	val->magic = 0;
	isc_mem_put(mctx, val, sizeof *val);
}

void
dns_validator_destroy(dns_validator_t **validatorp) {
	dns_validator_t *val;
	isc_boolean_t want_destroy = ISC_FALSE;

	REQUIRE(validatorp != NULL);
	val = *validatorp;
	REQUIRE(VALID_VALIDATOR(val));

	LOCK(&val->lock);

	REQUIRE(val->event == NULL);

	val->attributes |= VALATTR_SHUTDOWN;
	if (val->fetch == NULL)
		want_destroy = ISC_TRUE;

	UNLOCK(&val->lock);

	if (want_destroy)
		destroy(val);

	*validatorp = NULL;
}



static void
validator_logv(dns_validator_t *val, isc_logcategory_t *category,
	   isc_logmodule_t *module, int level, const char *fmt, va_list ap)
{
	char msgbuf[2048];

	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);

	if (val->event != NULL && val->event->name != NULL &&
	    val->event->rdataset != NULL)
	{
		char namebuf[1024];
		char typebuf[256];
		isc_buffer_t b;
		isc_region_t r;
		
		dns_name_format(val->event->name, namebuf, sizeof(namebuf));

		isc_buffer_init(&b, (unsigned char *)typebuf, sizeof(typebuf));
		if (dns_rdatatype_totext(val->event->type, &b)
		    != ISC_R_SUCCESS)
		{
			isc_buffer_clear(&b);
			isc_buffer_putstr(&b, "<bad type>");
		}
		isc_buffer_usedregion(&b, &r);
		isc_log_write(dns_lctx, category, module, level,
			      "validating %s %.*s: %s", namebuf,
			      (int) r.length, (char *) r.base, msgbuf);
	} else {
		isc_log_write(dns_lctx, category, module, level,
			      "validator @%p: %s", val, msgbuf);
		
	}
}

static void
validator_log(dns_validator_t *val, int level, const char *fmt, ...)
{
        va_list ap;
	va_start(ap, fmt);
	validator_logv(val, DNS_LOGCATEGORY_DNSSEC,
		       DNS_LOGMODULE_VALIDATOR, level, fmt, ap);
	va_end(ap);
}

