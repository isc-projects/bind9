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

#include <isc/mem.h>
#include <isc/print.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dnssec.h>
#include <dns/events.h>
#include <dns/keytable.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/nxt.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>
#include <dns/resolver.h>
#include <dns/result.h>
#include <dns/validator.h>
#include <dns/view.h>

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
	dns_validator_t *		authvalidator;
	dns_keytable_t *		keytable;
	dns_keynode_t *			keynode;
	dst_key_t *			key;
	dns_siginfo_t *			siginfo;
	isc_task_t *			task;
	isc_taskaction_t		action;
	void *				arg;
	unsigned int			labels;
	dns_rdataset_t *		currentset;
	isc_boolean_t			seensig;
	dns_rdataset_t *		keyset;
};

#define VALIDATOR_MAGIC			0x56616c3fU	/* Val?. */
#define VALID_VALIDATOR(v)	 	ISC_MAGIC_VALID(v, VALIDATOR_MAGIC)

#define VALATTR_SHUTDOWN		0x01
#define VALATTR_FOUNDNONEXISTENCE	0x02
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
		validator_log(val, ISC_LOG_DEBUG(3),
			      "keyset with trust %d", rdataset->trust);
		result = get_dst_key(val, val->siginfo, rdataset);
		if (result != ISC_R_SUCCESS) {
			/*
			 * No matching key.
			 */
			validator_done(val, result);
			UNLOCK(&val->lock);
			goto free_event;
		}
		val->keyset = devent->rdataset;
		devent->rdataset = NULL;
		result = validate(val, ISC_TRUE);
		if (result != DNS_R_WAIT) {
			validator_done(val, result);
			UNLOCK(&val->lock);
			goto free_event;
		}
		UNLOCK(&val->lock);
	} else {
		validator_log(val, ISC_LOG_DEBUG(3),
			      "fetch_callback_validator: got %s",
			      dns_result_totext(devent->result));
		validator_done(val, devent->result);
	}

 free_event:
	dns_resolver_destroyfetch(&val->fetch);
	/*
	 * Free stuff from the event.
	 */
	if (devent->rdataset != NULL)
		isc_mem_put(val->view->mctx, devent->rdataset,
			    sizeof(dns_rdataset_t));
	if (devent->sigrdataset != NULL)
		isc_mem_put(val->view->mctx, devent->sigrdataset,
			    sizeof(dns_rdataset_t));
	isc_event_free(&event);
}


static void
fetch_callback_nullkey(isc_task_t *task, isc_event_t *event) {
	dns_fetchevent_t *devent;
	dns_validator_t *val;
	dns_rdataset_t *rdataset, *sigrdataset;
	dns_fetch_t *fetch;
	isc_result_t result;

	UNUSED(task);
	INSIST(event->ev_type == DNS_EVENT_FETCHDONE);
	devent = (dns_fetchevent_t *)event;
	val = devent->ev_arg;
	rdataset = devent->rdataset;
	sigrdataset = devent->sigrdataset;

	validator_log(val, ISC_LOG_DEBUG(3), "in fetch_callback_nullkey");
	fetch = val->fetch;
	val->fetch = NULL;
	if (devent->result == ISC_R_SUCCESS) {
		LOCK(&val->lock);
		if (!containsnullkey(val, rdataset)) {
			/*
			 * No null key.
			 */
			validator_log(val, ISC_LOG_DEBUG(3),
				      "found a keyset, no null key");
			result = proveunsecure(val, ISC_TRUE);
			if (result != DNS_R_WAIT)
				validator_done(val, result);
		} else {
			validator_log(val, ISC_LOG_DEBUG(3),
				      "found a keyset with a null key");
			if (rdataset->trust >= dns_trust_secure) {
				validator_log(val, ISC_LOG_DEBUG(3),
					      "insecurity proof succeeded");
				val->event->rdataset->trust = dns_trust_answer;
				validator_done(val, ISC_R_SUCCESS);
			} else if (!dns_rdataset_isassociated(sigrdataset)) {
				validator_log(val, ISC_LOG_DEBUG(3),
					      "insecurity proof failed");
				validator_done(val, DNS_R_NOTINSECURE);
			} else {
				dns_name_t *tname;
				tname = dns_fixedname_name(&devent->foundname);
				result = dns_validator_create(val->view, tname,
							   dns_rdatatype_key,
							   rdataset,
							   sigrdataset, NULL,
							   0, val->task,
							   nullkeyvalidated,
							   val,
							   &val->keyvalidator);
				if (result != ISC_R_SUCCESS)
					validator_done(val, result);
				/*
				 * Don't free these, since they'll be
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
		/*
		 * No keys.
		 */
		validator_log(val, ISC_LOG_DEBUG(3),
			      "no keys found");
		LOCK(&val->lock);
		result = proveunsecure(val, ISC_TRUE);
		if (result != DNS_R_WAIT)
			validator_done(val, result);
		UNLOCK(&val->lock);
	} else {
		validator_log(val, ISC_LOG_DEBUG(3),
			      "fetch_callback_nullkey: got %s",
			      dns_result_totext(devent->result));
		validator_done(val, devent->result);
	}

	dns_resolver_destroyfetch(&fetch);

	/*
	 * Free stuff from the event.
	 */
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
		validator_log(val, ISC_LOG_DEBUG(3),
			      "keyset with trust %d", rdataset->trust);
		result = get_dst_key(val, val->siginfo, rdataset);
		if (result != ISC_R_SUCCESS) {
			/*
			 * No matching key.
			 */
			validator_done(val, result);
			UNLOCK(&val->lock);
			goto free_event;
		}
		result = validate(val, ISC_TRUE);
		if (result != DNS_R_WAIT) {
			validator_done(val, result);
			UNLOCK(&val->lock);
			goto free_event;
		}
		UNLOCK(&val->lock);
	} else {
		validator_log(val, ISC_LOG_DEBUG(3), 
			      "keyvalidated: got %s",
			      dns_result_totext(devent->result));
		validator_done(val, devent->result);
	}

 free_event:
	dns_validator_destroy(&val->keyvalidator);
	/*
	 * free stuff from the event.
	 */
	isc_mem_put(val->view->mctx, devent->rdataset, sizeof(dns_rdataset_t));
	isc_mem_put(val->view->mctx, devent->sigrdataset,
		    sizeof(dns_rdataset_t));
	isc_event_free(&event);
}

static void
authvalidated(isc_task_t *task, isc_event_t *event) {
	dns_validatorevent_t *devent;
	dns_validator_t *val;
	dns_rdataset_t *rdataset, *sigrdataset;
	isc_result_t result;

	UNUSED(task);
	INSIST(event->ev_type == DNS_EVENT_VALIDATORDONE);
	devent = (dns_validatorevent_t *)event;
	rdataset = devent->rdataset;
	sigrdataset = devent->sigrdataset;
	val = devent->ev_arg;

	validator_log(val, ISC_LOG_DEBUG(3), "in authvalidated");
	if (devent->result != ISC_R_SUCCESS) {
		validator_log(val, ISC_LOG_DEBUG(3), 
			      "authvalidated: got %s",
			      dns_result_totext(devent->result));
		validator_done(val, devent->result);
		goto free_event;
	}

	if (rdataset->type == dns_rdatatype_nxt) {
		int order;
		dns_rdata_t rdata;
		isc_region_t r;
		dns_name_t nextname;

		validator_log(val, ISC_LOG_DEBUG(3),
			      "authvalidated looking for relevant nxt");
		order = dns_name_compare(val->event->name, devent->name);
		if (order == 0) {
			if (val->event->type >= 128) {
				validator_log(val, ISC_LOG_DEBUG(3),
					      "invalid type %d",
					      val->event->type);
				goto out;
			}
			result = dns_rdataset_first(devent->rdataset);
			INSIST(result == ISC_R_SUCCESS);
			dns_rdataset_current(devent->rdataset, &rdata);
			if (dns_nxt_typepresent(&rdata, val->event->type)) {
				validator_log(val, ISC_LOG_DEBUG(3),
					      "type should not be present");
				goto out;
			}
			validator_log(val, ISC_LOG_DEBUG(3),
			      "nxt bitmask ok");
		} else if (order > 0) {
			result = dns_rdataset_first(devent->rdataset);
			INSIST(result == ISC_R_SUCCESS);
			dns_rdataset_current(devent->rdataset, &rdata);
			dns_rdata_toregion(&rdata, &r);
			dns_name_init(&nextname, NULL);
			dns_name_fromregion(&nextname, &r);
			order = dns_name_compare(val->event->name, &nextname);
			if (order >= 0) {
				dns_siginfo_t *siginfo;
				siginfo = devent->validator->siginfo;
				if (!dns_name_equal(&siginfo->signer,
						    &nextname))
				{
					validator_log(val, ISC_LOG_DEBUG(3),
						"next name is not greater");
					goto out;
				}
				validator_log(val, ISC_LOG_DEBUG(3),
					      "nxt points to zone apex, ok");
			}
			validator_log(val, ISC_LOG_DEBUG(3),
				      "nxt range ok");
		} else {
			validator_log(val, ISC_LOG_DEBUG(3),
				"nxt owner name is not less");
			goto out;
		}
		val->attributes |= VALATTR_FOUNDNONEXISTENCE;
	out: ;
	}

	isc_event_free(&event);
	dns_validator_destroy(&val->authvalidator);
	LOCK(&val->lock);
	result = nxtvalidate(val, ISC_TRUE);
	if (result != DNS_R_WAIT)
		validator_done(val, result);
	UNLOCK(&val->lock);
	return;

 free_event:
	/*
	 * free stuff from the event.
	 */
	isc_event_free(&event);
	dns_validator_destroy(&val->authvalidator);
}

static void
negauthvalidated(isc_task_t *task, isc_event_t *event) {
	dns_validatorevent_t *devent;
	dns_validator_t *val;
	dns_rdataset_t *rdataset;

	UNUSED(task);
	INSIST(event->ev_type == DNS_EVENT_VALIDATORDONE);
	devent = (dns_validatorevent_t *)event;
	rdataset = devent->rdataset;
	val = devent->ev_arg;

	validator_log(val, ISC_LOG_DEBUG(3), "in negauthvalidated");
	if (devent->result != ISC_R_SUCCESS) {
		validator_log(val, ISC_LOG_DEBUG(3), 
			      "negauthvalidated: got %s",
			      dns_result_totext(devent->result));
		validator_done(val, devent->result);
		goto free_event;
	}

	isc_mem_put(val->view->mctx, rdataset, sizeof *rdataset);
	isc_event_free(&event);
	dns_validator_destroy(&val->authvalidator);
	LOCK(&val->lock);
	val->attributes |= VALATTR_FOUNDNONEXISTENCE;

	validator_log(val, ISC_LOG_DEBUG(3), "nonexistence proof found");
	validator_done(val, ISC_R_SUCCESS);
	UNLOCK(&val->lock);
	return;

 free_event:
	/*
	 * free stuff from the event.
	 */
	isc_mem_put(val->view->mctx, rdataset, sizeof *rdataset);
	isc_event_free(&event);
	dns_validator_destroy(&val->authvalidator);
}

static void
nullkeyvalidated(isc_task_t *task, isc_event_t *event) {
	dns_validatorevent_t *devent;
	dns_validator_t *val;
	isc_result_t result;

	UNUSED(task);
	INSIST(event->ev_type == DNS_EVENT_VALIDATORDONE);
	devent = (dns_validatorevent_t *)event;
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

	/*
	 * free stuff from the event.
	 */
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
		dst_key_free(&key);
		result = dns_rdataset_next(rdataset);
	}
	return (found);
}

/*
 * Try to find a key that could have signed 'siginfo' among those
 * in 'rdataset'.  If found, build a dst_key_t for it and point
 * val->key at it.
 *
 * If val->key is non-NULL, this returns the next matching key.
 */
static inline isc_result_t 
get_dst_key(dns_validator_t *val, dns_siginfo_t *siginfo,
	    dns_rdataset_t *rdataset)
{
	isc_result_t result;
	isc_buffer_t b;
	dns_rdata_t rdata;
	char ntext[1024];
	dst_key_t *oldkey = val->key;
	isc_boolean_t foundold;

	if (oldkey == NULL)
		foundold = ISC_TRUE;
	else {
		foundold = ISC_FALSE;
		val->key = NULL;
	}

	result = dns_rdataset_first(rdataset);
	if (result != ISC_R_SUCCESS)
		goto failure;
	do {
		dns_rdataset_current(rdataset, &rdata);
		/*
		 * We keep one byte of ntext in reserve so
		 * we're sure we can NUL terminate.
		 */
		isc_buffer_init(&b, ntext, sizeof(ntext) - 1);
		result = dns_name_totext(&siginfo->signer, ISC_FALSE, &b);
		if (result != ISC_R_SUCCESS)
			goto failure;

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
			goto failure;
		if (siginfo->algorithm ==
		    (dns_secalg_t)dst_key_alg(val->key) &&
		    siginfo->tag ==
		    (dns_keytag_t)dst_key_id(val->key) &&
		    dst_key_iszonekey(val->key))
		{
			if (foundold)
				/*
				 * This is the key we're looking for.
				 */
				return (ISC_R_SUCCESS);
			else if (dst_key_compare(oldkey, val->key) == ISC_TRUE)
			{
				foundold = ISC_TRUE;
				dst_key_free(&oldkey);
			}
		}
		dst_key_free(&val->key);
		result = dns_rdataset_next(rdataset);
	} while (result == ISC_R_SUCCESS);
	if (result == ISC_R_NOMORE)
		result = ISC_R_NOTFOUND;

 failure:
	if (oldkey != NULL)
		dst_key_free(&oldkey);

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
	 * Is the key used for the signature a security root?
	 */
	INSIST(val->keynode == NULL);
	val->keytable = val->view->secroots;
	result = dns_keytable_findkeynode(val->view->secroots,
					  &siginfo->signer,
					  siginfo->algorithm, siginfo->tag,
					  &val->keynode);
	if (result == ISC_R_SUCCESS) {
		/*
		 * The key is a security root.
		 */
		val->key = dns_keynode_key(val->keynode);
		return (ISC_R_SUCCESS);
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
		if (rdataset.trust == dns_trust_pending &&
		    dns_rdataset_isassociated(&sigrdataset))
		{
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
		} else if (rdataset.trust == dns_trust_pending) {
			/*
			 * Having a pending key with no signature means that
			 * something is broken.
			 */
			result = DNS_R_CONTINUE;
		} else if (rdataset.trust < dns_trust_secure) {
			/*
			 * The key is legitimately insecure.  There's no
			 * point in even attempting verification.
			 */
			val->key = NULL;
			result = ISC_R_SUCCESS;
		} else {
			/*
			 * See if we've got the key used in the signature.
			 */
			validator_log(val, ISC_LOG_DEBUG(3),
				      "keyset with trust %d", rdataset.trust);
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
		   result == DNS_R_NXRRSET)
	{
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

/*
 * Attempts positive response validation.
 *
 * Returns:
 *	ISC_R_SUCCESS	Validation completed successfully
 *	DNS_R_WAIT	Validation has started but is waiting
 *			for an event.
 *	Other return codes are possible and all indicate failure.
 */
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
		/*
		 * We already have a sigrdataset.
		 */
		result = ISC_R_SUCCESS;
		validator_log(val, ISC_LOG_DEBUG(3), "resuming validate");
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

		if (val->key == NULL) {
			event->rdataset->trust = dns_trust_answer;
			event->sigrdataset->trust = dns_trust_answer;
			validator_log(val, ISC_LOG_DEBUG(3),
				      "marking as answer");
			return (ISC_R_SUCCESS);

		}

		do {
			result = dns_dnssec_verify(event->name,
						   event->rdataset,
						   val->key, ISC_FALSE,
						   val->view->mctx, &rdata);
			validator_log(val, ISC_LOG_DEBUG(3),
				      "verify rdataset: %s",
				      isc_result_totext(result));
			if (result == ISC_R_SUCCESS)
				break;
			if (val->keynode != NULL) {
				dns_keynode_t *nextnode = NULL;
				result = dns_keytable_findnextkeynode(
							val->keytable,
							val->keynode,
							&nextnode);
				dns_keytable_detachkeynode(val->keytable,
							   &val->keynode);
				val->keynode = nextnode;
				if (result != ISC_R_SUCCESS) {
					val->key = NULL;
					break;
				}
				val->key = dns_keynode_key(val->keynode);
			} else {
				if (get_dst_key(val, val->siginfo, val->keyset)
				    != ISC_R_SUCCESS)
					break;
			}
		} while (1);
		if (result != ISC_R_SUCCESS)
			validator_log(val, ISC_LOG_DEBUG(3),
				      "failed to verify rdataset");
		if (val->keynode != NULL)
			dns_keytable_detachkeynode(val->keytable,
						   &val->keynode);
		else {
			if (val->key != NULL)
				dst_key_free(&val->key);
			if (val->keyset != NULL)
				isc_mem_put(val->view->mctx, val->keyset,
					    sizeof *val->keyset);
				val->keyset = NULL;
		}
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
				      isc_result_totext(result));
	}
	INSIST(result == ISC_R_NOMORE);

	validator_log(val, ISC_LOG_INFO, "no valid signature found");
	return (DNS_R_NOVALIDSIG);
}


static inline isc_result_t
nxtvalidate(dns_validator_t *val, isc_boolean_t resume) {
	dns_name_t *name;
	dns_message_t *message = val->event->message;
	isc_result_t result;

	if (!resume) {
		result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
		if (result != ISC_R_SUCCESS)
			validator_done(val, ISC_R_NOTFOUND);
	} else {
		result = ISC_R_SUCCESS;
		validator_log(val, ISC_LOG_DEBUG(3), "resuming nxtvalidate");
	}

	for (;
	     result == ISC_R_SUCCESS;
	     result = dns_message_nextname(message, DNS_SECTION_AUTHORITY))
	{
		dns_rdataset_t *rdataset = NULL, *sigrdataset = NULL;

		name = NULL;
		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &name);
		if (resume) {
			rdataset = ISC_LIST_NEXT(val->currentset, link);
			val->currentset = NULL;
			resume = ISC_FALSE;
		}
		else {
			for (rdataset = ISC_LIST_HEAD(name->list);
			     rdataset != NULL;
			     rdataset = ISC_LIST_NEXT(rdataset, link))
				rdataset->trust = dns_trust_pending;

			rdataset = ISC_LIST_HEAD(name->list);
		}

		for (;
		     rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link))
		{
			if (rdataset->type == dns_rdatatype_sig)
				continue;

			for (sigrdataset = ISC_LIST_HEAD(name->list);
			     sigrdataset != NULL;
			     sigrdataset = ISC_LIST_NEXT(sigrdataset,
							 link))
			{
				if (sigrdataset->type == dns_rdatatype_sig &&
				    sigrdataset->covers == rdataset->type)
					break;
			}
			if (sigrdataset == NULL)
				continue;
			val->seensig = ISC_TRUE;
			val->authvalidator = NULL;
			val->currentset = rdataset;
			result = dns_validator_create(val->view, name,
						      rdataset->type,
						      rdataset,
						      sigrdataset,
						      NULL, 0,
						      val->task,
						      authvalidated,
						      val,
						      &val->authvalidator);
			if (result != ISC_R_SUCCESS)
				return (result);
			return (DNS_R_WAIT);
						      
		}
	}
	if (result == ISC_R_NOMORE)
		result = ISC_R_SUCCESS;
	if (result != ISC_R_SUCCESS)
		validator_done(val, result);

	if ((val->attributes & VALATTR_FOUNDNONEXISTENCE) == 0) {
		if (!val->seensig) {
			dns_rdataset_t *rdataset;
			rdataset = isc_mem_get(val->view->mctx,
					       sizeof(dns_rdataset_t));
			if (rdataset == NULL)
				return (ISC_R_NOMEMORY);
			dns_rdataset_init(rdataset);
			result = dns_validator_create(val->view, name,
						      dns_rdatatype_soa,
						      rdataset,
						      NULL, NULL, 0,
						      val->task,
						      negauthvalidated,
						      val,
						      &val->authvalidator);
			if (result != ISC_R_SUCCESS)
				return (result);
			return (DNS_R_WAIT);
		}
		validator_log(val, ISC_LOG_DEBUG(3),
			      "nonexistence proof not found");
		return (DNS_R_NOVALIDNXT);
	} else {
		validator_log(val, ISC_LOG_DEBUG(3),
			      "nonexistence proof found");
		return (ISC_R_SUCCESS);
	}

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

	if (!resume)
		val->labels = dns_name_depth(dns_fixedname_name(&secroot)) + 1;
	else {
		validator_log(val, ISC_LOG_DEBUG(3), "resuming proveunsecure");
		val->labels++;
	}

	for (;
	     val->labels <= dns_name_depth(val->event->name);
	     val->labels++)
	{
		dns_rdataset_t rdataset, sigrdataset;

		if (val->labels == dns_name_depth(val->event->name)) {
			if (val->event->type == dns_rdatatype_key)
				break;
			tname = val->event->name;
		} else {
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
				return (DNS_R_NOTINSECURE);
			validator_log(val, ISC_LOG_DEBUG(3),
				      "found keyset, looking for null key");
			if (!containsnullkey(val, &rdataset))
				continue;
		
			if (rdataset.trust >= dns_trust_secure) {
				validator_log(val, ISC_LOG_DEBUG(3),
					      "insecurity proof succeeded");
				val->event->rdataset->trust = dns_trust_answer;
				return (ISC_R_SUCCESS);
			}

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
				isc_mem_put(val->view->mctx, fname,
					    sizeof *fname);
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
			val->fetch = NULL;
			result = dns_resolver_createfetch(val->view->resolver,
							tname,
							dns_rdatatype_key,
							NULL, NULL, NULL, 0,
							val->event->ev_sender,
							fetch_callback_nullkey,
							val, frdataset,
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
	validator_log(val, ISC_LOG_DEBUG(3), "insecurity proof failed");
	return (DNS_R_NOTINSECURE); /* Didn't find a null key */
}

static void
validator_start(isc_task_t *task, isc_event_t *event) {
	dns_validator_t *val;
	dns_validatorevent_t *vevent;
	isc_result_t result = ISC_R_FAILURE;

	UNUSED(task);
	REQUIRE(event->ev_type == DNS_EVENT_VALIDATORSTART);
	vevent = (dns_validatorevent_t *) event;
	val = vevent->validator;

	validator_log(val, ISC_LOG_DEBUG(3), "starting");
	
	LOCK(&val->lock);

	if (val->event->rdataset != NULL && val->event->sigrdataset != NULL) {
		/*
		 * This looks like a simple validation.  We say "looks like"
		 * because we don't know if wildcards are involved yet so it
		 * could still get complicated.
		 */
		validator_log(val, ISC_LOG_DEBUG(3),
			      "attempting positive response validation");
	
		result = validate(val, ISC_FALSE);
	} else if (val->event->rdataset != NULL) {
		/*
		 * This is either an unsecure subdomain or a response from
		 * a broken server.
		 */
		validator_log(val, ISC_LOG_DEBUG(3),
			      "attempting insecurity proof");
	
		result = proveunsecure(val, ISC_FALSE);
	} else if (val->event->rdataset == NULL &&
		 val->event->sigrdataset == NULL)
	{
		/*
		 * This is a nonexistence validation.
		 */
		validator_log(val, ISC_LOG_DEBUG(3),
			      "attempting negative response validation");
	
		result = nxtvalidate(val, ISC_FALSE);
	} else {
		/*
		 * This shouldn't happen.
		 */
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
	REQUIRE(type != 0);
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
	val->authvalidator = NULL;
	val->keynode = NULL;
	val->key = NULL;
	val->siginfo = NULL;
	val->task = task;
	val->action = action;
	val->arg = arg;
	val->labels = 0;
	val->currentset = NULL;
	val->keyset = NULL;
	val->seensig = ISC_FALSE;
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
#if 0
	REQUIRE(val->currentset == NULL);
#endif

	if (val->keynode != NULL)
		dns_keytable_detachkeynode(val->keytable, &val->keynode);
	else if (val->key != NULL)
		dst_key_free(&val->key);
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

	if (val->event != NULL && val->event->name != NULL) {
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

