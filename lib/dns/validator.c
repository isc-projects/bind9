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

#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/stdtime.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/validator.h>
#include <dns/db.h>
#include <dns/dnssec.h>
#include <dns/events.h>
#include <dns/keytable.h>
#include <dns/log.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatatype.h>
#include <dns/rdataset.h>
#include <dns/resolver.h>
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
};

#define VALIDATOR_MAGIC			0x56616c3fU	/* Val?. */
#define VALID_VALIDATOR(v)	 	ISC_MAGIC_VALID(v, VALIDATOR_MAGIC)

#define VALATTR_SHUTDOWN		0x01
#define SHUTDOWN(v)		(((v)->attributes & VALATTR_SHUTDOWN) != 0)

static inline isc_result_t get_dst_key(dns_validator_t *val,
				       dns_siginfo_t *siginfo,
				       dns_rdataset_t *rdataset);
static inline isc_result_t validate(dns_validator_t *val, isc_boolean_t resume);

static void validator_log(dns_validator_t *val, int level,
			  const char *fmt, ...);

static void
rdata_to_siginfo(dns_rdata_t *rdata, dns_siginfo_t *siginfo) {
	isc_buffer_t b;
	isc_region_t r;

	REQUIRE(rdata->type == 24);

	isc_buffer_init(&b, rdata->data, rdata->length, ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&b, rdata->length);
	siginfo->covers = (dns_rdatatype_t)isc_buffer_getuint16(&b);
	siginfo->algorithm = (dns_secalg_t)isc_buffer_getuint8(&b);
	siginfo->labels = isc_buffer_getuint8(&b);
	siginfo->original_ttl = (dns_ttl_t)isc_buffer_getuint32(&b);
	siginfo->expiration = (isc_stdtime_t)isc_buffer_getuint32(&b);
	siginfo->inception = (isc_stdtime_t)isc_buffer_getuint32(&b);
	siginfo->tag = (dns_keytag_t)isc_buffer_getuint16(&b);
	dns_name_init(&siginfo->signer, NULL);
	isc_buffer_remaining(&b, &r);
	dns_name_fromregion(&siginfo->signer, &r);
	isc_buffer_forward(&b, siginfo->signer.length);
	isc_buffer_remaining(&b, &siginfo->signature);
}

static void
validator_done(dns_validator_t *val, isc_result_t result) {
	isc_task_t *task;

	REQUIRE(val->event != NULL);

	/*
	 * Caller must be holding the lock.
	 */

	val->event->result = result;
	task = val->event->sender;
	val->event->sender = val;
	val->event->type = DNS_EVENT_VALIDATORDONE;
	val->event->action = val->action;
	val->event->arg = val->arg;
	isc_task_sendanddetach(&task, (isc_event_t **)&val->event);
	
}

static void
fetch_callback_validator(isc_task_t *task, isc_event_t *event) {
	dns_fetchevent_t *devent;
	dns_validator_t *val;
	dns_rdataset_t *rdataset;
	isc_result_t result;

	UNUSED(task);
	INSIST(event->type == DNS_EVENT_FETCHDONE);
	devent = (dns_fetchevent_t *)event;
	val = devent->arg;
	rdataset = devent->rdataset;

	validator_log(val, ISC_LOG_DEBUG(3), "in fetch_callback_validator");
	if (devent->result == ISC_R_SUCCESS) {
		result = get_dst_key(val, val->siginfo, rdataset);
		if (result != ISC_R_SUCCESS) {
			/* No matching key */
			validator_done(val, result);
			goto free_event;
		}
		LOCK(&val->lock);
		result = validate(val, ISC_TRUE);
		if (result != DNS_R_CONTINUE) {
			validator_done(val, result);
			goto free_event;
		}
		UNLOCK(&val->lock);
	}
	else
		validator_log(val, ISC_LOG_DEBUG(3),
			      "fetch_callback_validator: got %s",
			      dns_result_totext(devent->result));

 free_event:
	/* free stuff from the event */
	isc_event_free(&event);
}

static void
keyvalidated(isc_task_t *task, isc_event_t *event) {
	dns_validatorevent_t *devent;
	dns_validator_t *val;
	dns_rdataset_t *rdataset;
	isc_result_t result;

	UNUSED(task);
	INSIST(event->type == DNS_EVENT_VALIDATORDONE);
	devent = (dns_validatorevent_t *)event;
	rdataset = devent->rdataset;
	val = devent->arg;

	validator_log(val, ISC_LOG_DEBUG(3), "in keyvalidated");
	if (devent->result == ISC_R_SUCCESS) {
		result = get_dst_key(val, val->siginfo, rdataset);
		if (result != ISC_R_SUCCESS) {
			/* No matching key */
			validator_done(val, result);
			goto free_event;
		}
		LOCK(&val->lock);
		result = validate(val, ISC_TRUE);
		if (result != DNS_R_WAIT)
			validator_done(val, result);
		UNLOCK(&val->lock);
	}
	else
		validator_log(val, ISC_LOG_DEBUG(3), 
			      "keyvalidated: got %s",
			      dns_result_totext(devent->result));
 free_event:
	/* free stuff from the event */
	isc_mem_put(devent->validator->view->mctx, devent->rdataset,
		    sizeof(dns_rdataset_t));
	isc_mem_put(devent->validator->view->mctx, devent->sigrdataset,
		    sizeof(dns_rdataset_t));
	isc_event_free(&event);
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
		isc_buffer_init(&b, ntext, sizeof(ntext) - 1,
				ISC_BUFFERTYPE_TEXT);
		result = dns_name_totext(&siginfo->signer, ISC_FALSE, &b);
		if (result != ISC_R_SUCCESS)
			return (result);

		/*
		 * NUL-terminate the character string.
		 */
		isc_buffer_putuint8(&b, 0);

		isc_buffer_init(&b, rdata.data, rdata.length,
				ISC_BUFFERTYPE_BINARY);
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
		    dst_key_iszonekey(val->key) &&
		    dst_key_proto(val->key) == DST_KEYPROTO_DNSSEC) {
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
						  val->event->sender,
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
					   val->key, val->view->mctx, &rdata);
		if (result == ISC_R_SUCCESS) {
			event->rdataset->trust = dns_trust_secure;
			event->sigrdataset->trust = dns_trust_secure;
			validator_log(val, ISC_LOG_DEBUG(3),
				      "marking as secure");
			return (result);
		}
	}
	return (result);
}

static void
validator_start(isc_task_t *task, isc_event_t *event) {
	dns_validator_t *val;
	dns_validatorevent_t *vevent;
	isc_result_t result;

	UNUSED(task);
	REQUIRE(event->type == DNS_EVENT_VALIDATORSTART);
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
	} else {
		/*
		 * This is a nonexistence validation.
		 */
		result = ISC_R_NOTIMPLEMENTED;
	}

	if (result != DNS_R_WAIT)
		validator_done(val, result);

	UNLOCK(&val->lock);
}

isc_result_t
dns_validator_create(dns_view_t *view, dns_name_t *name,
		     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset,
		     dns_message_t *message, unsigned int options,
		     isc_task_t *task, isc_taskaction_t action, void *arg,
		     dns_validator_t **validatorp)
{
	isc_result_t result;
	dns_validator_t *val;
	isc_task_t *tclone;
	dns_validatorevent_t *event;

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
	val->task = task;
	val->action = action;
	val->arg = arg;
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
		task = validator->event->sender;
		validator->event->sender = validator;
		isc_task_sendanddetach(&task,
				       (isc_event_t **)&validator->event);
		/*
		 * XXXRTH  Do other cancelation stuff here.
		 */
	}
	UNLOCK(&validator->lock);
}

static void
destroy(dns_validator_t *val) {
	isc_mem_t *mctx;

	REQUIRE(SHUTDOWN(val));
	REQUIRE(val->event == NULL);
	REQUIRE(val->fetch == NULL);

	if (val->key != NULL)
		dst_key_free(val->key);
	if (val->keynode != NULL)
		dns_keytable_detachkeynode(val->keytable, &val->keynode);
	isc_mutex_destroy(&val->lock);
	mctx = val->view->mctx;
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

		isc_buffer_init(&b, (unsigned char *) typebuf, sizeof(typebuf),
				ISC_BUFFERTYPE_TEXT);
		if (dns_rdatatype_totext(val->event->rdataset->type, &b)
		    != ISC_R_SUCCESS)
		{
			isc_buffer_clear(&b);
			RUNTIME_CHECK(isc_buffer_putstr(&b, "<bad type>")
				      == ISC_R_SUCCESS);
		}
		isc_buffer_used(&b, &r);
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

