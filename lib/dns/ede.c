/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <isc/mem.h>
#include <isc/util.h>

#include <dns/ede.h>

#define DNS_EDE_MAGIC	 ISC_MAGIC('E', 'D', 'E', '!')
#define DNS_EDE_VALID(v) ISC_MAGIC_VALID(v, DNS_EDE_MAGIC)

void
dns_ede_add(dns_edectx_t *edectx, uint16_t code, const char *text) {
	REQUIRE(DNS_EDE_VALID(edectx));

	size_t pos = 0;
	uint16_t becode = htobe16(code);
	dns_ednsopt_t *edns = NULL;
	size_t textlen = 0;

	for (pos = 0; pos < DNS_EDE_MAX_ERRORS; pos++) {
		edns = edectx->ede[pos];

		if (edns == NULL) {
			break;
		}

		if (memcmp(&becode, edns->value, sizeof(becode)) == 0) {
			isc_log_write(DNS_LOGCATEGORY_RESOLVER,
				      DNS_LOGMODULE_RESOLVER, ISC_LOG_DEBUG(1),
				      "ignoring duplicate ede %u %s", code,
				      text == NULL ? "(null)" : text);
			return;
		}
	}

	if (pos >= DNS_EDE_MAX_ERRORS) {
		isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_DEBUG(1), "too many ede, ignoring %u %s",
			      code, text == NULL ? "(null)" : text);
		return;
	}

	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
		      ISC_LOG_DEBUG(1), "set ede: info-code %u extra-text %s",
		      code, text == NULL ? "(null)" : text);

	if (text != NULL) {
		textlen = strlen(text);

		if (textlen > DNS_EDE_EXTRATEXT_LEN) {
			isc_log_write(DNS_LOGCATEGORY_RESOLVER,
				      DNS_LOGMODULE_RESOLVER, ISC_LOG_DEBUG(1),
				      "truncate EDE code %hu text: %s", code,
				      text);
			textlen = DNS_EDE_EXTRATEXT_LEN;
		}
	}

	edns = isc_mem_get(edectx->mctx,
			   sizeof(*edns) + sizeof(becode) + textlen);
	*edns = (dns_ednsopt_t){
		.code = DNS_OPT_EDE,
		.length = sizeof(becode) + textlen,
		.value = (uint8_t *)edns + sizeof(*edns),
	};

	memmove(edns->value, &becode, sizeof(becode));
	if (textlen > 0) {
		memmove(edns->value + sizeof(becode), text, textlen);
	}

	edectx->ede[pos] = edns;
}

void
dns_ede_init(isc_mem_t *mctx, dns_edectx_t *edectx) {
	REQUIRE(mctx != NULL);

	/*
	 * Memory context is assigned, not attached here,
	 * thus there's no detach in dns_ede_reset().
	 */
	*edectx = (dns_edectx_t){
		.magic = DNS_EDE_MAGIC,
		.mctx = mctx,
	};
}

void
dns_ede_reset(dns_edectx_t *edectx) {
	REQUIRE(DNS_EDE_VALID(edectx));

	for (size_t i = 0; i < DNS_EDE_MAX_ERRORS; i++) {
		dns_ednsopt_t *edns = edectx->ede[i];
		if (edns == NULL) {
			break;
		}

		isc_mem_put(edectx->mctx, edns, sizeof(*edns) + edns->length);
		edectx->ede[i] = NULL;
	}
}

void
dns_ede_invalidate(dns_edectx_t *edectx) {
	REQUIRE(DNS_EDE_VALID(edectx));

	dns_ede_reset(edectx);

	edectx->magic = 0;
	edectx->mctx = NULL;
}

void
dns_ede_copy(dns_edectx_t *edectx_to, dns_edectx_t *edectx_from) {
	REQUIRE(DNS_EDE_VALID(edectx_to));
	REQUIRE(DNS_EDE_VALID(edectx_from));

	size_t nextede = 0;

	for (nextede = 0; nextede < DNS_EDE_MAX_ERRORS; nextede++) {
		if (edectx_to->ede[nextede] == NULL) {
			break;
		}
	}

	for (size_t pos = 0; pos < DNS_EDE_MAX_ERRORS; pos++) {
		if (edectx_from->ede[pos] == NULL) {
			break;
		}

		if (nextede >= DNS_EDE_MAX_ERRORS) {
			isc_log_write(DNS_LOGCATEGORY_RESOLVER,
				      DNS_LOGMODULE_RESOLVER, ISC_LOG_DEBUG(1),
				      "too many ede from subfetch");
			break;
		}

		INSIST(edectx_to->ede[nextede] == NULL);

		dns_ednsopt_t *edns = isc_mem_get(
			edectx_to->mctx,
			sizeof(*edns) + edectx_from->ede[pos]->length);
		*edns = (dns_ednsopt_t){
			.code = DNS_OPT_EDE,
			.length = edectx_from->ede[pos]->length,
			.value = (uint8_t *)edns + sizeof(*edns),
		};
		memmove(edns->value, edectx_from->ede[pos]->value,
			edectx_from->ede[pos]->length);

		edectx_to->ede[nextede] = edns;
		nextede++;
	}
}
