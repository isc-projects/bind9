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

#include <stdbool.h>

#include <isc/buffer.h>
#include <isc/hex.h>
#include <isc/lex.h>
#include <isc/string.h>
#include <isc/util.h>

#define D ('0' - 0x0) /* ascii '0' to hex */
#define U ('A' - 0xA) /* ascii 'A' to hex */
#define L ('a' - 0xa) /* ascii 'a' to hex */

const uint8_t isc__hex_char[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, D, D, D, D, D, D, D, D, D, D, 0, 0, 0, 0, 0, 0, 0, U,
	U, U, U, U, U, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, L, L, L, L, L, L, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#undef D
#undef U
#undef L

/*
 * BEW: These static functions are copied from lib/dns/rdata.c.
 */
static isc_result_t
str_totext(const char *source, isc_buffer_t *target);

static isc_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length);

static const char upperhex[] = "0123456789ABCDEF";
static const char lowerhex[] = "0123456789abcdef";

static isc_result_t
hex_totext(isc_region_t *source, int wordlength, const char *wordbreak,
	   const char *hex, isc_buffer_t *target) {
	char buf[3];
	unsigned int loops = 0;

	if (wordlength < 2) {
		wordlength = 2;
	}

	memset(buf, 0, sizeof(buf));
	while (source->length > 0) {
		buf[0] = hex[(source->base[0] >> 4) & 0xf];
		buf[1] = hex[(source->base[0]) & 0xf];
		RETERR(str_totext(buf, target));
		isc_region_consume(source, 1);

		loops++;
		if (source->length != 0 && (int)((loops + 1) * 2) >= wordlength)
		{
			loops = 0;
			RETERR(str_totext(wordbreak, target));
		}
	}
	return ISC_R_SUCCESS;
}

isc_result_t
isc_hex_totext(isc_region_t *source, int wordlength, const char *wordbreak,
	       isc_buffer_t *target) {
	return hex_totext(source, wordlength, wordbreak, upperhex, target);
}

isc_result_t
isc_hex_totextlower(isc_region_t *source, int wordlength, const char *wordbreak,
		    isc_buffer_t *target) {
	return hex_totext(source, wordlength, wordbreak, lowerhex, target);
}

void
isc_hex_decodeinit(isc_hex_decodectx_t *ctx, int length, isc_buffer_t *target) {
	ctx->digits = 0;
	ctx->length = length;
	ctx->target = target;
}

isc_result_t
isc_hex_decodechar(isc_hex_decodectx_t *ctx, int c) {
	uint8_t hexval;

	hexval = isc_hex_char(c);
	if (hexval == 0) {
		return ISC_R_BADHEX;
	}
	ctx->val[ctx->digits++] = c - hexval;
	if (ctx->digits == 2) {
		unsigned char num;

		num = (ctx->val[0] << 4) + (ctx->val[1]);
		RETERR(mem_tobuffer(ctx->target, &num, 1));
		if (ctx->length >= 0) {
			if (ctx->length == 0) {
				return ISC_R_BADHEX;
			} else {
				ctx->length -= 1;
			}
		}
		ctx->digits = 0;
	}
	return ISC_R_SUCCESS;
}

isc_result_t
isc_hex_decodefinish(isc_hex_decodectx_t *ctx) {
	if (ctx->length > 0) {
		return ISC_R_UNEXPECTEDEND;
	}
	if (ctx->digits != 0) {
		return ISC_R_BADHEX;
	}
	return ISC_R_SUCCESS;
}

isc_result_t
isc_hex_tobuffer(isc_lex_t *lexer, isc_buffer_t *target, int length) {
	unsigned int before, after;
	isc_hex_decodectx_t ctx;
	isc_textregion_t *tr;
	isc_token_t token;
	bool eol;

	REQUIRE(length >= isc_one_or_more);

	isc_hex_decodeinit(&ctx, length, target);

	before = isc_buffer_usedlength(target);
	while (ctx.length != 0) {
		unsigned int i;

		if (length > 0) {
			eol = false;
		} else {
			eol = true;
		}
		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_string, eol));
		if (token.type != isc_tokentype_string) {
			break;
		}
		tr = &token.value.as_textregion;
		for (i = 0; i < tr->length; i++) {
			RETERR(isc_hex_decodechar(&ctx, tr->base[i]));
		}
	}
	after = isc_buffer_usedlength(target);
	if (ctx.length < 0) {
		isc_lex_ungettoken(lexer, &token);
	}
	RETERR(isc_hex_decodefinish(&ctx));
	if (length == isc_one_or_more && before == after) {
		return ISC_R_UNEXPECTEDEND;
	}
	return ISC_R_SUCCESS;
}

isc_result_t
isc_hex_decodestring(const char *cstr, isc_buffer_t *target) {
	isc_hex_decodectx_t ctx;

	isc_hex_decodeinit(&ctx, isc_zero_or_more, target);
	for (;;) {
		int c = *cstr++;
		if (c == '\0') {
			break;
		}
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			continue;
		}
		RETERR(isc_hex_decodechar(&ctx, c));
	}
	RETERR(isc_hex_decodefinish(&ctx));
	return ISC_R_SUCCESS;
}

static isc_result_t
str_totext(const char *source, isc_buffer_t *target) {
	unsigned int l;
	isc_region_t region;

	isc_buffer_availableregion(target, &region);
	l = strlen(source);

	if (l > region.length) {
		return ISC_R_NOSPACE;
	}

	memmove(region.base, source, l);
	isc_buffer_add(target, l);
	return ISC_R_SUCCESS;
}

static isc_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length) {
	isc_region_t tr;

	isc_buffer_availableregion(target, &tr);
	if (length > tr.length) {
		return ISC_R_NOSPACE;
	}
	memmove(tr.base, base, length);
	isc_buffer_add(target, length);
	return ISC_R_SUCCESS;
}
