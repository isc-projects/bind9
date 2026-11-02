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

#pragma once

/*! \file
 * \brief
 * Bracketed token lists.
 *
 * The contents of the "{ ... }" block of a "plugin" or "dyndb" statement
 * are lexed, but not parsed, by named. They are handed to the plugin or
 * driver as a CFG_TOKEN_EOF-terminated array of tokens, in which:
 *
 * \li	CFG_TOKEN_OPEN, CFG_TOKEN_CLOSE, CFG_TOKEN_END, CFG_TOKEN_SLASH
 *	and CFG_TOKEN_BANG stand for '{', '}', ';', '/' and '!' respectively;
 * \li	CFG_TOKEN_LINE sets the absolute source line for following tokens;
 * \li	CFG_TOKEN_STRING preserves the token's original spelling,
 *	including quotes and escapes. For example, "10.0.0.0/8" is three
 *	tokens: "10.0.0.0", CFG_TOKEN_SLASH and "8".
 *
 * The outer brackets are not included. The cfg_tokens_*() functions
 * provide a cursor to walk such an array.
 */

#include <inttypes.h>
#include <stdbool.h>

#include <isc/formatcheck.h>
#include <isc/types.h>

#include <isccfg/cfg.h>

typedef enum {
	CFG_TOKEN_EOF = 0,
	CFG_TOKEN_STRING,
	CFG_TOKEN_LINE,
	CFG_TOKEN_OPEN,
	CFG_TOKEN_CLOSE,
	CFG_TOKEN_END,
	CFG_TOKEN_SLASH,
	CFG_TOKEN_BANG,
} cfg_token_kind_t;

struct cfg_token {
	cfg_token_kind_t kind;
	union {
		const char   *text;
		unsigned long line;
	};
};

typedef struct cfg_tokenstring cfg_tokenstring_t;

typedef struct cfg_tokens {
	const cfg_token_t *next;
	const char	  *file;
	unsigned long	   line;
	cfg_tokenstring_t *strings;
} cfg_tokens_t;

void
cfg_tokens_init(cfg_tokens_t *tok, const cfg_token_t *tokens, const char *file,
		unsigned long line);
/*%<
 * Initialize the cursor 'tok' to walk 'tokens'. 'file' and 'line' are
 * the location of the opening bracket, and are used for logging.
 * 'tokens' may be NULL, which is treated as an empty list.
 */

void
cfg_tokens_clear(cfg_tokens_t *tok);
/*%<
 * Release decoded strings owned by the cursor. Call after finishing
 * with the cursor and all values returned by cfg_tokens_getstring().
 */

const cfg_token_t *
cfg_tokens_peek(cfg_tokens_t *tok);
/*%<
 * Return the next token without consuming it, skipping line markers and
 * updating the source line. Returns NULL at the end of the list.
 */

const cfg_token_t *
cfg_tokens_next(cfg_tokens_t *tok);
/*%<
 * Like cfg_tokens_peek(), but consume the token.
 */

isc_result_t
cfg_tokens_expect(cfg_tokens_t *tok, cfg_token_kind_t marker);
/*%<
 * Consume the next token, which must be 'marker' (one of CFG_TOKEN_OPEN,
 * CFG_TOKEN_CLOSE, CFG_TOKEN_END, CFG_TOKEN_SLASH or CFG_TOKEN_BANG).
 * Logs an error if it is not.
 *
 * Returns:
 * \li	ISC_R_SUCCESS
 * \li	ISC_R_UNEXPECTEDTOKEN
 * \li	ISC_R_UNEXPECTEDEND
 */

isc_result_t
cfg_tokens_getstring(cfg_tokens_t *tok, const char **strp);
/*%<
 * Consume the next token, which must be a string, and store it in
 * '*strp'. Quoted strings are decoded using the configuration grammar.
 * The result is valid until cfg_tokens_clear() or the token array is
 * freed. Logs an error if the token is not a string.
 *
 * Returns:
 * \li	ISC_R_SUCCESS
 * \li	ISC_R_UNEXPECTEDTOKEN
 * \li	ISC_R_UNEXPECTEDEND
 */

isc_result_t
cfg_tokens_getaml(cfg_tokens_t *tok, cfg_obj_t **objp);
/*%<
 * Consume a bracketed address match list ("{ ... }") and parse it into
 * a configuration object suitable for cfg_acl_fromconfig(). The
 * resulting object carries the file and line the list was found at.
 *
 * Requires:
 * \li	'objp' is not NULL and '*objp' is NULL.
 */

void
cfg_tokens_log(const cfg_tokens_t *tok, int level, const char *fmt, ...)
	ISC_FORMAT_PRINTF(3, 4);
/*%<
 * Log a message prefixed with the current file and line of 'tok'.
 */
