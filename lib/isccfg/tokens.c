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

#include <stdarg.h>
#include <stdio.h>

#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <isccfg/cfg.h>
#include <isccfg/grammar.h>
#include <isccfg/tokens.h>

struct cfg_tokenstring {
	cfg_obj_t *obj;
	cfg_tokenstring_t *next;
};

static const char *const empty[] = { NULL };

void
cfg_tokens_init(cfg_tokens_t *tok, const char *const *tokens, const char *file,
		unsigned long line) {
	REQUIRE(tok != NULL);

	*tok = (cfg_tokens_t){
		.next = (tokens != NULL) ? tokens : empty,
		.file = file,
		.line = line,
	};
}

void
cfg_tokens_clear(cfg_tokens_t *tok) {
	while (tok->strings != NULL) {
		cfg_tokenstring_t *string = tok->strings;

		tok->strings = string->next;
		cfg_obj_detach(&string->obj);
		isc_mem_put(isc_g_mctx, string, sizeof(*string));
	}
}

const char *
cfg_tokens_peek(cfg_tokens_t *tok) {
	REQUIRE(tok != NULL);

	while (*tok->next == CFG_TOKEN_NEWLINE) {
		tok->next++;
		tok->line++;
	}
	return *tok->next;
}

const char *
cfg_tokens_next(cfg_tokens_t *tok) {
	const char *token = cfg_tokens_peek(tok);

	if (token != NULL) {
		tok->next++;
	}
	return token;
}

void
cfg_tokens_log(const cfg_tokens_t *tok, int level, const char *fmt, ...) {
	va_list ap;
	char msgbuf[2048];

	REQUIRE(tok != NULL);

	if (!isc_log_wouldlog(level)) {
		return;
	}

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	isc_log_write(CFG_LOGCATEGORY_CONFIG, CFG_LOGMODULE_PARSER, level,
		      "%s:%lu: %s", tok->file != NULL ? tok->file : "none",
		      tok->line, msgbuf);
}

static const char *
markername(const char *marker) {
	if (marker == CFG_TOKEN_OPEN) {
		return "'{'";
	} else if (marker == CFG_TOKEN_CLOSE) {
		return "'}'";
	} else if (marker == CFG_TOKEN_END) {
		return "';'";
	} else if (marker == CFG_TOKEN_SLASH) {
		return "'/'";
	} else if (marker == CFG_TOKEN_BANG) {
		return "'!'";
	}
	UNREACHABLE();
}

isc_result_t
cfg_tokens_expect(cfg_tokens_t *tok, const char *marker) {
	const char *token = cfg_tokens_next(tok);

	if (token == NULL) {
		cfg_tokens_log(tok, ISC_LOG_ERROR,
			       "expected %s, found end of input",
			       markername(marker));
		return ISC_R_UNEXPECTEDEND;
	}
	if (token != marker) {
		cfg_tokens_log(tok, ISC_LOG_ERROR, "expected %s",
			       markername(marker));
		return ISC_R_UNEXPECTEDTOKEN;
	}
	return ISC_R_SUCCESS;
}

isc_result_t
cfg_tokens_getstring(cfg_tokens_t *tok, const char **strp) {
	const char *token = NULL;

	REQUIRE(strp != NULL);

	token = cfg_tokens_next(tok);
	if (token == NULL) {
		cfg_tokens_log(tok, ISC_LOG_ERROR,
			       "expected string, found end of input");
		return ISC_R_UNEXPECTEDEND;
	}
	if (!CFG_TOKEN_ISSTRING(token)) {
		cfg_tokens_log(tok, ISC_LOG_ERROR, "expected string");
		return ISC_R_UNEXPECTEDTOKEN;
	}
	if (token[0] == '"') {
		cfg_obj_t *obj = NULL;
		isc_buffer_t buffer;
		size_t length = strlen(token);

		isc_buffer_constinit(&buffer, token, length);
		isc_buffer_add(&buffer, length);
		RETERR(cfg_parse_buffer(&buffer, tok->file, tok->line,
					&cfg_type_qstring, 0, &obj));

		cfg_tokenstring_t *string = isc_mem_get(isc_g_mctx,
							sizeof(*string));
		*string = (cfg_tokenstring_t){ .obj = obj,
					       .next = tok->strings };
		tok->strings = string;
		*strp = cfg_obj_asstring(obj);
	} else {
		*strp = token;
	}
	return ISC_R_SUCCESS;
}

static void
print_tobuffer(void *closure, const char *text, int textlen) {
	isc_buffer_putmem(closure, (const unsigned char *)text, textlen);
}

isc_result_t
cfg_tokens_getaml(cfg_tokens_t *tok, cfg_obj_t **objp) {
	isc_result_t result;
	const char *const *end = NULL;
	unsigned long line;
	unsigned int depth = 0;
	isc_buffer_t *b = NULL;
	cfg_printer_t pctx;

	REQUIRE(objp != NULL && *objp == NULL);

	RETERR(cfg_tokens_expect(tok, CFG_TOKEN_OPEN));
	line = tok->line;

	/* Find the matching closing bracket. */
	for (end = tok->next;; end++) {
		if (*end == NULL) {
			cfg_tokens_log(tok, ISC_LOG_ERROR,
				       "expected '}', found end of input");
			return ISC_R_UNEXPECTEDEND;
		} else if (*end == CFG_TOKEN_OPEN) {
			depth++;
		} else if (*end == CFG_TOKEN_CLOSE) {
			if (depth == 0) {
				break;
			}
			depth--;
		}
	}

	/*
	 * Turn the tokens back into text and parse that, so that the
	 * address match list grammar lives only in the configuration
	 * parser. The line breaks are preserved, so errors are reported
	 * at the right line.
	 */
	isc_buffer_allocate(isc_g_mctx, &b, 256);
	pctx = (cfg_printer_t){ .f = print_tobuffer, .closure = b };
	cfg_print_tokens(&pctx, tok->next, end);

	result = cfg_parse_buffer(b, tok->file, line, &cfg_type_bracketed_aml,
				  0, objp);
	isc_buffer_free(&b);

	for (; tok->next != end; tok->next++) {
		if (*tok->next == CFG_TOKEN_NEWLINE) {
			tok->line++;
		}
	}
	tok->next++;

	return result;
}
