/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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

#include <ctype.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/boolean.h>
#include <isc/error.h>
#include <isc/lex.h>

#include "util.h"

typedef struct inputsource {
	isc_result_t			result;
	isc_boolean_t			is_file;
	isc_boolean_t			need_close;
	isc_boolean_t			have_token;
	isc_token_t			token;
	unsigned int			char_count;
	int				chars[2];
	void *				input;
	char *				name;
	unsigned long			line;
	LINK(struct inputsource)	link;
} inputsource;

#define LEX_MAGIC			0x4C657821U	/* Lex!. */
#define VALID_LEX(l)			((l) != NULL && \
					 (l)->magic == LEX_MAGIC)

struct isc_lex {
	/* Unlocked. */
	unsigned int			magic;
	isc_mem_t *			mctx;
	size_t				max_token;
	char *				data;
	unsigned int			options;
	unsigned int			comments;
	isc_boolean_t			comment_ok;
	isc_boolean_t			last_was_eol;
	isc_lexspecials_t		specials;
	LIST(struct inputsource)	sources;
};

isc_result_t
isc_lex_create(isc_mem_t *mctx, size_t max_token, isc_lex_t **lexp) {
	isc_lex_t *lex;

	/*
	 * Create a lexer.
	 */
	
	REQUIRE(lexp != NULL && *lexp == NULL);
	REQUIRE(max_token > 0);

	lex = isc_mem_get(mctx, sizeof *lex);
	if (lex == NULL)
		return (ISC_R_NOMEMORY);
	lex->data = isc_mem_get(mctx, max_token);
	if (lex->data == NULL) {
		isc_mem_put(mctx, lex, sizeof *lex);
		return (ISC_R_NOMEMORY);
	}
	lex->mctx = mctx;
	lex->max_token = max_token;
	lex->comments = 0;
	lex->comment_ok = ISC_TRUE;
	lex->last_was_eol = ISC_TRUE;
	memset(lex->specials, 0, 256);
	INIT_LIST(lex->sources);
	lex->magic = LEX_MAGIC;
	
	*lexp = lex;

	return (ISC_R_SUCCESS);
}

void
isc_lex_destroy(isc_lex_t **lexp) {
	isc_lex_t *lex;

	/*
	 * Destroy the lexer.
	 */

	REQUIRE(lexp != NULL);
	lex = *lexp;
	REQUIRE(VALID_LEX(lex));

	while (!EMPTY(lex->sources))
		isc_lex_close(lex);
	if (lex->data != NULL)
		isc_mem_put(lex->mctx, lex->data, lex->max_token);
	isc_mem_put(lex->mctx, lex, sizeof *lex);
	lex->magic = 0;

	*lexp = NULL;
}

unsigned int
isc_lex_getcomments(isc_lex_t *lex) {
	/*
	 * Return the current lexer commenting styles.
	 */

	REQUIRE(VALID_LEX(lex));

	return (lex->comments);
}

void
isc_lex_setcomments(isc_lex_t *lex, unsigned int comments) {
	/*
	 * Set allowed lexer commenting styles.
	 */

	REQUIRE(VALID_LEX(lex));

	lex->comments = comments;
}

void
isc_lex_getspecials(isc_lex_t *lex, isc_lexspecials_t specials) {
	/*
	 * Put the current list of specials into 'specials'.
	 */

	REQUIRE(VALID_LEX(lex));

	memcpy(specials, lex->specials, 256);
}

void
isc_lex_setspecials(isc_lex_t *lex, isc_lexspecials_t specials) {
	/*
	 * The characters in 'specials' are returned as tokens.  Along with
	 * whitespace, they delimit strings and numbers.
	 */

	REQUIRE(VALID_LEX(lex));

	memcpy(lex->specials, specials, 256);
}

static inline isc_result_t
new_source(isc_lex_t *lex, isc_boolean_t is_file, isc_boolean_t need_close,
	   void *input, char *name)
{
	inputsource *source;

	source = isc_mem_get(lex->mctx, sizeof *source);
	if (source == NULL)
		return (ISC_R_NOMEMORY);
	source->result = ISC_R_SUCCESS;
	source->is_file = is_file;
	source->need_close = need_close;
	source->have_token = ISC_FALSE;
	source->token.type = isc_tokentype_unknown;
	source->token.value.as_pointer = NULL;
	source->char_count = 0;
	source->input = input;
	source->name = isc_mem_strdup(lex->mctx, name);
	source->line = 1;
	PREPEND(lex->sources, source, link);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_lex_openfile(isc_lex_t *lex, char *filename) {
	FILE *stream;

	/*
	 * Open 'filename' and make it the current input source for 'lex'.
	 */

	REQUIRE(VALID_LEX(lex));

	/*
	 * XXX we should really call something like isc_file_open() to
	 * get maximally safe file opening.
	 */
	stream = fopen(filename, "r");
	/*
	 * The C standard doesn't say that errno is set by fopen(), so
	 * we just return a generic error.
	 */
	if (stream == NULL)
		return (ISC_R_FAILURE);
	flockfile(stream);
	
	return (new_source(lex, ISC_TRUE, ISC_TRUE, stream, filename));
}

isc_result_t
isc_lex_openstream(isc_lex_t *lex, FILE *stream) {
	char name[128];

	/*
	 * Make 'stream' the current input source for 'lex'.
	 */

	REQUIRE(VALID_LEX(lex));

	flockfile(stream);
	/* This is safe. */
	sprintf(name, "stream-%p", stream);

	return (new_source(lex, ISC_TRUE, ISC_FALSE, stream, name));
}

isc_result_t
isc_lex_openbuffer(isc_lex_t *lex, isc_buffer_t *buffer) {
	char name[128];

	/*
	 * Make 'buffer' the current input source for 'lex'.
	 */

	REQUIRE(VALID_LEX(lex));

	/* This is safe. */
	sprintf(name, "buffer-%p", buffer);

	return (new_source(lex, ISC_FALSE, ISC_FALSE, buffer, name));
}

void
isc_lex_close(isc_lex_t *lex) {
	inputsource *source;

	/*
	 * Close the most recently opened object (i.e. file or buffer).
	 */

	REQUIRE(VALID_LEX(lex));
	source = HEAD(lex->sources);
	REQUIRE(source != NULL);
	
	UNLINK(lex->sources, source, link);
	if (source->is_file) {
		funlockfile((FILE *)(source->input));
		if (source->need_close)
			fclose((FILE *)(source->input));
	}
	isc_mem_free(lex->mctx, source->name);
	isc_mem_put(lex->mctx, source, sizeof *source);
}

typedef enum {
	lexstate_start,
	lexstate_crlf,
	lexstate_string,
	lexstate_number,
	lexstate_maybecomment,
	lexstate_ccomment,
	lexstate_ccommentend,
	lexstate_eatline,
	lexstate_qstring
} lexstate;

isc_result_t
isc_lex_gettoken(isc_lex_t *lex, unsigned int options, isc_token_t *tokenp) {
	inputsource *source;
	int c;
	isc_boolean_t done = ISC_FALSE;
	isc_boolean_t no_comments = ISC_FALSE;
	isc_boolean_t escaped = ISC_FALSE;
	lexstate state = lexstate_start;
	lexstate saved_state = lexstate_start;
	isc_buffer_t *buffer;
	FILE *stream;
	char *curr, *prev;
	size_t remaining;

	/*
	 * Get the next token.
	 */

	REQUIRE(VALID_LEX(lex));
	source = HEAD(lex->sources);
	REQUIRE(source != NULL);
	REQUIRE(tokenp != NULL);

	if (source->have_token) {
		*tokenp = source->token;
		source->have_token = ISC_FALSE;
		return (ISC_R_SUCCESS);
	}

	if (source->char_count == 0 && source->result != ISC_R_SUCCESS)
		return (source->result);

	curr = lex->data;
	prev = NULL;
	remaining = lex->max_token;
	do {
		if (source->char_count > 0) {
			source->char_count--;
			c = source->chars[source->char_count];
		} else if (source->is_file) {
			stream = source->input;

			c = getc_unlocked(stream);
			if (c == EOF) {
				if (ferror(stream)) {
					source->result = ISC_R_IOERROR;
					return (source->result);
				}
				source->result = ISC_R_EOF;
			}
		} else {
			buffer = source->input;

			if (buffer->current == buffer->used) {
				c = EOF;
				source->result = ISC_R_EOF;
			} else {
				c = *((char *)buffer->base + buffer->current);
				buffer->current++;
			}
		}

		if (lex->comment_ok && !no_comments) {
			if (c == ';' &&
			    ((lex->comments & ISC_LEXCOMMENT_DNSMASTERFILE)
			     != 0)) {
				saved_state = state;
				state = lexstate_eatline;
				no_comments = ISC_TRUE;
				continue;
			} else if (c == '/' &&
				   (lex->comments &
				    (ISC_LEXCOMMENT_C|
				     ISC_LEXCOMMENT_CPLUSPLUS)) != 0) {
				saved_state = state;
				state = lexstate_maybecomment;
				no_comments = ISC_TRUE;
				continue;
			} else if (c == '#' &&
				   ((lex->comments & ISC_LEXCOMMENT_SHELL)
				    != 0)) {
				saved_state = state;
				state = lexstate_eatline;
				no_comments = ISC_TRUE;
				continue;
			}
		}

	no_read:
		/* INSIST(c == EOF || (c >= 0 && c <= 255)); */
		switch (state) {
		case lexstate_start:
			if (c == EOF) {
				lex->last_was_eol = ISC_FALSE;
				if ((options & ISC_LEXOPT_EOF) == 0)
					return (ISC_R_EOF);
				tokenp->type = isc_tokentype_eof;
				done = ISC_TRUE;
			} else if (c == ' ' || c == '\t') {
				if (lex->last_was_eol &&
				    (options & ISC_LEXOPT_INITIALWS)
				    != 0) {
					lex->last_was_eol = ISC_FALSE;
					tokenp->type = isc_tokentype_initialws;
					tokenp->value.as_char = c;
					done = ISC_TRUE;
				}
			} else if (c == '\n') {
				if ((options & ISC_LEXOPT_EOL) != 0) {
					tokenp->type = isc_tokentype_eol;
					done = ISC_TRUE;
				}
				lex->last_was_eol = ISC_TRUE;
			} else if (c == '\r') {
				if ((options & ISC_LEXOPT_EOL) != 0)
					state = lexstate_crlf;
			} else if (c == '"' &&
				   (options & ISC_LEXOPT_QSTRING)) {
				lex->last_was_eol = ISC_FALSE;
				no_comments = ISC_TRUE;
				state = lexstate_qstring;
			} else if (lex->specials[c]) {
				lex->last_was_eol = ISC_FALSE;
				tokenp->type = isc_tokentype_special;
				tokenp->value.as_char = c;
				done = ISC_TRUE;
			} else if (isdigit(c) &&
				   (options & ISC_LEXOPT_NUMBER)) {
				lex->last_was_eol = ISC_FALSE;
				state = lexstate_number;
				goto no_read;
			} else {
				lex->last_was_eol = ISC_FALSE;
				state = lexstate_string;
				goto no_read;
			}
			break;
		case lexstate_crlf:
			if (c != '\n') {
				INSIST(source->char_count < 2);
				source->chars[source->char_count++] = c;
			}
			tokenp->type = isc_tokentype_eol;
			done = ISC_TRUE;
			lex->last_was_eol = ISC_TRUE;
			break;
		case lexstate_number:
			if (!isdigit(c)) {
				if (c == ' ' || c == '\t' || c == '\r' ||
				    c == '\n' || c == EOF ||
				    lex->specials[c]) {
					INSIST(source->char_count < 2);
					source->chars[source->char_count++] =
						c;
					tokenp->type =
						isc_tokentype_number;
					/* XXX convert to number */
					tokenp->value.as_textregion.base =
						lex->data;
					tokenp->value.as_textregion.length = 
						lex->max_token - remaining;
					done = ISC_TRUE;
					continue;
				} else
					state = lexstate_string;
			}
			if (remaining > 0) {
				*curr++ = c;
				remaining--;
			} else
				return (ISC_R_NOSPACE);
			break;
		case lexstate_string:
			if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
			    c == EOF || lex->specials[c]) {
				INSIST(source->char_count < 2);
				source->chars[source->char_count++] = c;
				tokenp->type = isc_tokentype_string;
				tokenp->value.as_textregion.base = lex->data;
				tokenp->value.as_textregion.length = 
					lex->max_token - remaining;
				done = ISC_TRUE;
				continue;
			}
			if (remaining > 0) {
				*curr++ = c;
				remaining--;
			} else
				return (ISC_R_NOSPACE);
			break;
		case lexstate_maybecomment:
			if (c == '*' &&
			    (lex->comments & ISC_LEXCOMMENT_C) != 0) {
				state = lexstate_ccomment;
				continue;
			} else if (c == '/' &&
			    (lex->comments & ISC_LEXCOMMENT_CPLUSPLUS) != 0) {
				state = lexstate_eatline;
				continue;
			}
			INSIST(source->char_count < 2);
			source->chars[source->char_count++] = c;
			c = '/';
			no_comments = ISC_FALSE;
			state = saved_state;
			goto no_read;
		case lexstate_ccomment:
			if (c == EOF)
				return (ISC_R_UNEXPECTEDEND);
			if (c == '*')
				state = lexstate_ccommentend;
			break;
		case lexstate_ccommentend:
			if (c == EOF)
				return (ISC_R_UNEXPECTEDEND);
			if (c == '/') {
				/*
				 * C-style comments become a single space.
				 * We do this to ensure that a comment will
				 * act as a delimiter for strings and
				 * numbers.
				 */
				c = ' ';
				no_comments = ISC_FALSE;
				state = saved_state;
				goto no_read;
			} else
				state = lexstate_ccomment;
			break;
		case lexstate_eatline:
			if (c == EOF)
				return (ISC_R_UNEXPECTEDEND);
			if (c == '\n') {
				no_comments = ISC_FALSE;
				state = saved_state;
				goto no_read;
			}
			break;
		case lexstate_qstring:
			if (c == EOF)
				return (ISC_R_UNEXPECTEDEND);
			if (c == '"') {
				if (escaped) {
					escaped = ISC_FALSE;
					/*
					 * Overwrite the preceding backslash.
					 */
					INSIST(prev != NULL);
					*prev = '"';
				} else {
					tokenp->type = isc_tokentype_qstring;
					tokenp->value.as_textregion.base =
						lex->data;
					tokenp->value.as_textregion.length = 
						lex->max_token - remaining;
					no_comments = ISC_FALSE;
					done = ISC_TRUE;
				}
			} else {
				if (c == '\\' && !escaped)
					escaped = ISC_TRUE;
				else
					escaped = ISC_FALSE;
				if (remaining > 0) {
					prev = curr;
					*curr++ = c;
					remaining--;
				} else
					return (ISC_R_NOSPACE);
			}
			break;
		default:
			FATAL_ERROR(__FILE__, __LINE__,
				    "Unexpected state %d", state);
			/* Does not return. */
		}

	} while (!done);

	return (ISC_R_SUCCESS);
}

void
isc_lex_ungettoken(isc_lex_t *lex, isc_token_t *tokenp) {
	inputsource *source;
	/*
	 * Unget the current token.
	 */

	REQUIRE(VALID_LEX(lex));
	source = HEAD(lex->sources);
	REQUIRE(source != NULL);
	REQUIRE(!source->have_token);
	REQUIRE(tokenp != NULL);
	
	source->token = *tokenp;
	source->have_token = ISC_TRUE;
}
