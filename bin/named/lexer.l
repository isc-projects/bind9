%{
#if !defined(lint) && !defined(SABER)
static char rcsid[] = "$Id: lexer.l,v 1.1 1999/01/30 00:50:10 brister Exp $";
#endif /* not lint */

/*
 * Copyright (c) 1996-1999 by Internet Software Consortium.
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

#include <stdlib.h>
#include <string.h>
 
#include "zone.h"
#include "parser_p.h"

int yylex(void);
 
%}

qstring		\"[^\"\n]*[\"\n]
intnum		-?[0-9]+
ws		[ \t]+

%%

"{"		{ return (L_LBRACE); }
"}"		{ return (L_RBRACE); }
";"		{ return (L_EOS); }



"options" 	{ return (L_OPTIONS); }
"directory"	{ return (L_DIRECTORY); }
"zone"		{ return (L_ZONE); }
"type"		{ return (L_TYPE); }
"file"		{ return (L_FILE); }
"master"	{ return (L_MASTER); }
"slave"		{ return (L_SLAVE); }
"hint"		{ return (L_HINT); }
"stub"		{ return (L_STUB); }
"forward" 	{ return (L_FORWARD); }

{intnum}	{
	yylval.num = strtol(yytext, NULL, 10);
	return (L_INTEGER);
}

{qstring}	{
	yylval.cp = strdup(yytext + 1); /* skip open quote */
	if (yylval.cp[yyleng - 2] != '"') {
		/* XXX use an isc log function. */	
		fprintf(stderr, "Unterminated string");
	} else {
		yylval.cp[yyleng - 2] = '\0';
		return L_QSTRING;
	}
}
