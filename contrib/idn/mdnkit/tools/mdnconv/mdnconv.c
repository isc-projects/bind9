#ifndef lint
static char *rcsid = "$Id: mdnconv.c,v 1.1 2002/01/02 02:47:02 marka Exp $";
#endif

/*
 * Copyright (c) 2000,2001 Japan Network Information Center.
 * All rights reserved.
 *  
 * By using this file, you agree to the terms and conditions set forth bellow.
 * 
 * 			LICENSE TERMS AND CONDITIONS 
 * 
 * The following License Terms and Conditions apply, unless a different
 * license is obtained from Japan Network Information Center ("JPNIC"),
 * a Japanese association, Kokusai-Kougyou-Kanda Bldg 6F, 2-3-4 Uchi-Kanda,
 * Chiyoda-ku, Tokyo 101-0047, Japan.
 * 
 * 1. Use, Modification and Redistribution (including distribution of any
 *    modified or derived work) in source and/or binary forms is permitted
 *    under this License Terms and Conditions.
 * 
 * 2. Redistribution of source code must retain the copyright notices as they
 *    appear in each source code file, this License Terms and Conditions.
 * 
 * 3. Redistribution in binary form must reproduce the Copyright Notice,
 *    this License Terms and Conditions, in the documentation and/or other
 *    materials provided with the distribution.  For the purposes of binary
 *    distribution the "Copyright Notice" refers to the following language:
 *    "Copyright (c) Japan Network Information Center.  All rights reserved."
 * 
 * 4. Neither the name of JPNIC may be used to endorse or promote products
 *    derived from this Software without specific prior written approval of
 *    JPNIC.
 * 
 * 5. Disclaimer/Limitation of Liability: THIS SOFTWARE IS PROVIDED BY JPNIC
 *    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *    PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL JPNIC BE LIABLE
 *    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *    OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *    ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * 6. Indemnification by Licensee
 *    Any person or entities using and/or redistributing this Software under
 *    this License Terms and Conditions shall defend indemnify and hold
 *    harmless JPNIC from and against any and all judgements damages,
 *    expenses, settlement liabilities, cost and other liabilities of any
 *    kind as a result of use and redistribution of this Software or any
 *    claim, suite, action, litigation or proceeding by any third party
 *    arising out of or relates to this License Terms and Conditions.
 * 
 * 7. Governing Law, Jurisdiction and Venue
 *    This License Terms and Conditions shall be governed by and and
 *    construed in accordance with the law of Japan. Any person or entities
 *    using and/or redistributing this Software under this License Terms and
 *    Conditions hereby agrees and consent to the personal and exclusive
 *    jurisdiction and venue of Tokyo District Court of Japan.
 */

/*
 * mdnconv -- Codeset converter for named.conf and zone files
 */

#include <config.h>

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include <mdn/result.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>
#include <mdn/utf8.h>
#include <mdn/resconf.h>
#include <mdn/res.h>
#include <mdn/util.h>
#include <mdn/version.h>

#include "util.h"

#define MAX_DELIMITER		10
#define MAX_LOCALMAPPER		10
#define MAX_MAPPER		10
#define MAX_NORMALIZER		10
#define MAX_CHEKER		10

#define FLAG_REVERSE		1
#define FLAG_DELIMITERMAP	2
#define FLAG_LOCALMAP		4
#define FLAG_NAMEPREP		8
#define FLAG_UNASSIGNCHECK	16
#define FLAG_SELECTIVE		32

int		line_number;		/* current input file line number */
static int	flush_every_line = 0;	/* pretty obvious */

static int		convert_file(mdn_resconf_t conf, FILE *fp, int flags);
static void		print_usage(char *cmd);
static void		print_version(void);
static unsigned long	get_ucs(const char *p);

int
main(int ac, char **av) {
	char *cmd = *av;
	char *cname;
	unsigned long delimiters[MAX_DELIMITER];
	char *localmappers[MAX_LOCALMAPPER];
	char *mappers[MAX_MAPPER];
	char *normalizers[MAX_NORMALIZER];
	char *prohibits[MAX_CHEKER];
	char *unassigns[MAX_CHEKER];
	char *nameprep_version = NULL;
	int ndelimiters = 0;
	int nlocalmappers = 0;
	int nmappers = 0;
	int nnormalizers = 0;
	int nprohibits = 0;
	int nunassigns = 0;
	char *in_code = NULL;
	char *out_code = NULL;
	char *resconf_file = NULL;
	int no_resconf = 0;
	char *encoding_alias = NULL;
	int check_unassigned = 0;
	int flags = FLAG_LOCALMAP | FLAG_NAMEPREP | FLAG_SELECTIVE;
	FILE *fp;
	mdn_result_t r;
	mdn_resconf_t resconf;

#ifdef HAVE_SETLOCALE
	(void)setlocale(LC_ALL, "");
#endif

	/*
	 * If the command name begins with 'r', reverse mode is assumed.
	 */
	if ((cname = strrchr(cmd, '/')) != NULL)
		cname++;
	else
		cname = cmd;
	if (cname[0] == 'r')
		flags |= FLAG_REVERSE;

	ac--;
	av++;
	while (ac > 0 && **av == '-') {

#define OPT_MATCH(opt) (strcmp(*av, opt) == 0)
#define MUST_HAVE_ARG if (ac < 2) print_usage(cmd)
#define APPEND_LIST(array, size, item, what) \
	if (size >= (sizeof(array) / sizeof(array[0]))) { \
		errormsg("too many " what "\n"); \
		exit(1); \
	} \
	array[size++] = item; \
	ac--; av++

		if (OPT_MATCH("-in") || OPT_MATCH("-i")) {
			MUST_HAVE_ARG;
			in_code = av[1];
			ac--;
			av++;
		} else if (OPT_MATCH("-out") || OPT_MATCH("-o")) {
			MUST_HAVE_ARG;
			out_code = av[1];
			ac--;
			av++;
		} else if (OPT_MATCH("-conf") || OPT_MATCH("-c")) {
			MUST_HAVE_ARG;
			resconf_file = av[1];
			ac--;
			av++;
		} else if (OPT_MATCH("-nameprep") || OPT_MATCH("-n")) {
			MUST_HAVE_ARG;
			nameprep_version = av[1];
			ac--;
			av++;
		} else if (OPT_MATCH("-noconf") || OPT_MATCH("-C")) {
			no_resconf = 1;
		} else if (OPT_MATCH("-reverse") || OPT_MATCH("-r")) {
			flags |= FLAG_REVERSE;
		} else if (OPT_MATCH("-nolocalmap") || OPT_MATCH("-L")) {
			flags &= ~FLAG_LOCALMAP;
		} else if (OPT_MATCH("-delimitermap") || OPT_MATCH("-d")) {
			flags |= FLAG_DELIMITERMAP;
		} else if (OPT_MATCH("-nonameprep") || OPT_MATCH("-N")) {
			flags &= ~FLAG_NAMEPREP;
		} else if (OPT_MATCH("-unassigncheck") || OPT_MATCH("-u")) {
			flags |= FLAG_UNASSIGNCHECK;
		} else if (OPT_MATCH("-whole") || OPT_MATCH("-w")) {
			flags &= ~FLAG_SELECTIVE;
		} else if (OPT_MATCH("-localmap")) {
			MUST_HAVE_ARG;
			APPEND_LIST(localmappers, nlocalmappers, av[1],
				    "local maps");
		} else if (OPT_MATCH("-delimiter")) {
			unsigned long v;
			MUST_HAVE_ARG;
			v = get_ucs(av[1]);
			APPEND_LIST(delimiters, ndelimiters, v,
				    "delimiter maps");
		} else if (OPT_MATCH("-map")) {
			MUST_HAVE_ARG;
			APPEND_LIST(mappers, nmappers, av[1], "mappers");
		} else if (OPT_MATCH("-normalize")) {
			MUST_HAVE_ARG;
			APPEND_LIST(normalizers, nnormalizers, av[1],
				    "normalizers");
		} else if (OPT_MATCH("-prohibit")) {
			MUST_HAVE_ARG;
			APPEND_LIST(prohibits, nprohibits, av[1],
				    "prohibited checkers");
		} else if (OPT_MATCH("-unassigned")) {
			MUST_HAVE_ARG;
			APPEND_LIST(unassigns, nunassigns, av[1],
				    "unassigned checkers");
			check_unassigned = 1;
		} else if (OPT_MATCH("-alias") || OPT_MATCH("-a")) {
			MUST_HAVE_ARG;
			encoding_alias = av[1];
			ac--;
			av++;
		} else if (OPT_MATCH("-flush")) {
			flush_every_line = 1;
		} else if (OPT_MATCH("-version") || OPT_MATCH("-v")) {
			print_version();
		} else {
			print_usage(cmd);
		}
#undef OPT_MATCH
#undef MUST_HAVE_ARG
#undef APPEND_LIST

		ac--;
		av++;
	}

	if (ac > 1)
		print_usage(cmd);

	/* Initialize. */
	if ((r = mdn_resconf_initialize()) != mdn_success) {
		errormsg("error initializing library\n");
		return (1);
	}

	/* Create resource context. */
	resconf = NULL;
	if ((r = mdn_resconf_create(&resconf)) != mdn_success) {
		errormsg("error initializing configuration parameters\n");
		return (1);
	}

	/* Load configuration file. */
	if (!no_resconf) {
		r = mdn_resconf_loadfile(resconf, resconf_file);
		if (r != mdn_success) {
			errormsg("error reading configuration file: %s\n",
				 mdn_result_tostring(r));
			return (1);
		}
	}

	/* Set encoding alias file. */
	if (encoding_alias != NULL)
		set_encoding_alias(encoding_alias);

	/* Set input/output codeset. */
	if (flags & FLAG_REVERSE) {
		if (in_code != NULL)
			set_idncode(resconf, in_code);
		else
			check_defaultidncode(resconf, "-in");
		if (out_code != NULL)
			set_localcode(resconf, out_code);
		else
			check_defaultlocalcode(resconf, "-out");
	} else {
		if (in_code != NULL)
			set_localcode(resconf, in_code);
		else
			check_defaultlocalcode(resconf, "-in");
		if (out_code != NULL)
			set_idncode(resconf, out_code);
		else
			check_defaultidncode(resconf, "-out");
	}

	/* Set delimiter map(s). */
	if (ndelimiters > 0)
		set_delimitermapper(resconf, delimiters, ndelimiters);

	/* Set local map(s). */
	if (nlocalmappers > 0)
		set_localmapper(resconf, localmappers, nlocalmappers);

	/* Set NAMEPREP version. */
	if (nameprep_version != NULL)
		set_nameprep(resconf, nameprep_version);

	/* Set NAMEPREP mapper. */
	if (nmappers > 0)
		set_mapper(resconf, mappers, nmappers);

	/* Set NAMEPREP normalizer. */
	if (nnormalizers > 0)
		set_normalizer(resconf, normalizers, nnormalizers);

	/* Set NAMEPREP prohibit checker. */
	if (nprohibits > 0)
		set_prohibit_checkers(resconf, prohibits, nprohibits);

	/* Set NAMEPREP unassigned checker. */
	if (nunassigns > 0)
		set_unassigned_checkers(resconf, unassigns, nunassigns);

	/* Open input file. */
	if (ac > 0) {
		if ((fp = fopen(av[0], "r")) == NULL) {
			errormsg("cannot open file %s: %s\n",
				 av[0], strerror(errno));
			return (1);
		}
	} else {
		fp = stdin;
	}

	/* Do the conversion. */
	return convert_file(resconf, fp, flags);
}

static int
convert_file(mdn_resconf_t conf, FILE *fp, int flags) {
	mdn_result_t r;
	char line1[1024];
	char line2[1024];
	char insn1[10], insn2[10];
	int nl_trimmed;
	int ace_hack;
	mdn_converter_t conv;

	/*
	 * See if the input codeset is an ACE.
	 */
	if (flags & FLAG_REVERSE)
		conv = mdn_resconf_getidnconverter(conf);
	else
		conv = mdn_resconf_getlocalconverter(conf);
	if (conv != NULL && mdn_converter_isasciicompatible(conv))
		ace_hack = 1;
	else
		ace_hack = 0;
	if (conv != NULL)
		mdn_converter_destroy(conv);

	if (flags & FLAG_REVERSE) {
		char *insnp = insn1;

		*insnp++ = 'i';
		if (flags & FLAG_NAMEPREP) {
			*insnp++ = '!';
			*insnp++ = 'N';
		}
		if (flags & FLAG_UNASSIGNCHECK) {
			*insnp++ = '!';
			*insnp++ = 'u';
		}
		*insnp = '\0';

		strcpy(insn2, "L");
	} else {
		char *insnp = insn2;

		strcpy(insn1, "l");

		if (flags & FLAG_DELIMITERMAP)
			*insnp++ = 'd';
		if (flags & FLAG_LOCALMAP)
			*insnp++ = 'M';
		if (flags & FLAG_NAMEPREP)
			*insnp++ = 'N';
		if (flags & FLAG_UNASSIGNCHECK)
			*insnp++ = 'u';
		*insnp++ = 'I';
		*insnp = '\0';
	}

	line_number = 1;
	while (fgets(line1, sizeof(line1), fp) != NULL) {
		/*
		 * Trim newline at the end.  This is needed for
		 * those ascii-comatible encodings such as UTF-5 or RACE
		 * not to try converting newlines, which will result
		 * in `invalid encoding' error.
		 */
		if (line1[strlen(line1) - 1] == '\n') {
			line1[strlen(line1) - 1] = '\0';
			nl_trimmed = 1;
		} else {
			nl_trimmed = 0;
		}

		/*
		 * Convert input line to UTF-8.
		 */
		if (ace_hack && (flags & FLAG_SELECTIVE)) {
			/*
			 * Selectively decode those portions.
			 */
			r = selective_decode(conf, insn1, line1, line2,
					     sizeof(line2));
		} else {
			r = mdn_res_nameconv(conf, insn1,
					     line1, line2, sizeof(line2));
		}
		if (r != mdn_success) {
			errormsg("conversion failed at line %d: %s\n",
				 line_number,
				 mdn_result_tostring(r));
			return (1);
		}
		if (!mdn_utf8_isvalidstring(line2)) {
			errormsg("conversion to utf-8 failed at line %d\n",
				 line_number);
			return (1);
		}

		/*
		 * Perform local mapping and NAMEPREP, and convert to
		 * the output codeset.
		 */
		if (!(flags & FLAG_REVERSE) && (flags & FLAG_SELECTIVE)) {
			r = selective_encode(conf, insn2, line2, line1,
					     sizeof(line1));
		} else {
			r = mdn_res_nameconv(conf, insn2, line2, line1,
					     sizeof(line1));
		}
		if (r != mdn_success) {
			errormsg("error in nameprep or output conversion "
				 "at line %d: %s\n",
				 line_number, mdn_result_tostring(r));
			return (1);
		}

		fputs(line1, stdout);
		if (nl_trimmed)
			putc('\n', stdout);

		if (flush_every_line)
			fflush(stdout);

		line_number++;
	}
	return (0);
}

static char *options[] = {
	"-in INPUT-CODESET   : specifies input codeset name.",
	"-i INPUT-CODESET    : synonym for -in",
	"-out OUTPUT-CODESET : specifies output codeset name.",
	"-o OUTPUT-CODESET   : synonym for -out",
	"-conf CONF-FILE     : specifies pathname of MDN configuration file.",
	"-c CONF-FILE        : synonym for -conf",
	"-noconf             : do not load MDN configuration file.",
	"-C                  : synonym for -noconf",
	"-reverse            : specifies reverse conversion.",
	"                      (i.e. IDN encoding to local encoding)",
	"-r                  : synonym for -reverse",
	"-nameprep VERSION   : specifies version name of NAMEPREP.",
	"-n VERSION          : synonym for -nameprep",
	"-nonameprep         : do not perform NAMEPREP.",
	"-N                  : synonym for -nonameprep",
	"-localmap MAPPING   : specifies local mapping.",
	"-nolocalmap         : do not perform local mapping.",
	"-L                  : synonym for -nolocalmap",
	"-map SCHEME         : specifies mapping scheme.",
	"-normalize SCHEME   : specifies normalization scheme.",
	"-prohibit SET       : specifies set of prohibited characters.",
	"-unassigned SET     : specifies set of unassigned code points.",
	"-unassigncheck      : perform unassigned codepoint check.",
	"-u                  : synonym for -unassigncheck",
	"-delimiter U+XXXX   : specifies local delimiter code point.",
	"-delimitermap       : perform local delimiter mapping.",
	"-d                  : synonym for -delimitermap",
	"-alias alias-file   : specifies codeset alias file.",
	"-a                  : synonym for -alias",
	"-flush              : line-buffering mode.",
	"-whole              : convert the whole region instead of",
	"                      regions containing non-ascii characters.",
	"-w                  : synonym for -whole",
	"-version            : print version number, then exit.",
	"-v                  : synonym for -version",
	"",
	" The following options can be specified multiple times",
	"   -localmap, -map, -normalize, -prohibit, -unassigned -delimiter",
	NULL,
};

static void
print_version() {
	fprintf(stderr, "mdnconv (mDNkit) version: %s\n"
		"library version: %s\n",
		MDNKIT_VERSION,
		mdn_version_getstring());
	exit(0);
}

static void
print_usage(char *cmd) {
	int i;

	fprintf(stderr, "Usage: %s [options..] [file]\n", cmd);

	for (i = 0; options[i] != NULL; i++)
		fprintf(stderr, "\t%s\n", options[i]);

	exit(1);
}

static unsigned long
get_ucs(const char *p) {
	unsigned long v;
	char *end;

	/* Skip optional 'U+' */
	if (strncmp(p, "U+", 2) == 0)
		p += 2;

	v = strtoul(p, &end, 16);
	if (*end != '\0') {
		fprintf(stderr, "invalid UCS code point \"%s\"\n", p);
		exit(1);
	}

	return v;
}
