#ifndef lint
static char *rcsid = "$Id: mdnconv.c,v 1.20 2000/12/06 09:46:34 m-kasahr Exp $";
#endif

/*
 * Copyright (c) 2000 Japan Network Information Center.  All rights reserved.
 *  
 * By using this file, you agree to the terms and conditions set forth bellow.
 * 
 * 			LICENSE TERMS AND CONDITIONS 
 * 
 * The following License Terms and Conditions apply, unless a different
 * license is obtained from Japan Network Information Center ("JPNIC"),
 * a Japanese association, Fuundo Bldg., 1-2 Kanda Ogawamachi, Chiyoda-ku,
 * Tokyo, Japan.
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
#include <stdarg.h>
#include <errno.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include <mdn/result.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>
#include <mdn/localencoding.h>
#include <mdn/utf8.h>
#include <mdn/resconf.h>

#include "util.h"

/* Maxmum number of normalizers */
#define MAX_NORMALIZER	10

int			line_number;	/* current input file line number */
int			flush_every_line = 0; /* pretty obvious */
mdn_converter_t		conv_in_ctx;	/* input converter */
mdn_converter_t		conv_out_ctx;	/* output converter */
mdn_normalizer_t	norm_ctx;	/* normalizer */

void			errormsg(const char *fmt, ...);
static int		convert_file(FILE *fp, char *zld, int auto_zld,
				     int selective);
static void		usage(char *cmd);

int
main(int ac, char **av) {
	char *cmd = *av;
	char *normalizer[MAX_NORMALIZER];
	int nnormalizer = 0;
	const char *in_code = NULL;
	const char *out_code = NULL;
	char *resconf_file = NULL;
	int no_resconf = 0;
	char zld[256 + 1];
	int zld_specified = 0;
	int auto_zld = 0;
	char *encoding_alias = NULL;
	int selective = 1;
	FILE *fp;
	mdn_resconf_t resconf;

#ifdef HAVE_SETLOCALE
	(void)setlocale(LC_ALL, "");
#endif

	zld[0] = '\0';

	ac--;
	av++;
	while (ac > 0 && **av == '-') {

#define MUST_HAVE_ARG if (ac < 2) usage(cmd)
		if (strcmp(*av, "-in") == 0) {
			MUST_HAVE_ARG;
			in_code = av[1];
			ac--;
			av++;
		} else if (strcmp(*av, "-out") == 0) {
			MUST_HAVE_ARG;
			out_code = av[1];
			ac--;
			av++;
		} else if (strcmp(*av, "-conf") == 0) {
			MUST_HAVE_ARG;
			resconf_file = av[1];
			ac--;
			av++;
		} else if (strcmp(*av, "-noconf") == 0) {
			no_resconf = 1;
		} else if (strcmp(*av, "-zld") == 0) {
			MUST_HAVE_ARG;
			canonical_zld(zld, av[1]);
			zld_specified = 1;
			ac--;
			av++;
		} else if (strcmp(*av, "-auto") == 0) {
			auto_zld = 1;
		} else if (strcmp(*av, "-normalize") == 0) {
			MUST_HAVE_ARG;
			if (nnormalizer >= MAX_NORMALIZER) {
				errormsg("too many normalizers\n");
				exit(1);
			}
			normalizer[nnormalizer++] = av[1];
			ac--;
			av++;
		} else if (strcmp(*av, "-alias") == 0) {
			MUST_HAVE_ARG;
			encoding_alias = *av;
		} else if (strcmp(*av, "-flush") == 0) {
			flush_every_line = 1;
		} else if (strcmp(*av, "-whole") == 0) {
			selective = 0;
		} else {
			usage(cmd);
		}
#undef MUST_HAVE_ARG

		ac--;
		av++;
	}

	if (ac > 1)
		usage(cmd);

	/*
	 * Load configuration file.
	 */
	resconf = NULL;
	if (!no_resconf) {
		mdn_result_t r;

		r = mdn_resconf_initialize();
		if (r == mdn_success)
			r = mdn_resconf_create(&resconf);
		if (r == mdn_success)
			r = mdn_resconf_loadfile(resconf, resconf_file);
		if (r != mdn_success) {
			errormsg("error reading configuration file: %s\n",
				 mdn_result_tostring(r));
			return (1);
		}
	}

	/*
	 * Get default input/output code.
	 */
	if (in_code == NULL)
		in_code = mdn_localencoding_name();

	if (out_code == NULL) {
		mdn_converter_t c;
		if (resconf != NULL &&
		    (c = mdn_resconf_serverconverter(resconf)) != NULL)
			out_code = mdn_converter_localencoding(c);
	}

	if (in_code == NULL) {
		errormsg("input codeset must be specified\n");
		return (1);
	}
	if (out_code == NULL) {
		errormsg("output codeset must be specified\n");
		return (1);
	}

	/*
	 * Initialize codeset converter.
	 */
	if (!initialize_converter(in_code, out_code, encoding_alias))
		return (1);

	/*
	 * Initialize normalizer.
	 */
	if (nnormalizer == 0 && resconf != NULL)
		norm_ctx = mdn_resconf_normalizer(resconf);
	if (norm_ctx == NULL &&
	    !initialize_normalizer(normalizer, nnormalizer))
		return (1);

	/*
	 * Default ZLD.
	 */
	if (!zld_specified && resconf != NULL) {
		const char *conf_zld = mdn_resconf_zld(resconf);
		if (conf_zld != NULL)
			canonical_zld(zld, conf_zld);
	}

	/*
	 * Open input file.
	 */
	if (ac > 0) {
		if ((fp = fopen(av[0], "r")) == NULL) {
			errormsg("cannot open file %s: %s\n",
				 av[0], strerror(errno));
			return (1);
		}
	} else {
		fp = stdin;
	}

	/*
	 * Do the conversion.
	 */
	return convert_file(fp, zld, auto_zld, selective);
}

static int
convert_file(FILE *fp, char *zld, int auto_zld, int selective) {
	mdn_result_t r;
	char line1[1024];
	char line2[1024];
	int nl_trimmed;
	int ace_hack;

	if (mdn_converter_isasciicompatible(conv_in_ctx))
		ace_hack = 1;
	else
		ace_hack = 0;

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
		if (ace_hack) {
			/*
			 * Selectively decode those portions.
			 */
			r = selective_decode(line1, line2, 1024);
		} else {
			r = mdn_converter_localtoutf8(conv_in_ctx,
						      line1, line2, 1024);
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
		 * Normalize and convert to the output codeset.
		 */
		if (selective) {
			r = selective_encode(line2, line1, sizeof(line1),
					     zld, auto_zld);
		} else {
			r = encode_region(line2, line1, sizeof(line1),
					  zld, auto_zld);
		}
		if (r != mdn_success)
			return (1);

		fputs(line1, stdout);
		if (nl_trimmed)
			putc('\n', stdout);

		if (flush_every_line)
			fflush(stdout);

		line_number++;
	}
	return (0);
}

void
errormsg(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

static void
usage(char *cmd) {
	int i;
	static char *options[] = {
		"-in input-codeset   : specifies input codeset name.",
		"-out output-codeset : specifies output codeset name.",
		"-normalize scheme   : specifies normalization scheme.",
		"                      this option can be specified",
		"                      multiple times.",
		"-zld zld            : specifies ZLD to use.",
		"-auto               : automatically appends ZLD where",
		"                      seemed appropriate.",
		"-alias alias-file   : specifies codeset alias file.",
		"-conf conf-file     : specifies pathname of MDN resolver",
		"                      configuration file.",
		"-noconf             : do not load MDN resolver configuration",
		"                      file.",
		"-flush              : line-buffering mode.",
		"-whole              : convert the whole region instead of",
		"                      regions containing non-ascii characters",
		NULL,
	};

	fprintf(stderr, "Usage: %s [options..] [file]\n", cmd);

	for (i = 0; options[i] != NULL; i++)
		fprintf(stderr, "\t%s\n", options[i]);

	exit(1);
}
