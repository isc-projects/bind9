/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/commandline.h>
#include <isc/boolean.h>
#include <isc/region.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/fixedname.h>

static void
print_wirename(isc_region_t *name) {
	unsigned char *ccurr, *cend;
		
	if (name->length == 0) {
		printf("<empty wire name>\n");
		return;
	}
	ccurr = name->base;
	cend = ccurr + name->length;
	while (ccurr != cend)
		printf("%02x ", *ccurr++);
	printf("\n");
}

int
main(int argc, char *argv[]) {
	char s[1000];
	isc_result_t result;
	dns_fixedname_t wname, wname2, oname, compname, downname;
	isc_buffer_t source;
	isc_region_t r;
	dns_name_t *name, *origin, *comp, *down;
	isc_boolean_t downcase = ISC_FALSE;
	size_t len;
	isc_boolean_t quiet = ISC_FALSE;
	isc_boolean_t concatenate = ISC_FALSE;
	isc_boolean_t got_name = ISC_FALSE;
	isc_boolean_t check_absolute = ISC_FALSE;
	isc_boolean_t check_wildcard = ISC_FALSE;
	isc_boolean_t test_downcase = ISC_FALSE;
	isc_boolean_t inplace = ISC_FALSE;
	int ch;

	while ((ch = isc_commandline_parse(argc, argv, "acdiqw")) != -1) {
		switch (ch) {
		case 'a':
			check_absolute = ISC_TRUE;
			break;
		case 'c':
			concatenate = ISC_TRUE;
			break;
		case 'd':
			test_downcase = ISC_TRUE;
			break;
		case 'i':
			inplace = ISC_TRUE;
			break;
		case 'q':
			quiet = ISC_TRUE;
			break;
		case 'w':
			check_wildcard = ISC_TRUE;
			break;
		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc > 0) {
		if (strcasecmp("none", argv[0]) == 0)
			origin = NULL;
		else {
			len = strlen(argv[0]);
			isc_buffer_init(&source, argv[0], len,
					ISC_BUFFERTYPE_TEXT);
			isc_buffer_add(&source, len);
			dns_fixedname_init(&oname);
			origin = &oname.name;
			result = dns_name_fromtext(origin, &source,
						   dns_rootname, ISC_FALSE,
						   NULL);
			if (result != 0) {
				fprintf(stderr,
					"dns_name_fromtext() failed: %d\n",
					result);
				exit(1);
			}
		}
	} else if (concatenate)
		origin = NULL;
	else
		origin = dns_rootname;

	if (argc >= 1) {
		if (strcasecmp("none", argv[0]) == 0)
			comp = NULL;
		else {
			len = strlen(argv[0]);
			isc_buffer_init(&source, argv[0], len,
					ISC_BUFFERTYPE_TEXT);
			isc_buffer_add(&source, len);
			dns_fixedname_init(&compname);
			comp = &compname.name;
			result = dns_name_fromtext(comp, &source,
						   origin, ISC_FALSE, NULL);
			if (result != 0) {
				fprintf(stderr,
					"dns_name_fromtext() failed: %d\n",
					result);
				exit(1);
			}
		}
	} else
		comp = NULL;

	dns_fixedname_init(&wname);
	name = dns_fixedname_name(&wname);
	dns_fixedname_init(&wname2);
	while (fgets(s, sizeof s, stdin) != NULL) {
		len = strlen(s);
		if (len > 0 && s[len - 1] == '\n') {
			s[len - 1] = '\0';
			len--;
		}
		isc_buffer_init(&source, s, len, ISC_BUFFERTYPE_TEXT);
		isc_buffer_add(&source, len);

		if (len > 0)
			result = dns_name_fromtext(name, &source, origin,
						   downcase, NULL);
		else {
			if (name == dns_fixedname_name(&wname))
				dns_fixedname_init(&wname);
			else
				dns_fixedname_init(&wname2);
			result = DNS_R_SUCCESS;
		}

		if (result != DNS_R_SUCCESS) {
			printf("%s\n", dns_result_totext(result));
			if (name == dns_fixedname_name(&wname))
				dns_fixedname_init(&wname);
			else
				dns_fixedname_init(&wname2);
			continue;
		}
			
		if (check_absolute && dns_name_countlabels(name) > 0) {
			if (dns_name_isabsolute(name))
				printf("absolute\n");
			else
				printf("relative\n");
		}
		if (check_wildcard && dns_name_countlabels(name) > 0) {
			if (dns_name_iswildcard(name))
				printf("wildcard\n");
			else
				printf("not wildcard\n");
		}
		dns_name_toregion(name, &r);
		if (!quiet) {
			print_wirename(&r);
			printf("%u labels, %u bytes.\n",
			       dns_name_countlabels(name), r.length);
		}

		if (concatenate) {
			if (got_name) {
				printf("Concatenating.\n");
				result = dns_name_concatenate(&wname.name,
							      &wname2.name,
							      &wname2.name,
							      NULL);
				name = &wname2.name;
				if (result == DNS_R_SUCCESS) {
					if (check_absolute &&
					    dns_name_countlabels(name) > 0) {
						if (dns_name_isabsolute(name))
							printf("absolute\n");
						else
							printf("relative\n");
					}
					if (check_wildcard &&
					    dns_name_countlabels(name) > 0) {
						if (dns_name_iswildcard(name))
							printf("wildcard\n");
						else
							printf("not "
							       "wildcard\n");
					}
					dns_name_toregion(name, &r);
					if (!quiet) {
						print_wirename(&r);
						printf("%u labels, "
						       "%u bytes.\n",
						   dns_name_countlabels(name),
						       r.length);
					}
				} else
					printf("%s\n",
					       dns_result_totext(result));
				got_name = ISC_FALSE;
			} else
				got_name = ISC_TRUE;
		}
		isc_buffer_init(&source, s, sizeof s, ISC_BUFFERTYPE_TEXT);
		if (dns_name_countlabels(name) > 0)
			result = dns_name_totext(name, ISC_FALSE, &source);
		else
			result = DNS_R_SUCCESS;
		if (result == DNS_R_SUCCESS) {
			isc_buffer_used(&source, &r);
			if (r.length > 0)
				printf("%.*s\n", (int)r.length, r.base);
			else
				printf("<empty text name>\n");
			if (!quiet) {
				printf("%u bytes.\n", source.used);
			}
		} else
			printf("%s\n", dns_result_totext(result));

		if (test_downcase) {
			if (inplace) {
				down = name;
			} else {
				dns_fixedname_init(&downname);
				down = dns_fixedname_name(&downname);
			}
			result = dns_name_downcase(name, down, NULL);
			INSIST(result == ISC_R_SUCCESS);
			if (!quiet) {
				dns_name_toregion(down, &r);
				print_wirename(&r);
				printf("%u labels, %u bytes.\n",
				       dns_name_countlabels(down),
				       r.length);
			}
			isc_buffer_init(&source, s, sizeof s,
					ISC_BUFFERTYPE_TEXT);
			if (dns_name_countlabels(down) > 0)
				result = dns_name_totext(down, ISC_FALSE,
							 &source);
			else
				result = DNS_R_SUCCESS;
			if (result == DNS_R_SUCCESS) {
				isc_buffer_used(&source, &r);
				if (r.length > 0)
					printf("%.*s\n", (int)r.length,
					       r.base);
				else
					printf("<empty text name>\n");
				if (!quiet) {
					printf("%u bytes.\n", source.used);
				}
			} else
				printf("%s\n", dns_result_totext(result));
		}

		if (comp != NULL && dns_name_countlabels(name) > 0) {
			int order;
			unsigned int nlabels, nbits;
			dns_namereln_t namereln;

			namereln = dns_name_fullcompare(name, comp, &order,
							&nlabels, &nbits);
			if (!quiet) {
				if (order < 0)
					printf("<");
				else if (order > 0)
					printf(">");
				else
					printf("=");
				switch (namereln) {
				case dns_namereln_contains:
					printf(", contains");
					break;
				case dns_namereln_subdomain:
					printf(", subdomain");
					break;
				case dns_namereln_commonancestor:
					printf(", common ancestor");
					break;
				default:
					break;
				}
				if (namereln != dns_namereln_none &&
				    namereln != dns_namereln_equal)
					printf(", nlabels = %u, nbits = %u",
					       nlabels, nbits);
				printf("\n");
			}
			printf("dns_name_equal() returns %s\n",
			       dns_name_equal(name, comp) ? "TRUE" : "FALSE");
		}

		if (concatenate) {
			if (got_name)
				name = &wname2.name;
			else
				name = &wname.name;
		}
	}
	
	return (0);
}
