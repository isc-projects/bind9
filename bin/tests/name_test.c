
#include <config.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/boolean.h>
#include <isc/region.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>

static void
print_wirename(isc_region_t name) {
	unsigned char *ccurr, *cend;
		
	ccurr = name->base;
	cend = ccurr + name->length;
	while (ccurr != cend)
		printf("%02x ", *ccurr++);
	printf("\n");
}

int
main(int argc, char *argv[]) {
	char s[1000];
	unsigned char b[255];
	unsigned char o[255];
	unsigned char c[255];
	unsigned int tbytes;
	dns_result_t result;
	struct dns_name name, oname, compname;
	struct isc_region source, target, r;
	dns_name_t origin, comp;
	isc_boolean_t downcase = ISC_FALSE;

	argc--;
	argv++;

	if (argc > 0) {
		if (strcasecmp("none", argv[0]) == 0)
			origin = NULL;
		else {
			source.base = (unsigned char *)argv[0];
			source.length = strlen(argv[0]);
			target.base = o;
			target.length = 255;
			result = dns_name_fromtext(&oname, &source,
						   dns_rootname, 0,
						   &target);
			if (result != 0) {
				fprintf(stderr,
					"dns_name_fromtext() failed: %d\n",
					result);
				exit(1);
			}
			origin = &oname;
		}
	} else
		origin = dns_rootname;

	if (argc > 1) {
		if (strcasecmp("none", argv[0]) == 0)
			comp = NULL;
		else {
			source.base = (unsigned char *)argv[1];
			source.length = strlen(argv[1]);
			target.base = c;
			target.length = 255;
			result = dns_name_fromtext(&compname, &source,
						   dns_rootname, 0,
						   &target);
			if (result != 0) {
				fprintf(stderr,
					"dns_name_fromtext() failed: %d\n",
					result);
				exit(1);
			}
			comp = &compname;
		}
	} else
		comp = NULL;

	while (gets(s) != NULL) {
		source.base = (unsigned char *)s;
		source.length = strlen(s);
		target.base = b;
		target.length = 255;
		result = dns_name_fromtext(&name, &source, origin, downcase,
					   &target);
		if (result == DNS_R_SUCCESS) {
			dns_name_toregion(&name, &r);
#ifndef QUIET
			print_wirename(&r);
			printf("%u labels, %u bytes.\n",
			       dns_name_countlabels(&name),
			       r.length);
#endif
		} else
			printf("%s\n", dns_result_totext(result));

		if (result == 0) {
			target.base = (unsigned char *)s;
			target.length = 1000;
			result = dns_name_totext(&name, 0, &target, &tbytes);
			if (result == DNS_R_SUCCESS) {
				printf("%.*s\n", (int)tbytes, s);
#ifndef QUIET
				printf("%u bytes.\n", tbytes);
#endif
			} else
				printf("%s\n", dns_result_totext(result));
		}

#ifndef QUIET
		if (comp != NULL) {
			int i;
			isc_boolean_t b;

			i = dns_name_compare(&name, comp);
			b = dns_name_issubdomain(&name, comp);
			if (i < 0)
				printf("<, ");
			else if (i > 0)
				printf(">, ");
			else
				printf("=, ");
			if (!b)
				printf("not ");
			printf("subdomain\n");
		}
#endif
	}
	
	return (0);
}
