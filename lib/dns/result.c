
#include <dns/result.h>

static char *text_table[DNS_R_LASTENTRY + 1] = {
	"success",				/*  0 */
	"out of memory",			/*  1 */
	"ran out of space",			/*  2 */
	"label too long",			/*  3 */
	"bad escape",				/*  4 */
	"bad bitstring",			/*  5 */
	"bitstring too long",			/*  6 */
	"empty label",				/*  7 */
	"bad dotted quad",			/*  8 */
	"unexpected end of input",		/*  9 */
	"not implemented",			/* 10 */
};

char *
dns_result_totext(dns_result_t result) {
	if (result == DNS_R_UNEXPECTED)
		return ("unexpected error");
	if (result > DNS_R_LASTENTRY)
		return ("unknown result code");
	return (text_table[result]);
}
