
#include <isc/result.h>

static char *text_table[ISC_R_LASTENTRY + 1] = {
	"success",				/*  0 */
	"out of memory",			/*  1 */
	"timed out",				/*  2 */
	"no available threads",			/*  3 */
	"address not available",		/*  4 */
	"address in use",			/*  5 */
	"permission denied",			/*  6 */
	"no pending connections",		/*  7 */
	"network unreachable",			/*  8 */
	"host unreachable",			/*  9 */
	"network down",				/* 10 */
	"host down",				/* 11 */
	"connection refused",			/* 12 */
	"not enough free resources",		/* 13 */
	"end of file",				/* 14 */
	"socket already bound",			/* 15 */
	"task was shut down",			/* 16 */
	"lock busy",				/* 17 */
};

char *
isc_result_totext(isc_result_t result) {
	if (result == ISC_R_UNEXPECTED)
		return ("unexpected error");
	if (result > ISC_R_LASTENTRY)
		return ("unknown result code");
	return (text_table[result]);
}
