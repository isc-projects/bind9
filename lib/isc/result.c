
#include <isc/result.h>

static char *text_table[ISC_R_LAST_ENTRY + 1] = {
	"success",
	"out of memory",
	"timed out",
	"no available threads",
	"address not available",
	"address in use",
	"permission denied",
	"no pending connections",
	"network unreachable",
	"host unreachable",
	"network down",
	"host down",
	"connection refused",
	"not enough free resources",
};

char *
isc_result_totext(isc_result_t result) {
	if (result == ISC_R_UNEXPECTED)
		return ("unexpected error");
	if (result > ISC_R_LAST_ENTRY)
		return ("unknown result code");
	return (text_table[result]);
}
