
#include <isc/result.h>

#define LAST_ENTRY	ISC_R_CONNREFUSED

static char *text_table[LAST_ENTRY+1] = {
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
};

char *
isc_result_totext(isc_result_t result) {
	if (result == ISC_R_UNEXPECTED)
		return ("unexpected error");
	if (result > LAST_ENTRY)
		return ("unknown result code");
	return (text_table[result]);
}
