
#include <isc/result.h>

#define LAST_ENTRY	ISC_R_NOMEMORY

static char *text_table[LAST_ENTRY+1] = {
	"success",
	"out of memory"
};

char *
isc_result_totext(isc_result result) {
	if (result == ISC_R_UNEXPECTED)
		return ("unexpected error");
	if (result > LAST_ENTRY)
		return ("unknown result code");
	return (text_table[result]);
}
