#include <isc/error.h>

#include "zone.h"

int
main (int argc, char **argv) {
	isc_mem_t *memctx = NULL;
	zonectx_t *zonectx = NULL;
        zoneinfo_t *zone = NULL;

	RUNTIME_CHECK(isc_mem_create(0, 0, &memctx) == ISC_R_SUCCESS);

	RUNTIME_CHECK(new_zonecontext(memctx, &zonectx) == ISC_R_SUCCESS);

        RUNTIME_CHECK(new_zone(zonectx, &zone) == ISC_R_SUCCESS);
}

