#include <isc/mem.h>
#include <isc/util.h>

#include <dns/journal.h>
#include <dns/types.h>

#include <stdlib.h>

int
main(int argc, char **argv) {
	char *file;
	isc_mem_t *mctx = NULL;

	if (argc != 2) {
		printf("usage: %s journal", argv[0]);
		exit(1);
	}

	file = argv[1];

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	RUNTIME_CHECK(dns_journal_print(mctx, file, stdout) == ISC_R_SUCCESS);
	isc_mem_detach(&mctx);
	exit(0);
}
