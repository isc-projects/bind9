#include <stdio.h>

#include <isc/fsaccess.h>
#include <isc/result.h>

#define PATH "/tmp/fsaccess"

int
main(void) {
	isc_fsaccess_t access;
	isc_result_t result;

	remove(PATH);
	fopen(PATH, "w");
	chmod(PATH, 0);

	access = 0;

	isc_fsaccess_add(ISC_FSACCESS_OWNER | ISC_FSACCESS_GROUP,
			 ISC_FSACCESS_READ | ISC_FSACCESS_WRITE,
			 &access);

	printf("fsaccess=%d\n", access);

	isc_fsaccess_add(ISC_FSACCESS_OTHER, ISC_FSACCESS_READ, &access);

	printf("fsaccess=%d\n", access);

	result = isc_fsaccess_set(PATH, access);
	if (result != ISC_R_SUCCESS)
		fprintf(stderr, "result = %s\n", isc_result_totext(result));

	return (0);
}
