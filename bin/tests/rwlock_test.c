
#include "attribute.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <isc/assertions.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/rwlock.h>

isc_rwlock_t lock;

static void *
run1(void *arg) {
	char *message = arg;

	INSIST(isc_rwlock_lock(&lock, isc_rwlocktype_read) == ISC_R_SUCCESS);
	printf("%s got READ lock\n", message);
	sleep(1);
	printf("%s giving up READ lock\n", message);
	INSIST(isc_rwlock_unlock(&lock, isc_rwlocktype_read) ==
	       ISC_R_SUCCESS);
	INSIST(isc_rwlock_lock(&lock, isc_rwlocktype_read) == ISC_R_SUCCESS);
	printf("%s got READ lock\n", message);
	sleep(1);
	printf("%s giving up READ lock\n", message);
	INSIST(isc_rwlock_unlock(&lock, isc_rwlocktype_read) ==
	       ISC_R_SUCCESS);
	INSIST(isc_rwlock_lock(&lock, isc_rwlocktype_write) == ISC_R_SUCCESS);
	printf("%s got WRITE lock\n", message);
	sleep(1);
	printf("%s giving up WRITE lock\n", message);
	INSIST(isc_rwlock_unlock(&lock, isc_rwlocktype_write) ==
	       ISC_R_SUCCESS);
	return (NULL);
}

static void *
run2(void *arg) {
	char *message = arg;

	INSIST(isc_rwlock_lock(&lock, isc_rwlocktype_write) == ISC_R_SUCCESS);
	printf("%s got WRITE lock\n", message);
	sleep(1);
	printf("%s giving up WRITE lock\n", message);
	INSIST(isc_rwlock_unlock(&lock, isc_rwlocktype_write) ==
	       ISC_R_SUCCESS);
	INSIST(isc_rwlock_lock(&lock, isc_rwlocktype_write) == ISC_R_SUCCESS);
	printf("%s got WRITE lock\n", message);
	sleep(1);
	printf("%s giving up WRITE lock\n", message);
	INSIST(isc_rwlock_unlock(&lock, isc_rwlocktype_write) ==
	       ISC_R_SUCCESS);
	INSIST(isc_rwlock_lock(&lock, isc_rwlocktype_read) == ISC_R_SUCCESS);
	printf("%s got READ lock\n", message);
	sleep(1);
	printf("%s giving up READ lock\n", message);
	INSIST(isc_rwlock_unlock(&lock, isc_rwlocktype_read) ==
	       ISC_R_SUCCESS);
	return (NULL);
}

void
main(int argc, char *argv[]) {
	unsigned int nworkers;
	unsigned int i;
	isc_thread_t workers[100];
	char name[100];
	void *dupname;

	if (argc > 1)
		nworkers = atoi(argv[1]);
	else
		nworkers = 2;
	if (nworkers > 100)
		nworkers = 100;
	printf("%d workers\n", nworkers);

	INSIST(isc_rwlock_init(&lock, 5, 10) == ISC_R_SUCCESS);

	for (i = 0; i < nworkers; i++) {
		sprintf(name, "%02u", i);
		dupname = strdup(name);
		INSIST(dupname != NULL);
		if (i != 0 && i % 3 == 0)
			INSIST(isc_thread_create(run1, dupname, &workers[i]) ==
			       ISC_R_SUCCESS);
		else
			INSIST(isc_thread_create(run2, dupname, &workers[i]) ==
			       ISC_R_SUCCESS);
	}

	for (i = 0; i < nworkers; i++)
		(void)isc_thread_join(workers[i], NULL);

	isc_rwlock_destroy(&lock);
}
