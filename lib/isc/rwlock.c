
#include <isc/assertions.h>
#include <isc/unexpect.h>
#include <isc/boolean.h>
#include <isc/rwlock.h>

#define LOCK(lp) \
	INSIST(isc_mutex_lock((lp)) == ISC_R_SUCCESS);
#define UNLOCK(lp) \
	INSIST(isc_mutex_unlock((lp)) == ISC_R_SUCCESS);
#define BROADCAST(cvp) \
	INSIST(isc_condition_broadcast((cvp)) == ISC_R_SUCCESS);
#define SIGNAL(cvp) \
	INSIST(isc_condition_signal((cvp)) == ISC_R_SUCCESS);
#define WAIT(cvp, lp) \
	INSIST(isc_condition_wait((cvp), (lp)) == ISC_R_SUCCESS);

#include <stdio.h>

static void
print_lock(char *operation, isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	printf("%s(%s):  ", operation,
	       (type == isc_rwlocktype_read ? "read" : "write"));
	printf("%s, %u active",
	       (rwl->type == isc_rwlocktype_read ? "reading" : "writing"),
	       rwl->active);
	if (rwl->type == isc_rwlocktype_read)
		printf(", %u granted", rwl->granted);
	printf(", %u rwaiting, %u wwaiting\n",
	       rwl->readers_waiting,
	       rwl->writers_waiting);
}

isc_result_t
isc_rwlock_init(isc_rwlock_t *rwl) {
	isc_result_t result;

	REQUIRE(rwl != NULL);

	rwl->type = isc_rwlocktype_read;
	rwl->active = 0;
	rwl->granted = 0;
	rwl->readers_waiting = 0;
	rwl->writers_waiting = 0;
	rwl->read_quota = 5;		/* XXX */
	result = isc_mutex_init(&rwl->lock);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}
	result = isc_condition_init(&rwl->readable);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_condition_init(readable) failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}
	result = isc_condition_init(&rwl->writeable);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_condition_init(writeable) failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	isc_boolean_t skip = ISC_FALSE;
	isc_boolean_t done = ISC_FALSE;

	LOCK(&rwl->lock);

#ifdef DEBUG
	print_lock("prelock", rwl, type);
#endif

	if (type == isc_rwlocktype_read) {
		if (rwl->readers_waiting != 0)
			skip = ISC_TRUE;
		while (!done) {
			if (!skip &&
			    ((rwl->active == 0 ||
			      (rwl->type == isc_rwlocktype_read &&
			       rwl->granted < rwl->read_quota)))) {
				rwl->type = isc_rwlocktype_read;
				rwl->active++;
				rwl->granted++;
				done = ISC_TRUE;
			} else {
				skip = ISC_FALSE;
				rwl->readers_waiting++;
				WAIT(&rwl->readable, &rwl->lock);
				rwl->readers_waiting--;
			}
		}
	} else {
		if (rwl->writers_waiting != 0)
			skip = ISC_TRUE;
		while (!done) {
			if (!skip && rwl->active == 0) {
				rwl->type = isc_rwlocktype_write;
				rwl->active = 1;
				done = ISC_TRUE;
			} else {
				skip = ISC_FALSE;
				rwl->writers_waiting++;
				WAIT(&rwl->writeable, &rwl->lock);
				rwl->writers_waiting--;
			}
		}
	}

#ifdef DEBUG
	print_lock("postlock", rwl, type);
#endif

	UNLOCK(&rwl->lock);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	LOCK(&rwl->lock);
	REQUIRE(rwl->type == type);

#ifdef DEBUG
	print_lock("preunlock", rwl, type);
#endif

	rwl->active--;
	if (rwl->active == 0) {
		rwl->granted = 0;
		if (rwl->type == isc_rwlocktype_read) {
			if (rwl->writers_waiting > 0) {
				rwl->type = isc_rwlocktype_write;
				SIGNAL(&rwl->writeable);
			} else if (rwl->readers_waiting > 0) {
				BROADCAST(&rwl->readable);
			}
		} else {
			if (rwl->readers_waiting > 0) {
				rwl->type = isc_rwlocktype_read;
				BROADCAST(&rwl->readable);
			} else if (rwl->writers_waiting > 0) {
				SIGNAL(&rwl->writeable);
			}
		}
	} else {
		if (rwl->type == isc_rwlocktype_read &&
		    rwl->writers_waiting == 0 &&
		    rwl->readers_waiting > 0) {
			INSIST(rwl->granted > 0);
			rwl->granted--;
			SIGNAL(&rwl->readable);
		}
	}

#ifdef DEBUG
	print_lock("postunlock", rwl, type);
#endif

	UNLOCK(&rwl->lock);

	return (ISC_R_SUCCESS);
}

void
isc_rwlock_destroy(isc_rwlock_t *rwl) {
	LOCK(&rwl->lock);
	REQUIRE(rwl->active == 0 &&
		rwl->readers_waiting == 0 &&
		rwl->writers_waiting == 0);
	UNLOCK(&rwl->lock);
	(void)isc_condition_destroy(&rwl->readable);
	(void)isc_condition_destroy(&rwl->writeable);
	(void)isc_mutex_destroy(&rwl->lock);
}
