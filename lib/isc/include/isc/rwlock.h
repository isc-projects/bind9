
#ifndef ISC_RWLOCK_H
#define ISC_RWLOCK_H 1

#include <isc/result.h>
#include <isc/mutex.h>
#include <isc/condition.h>

typedef enum {
	isc_rwlocktype_read = 0,
	isc_rwlocktype_write
} isc_rwlocktype_t;

typedef struct isc_rwlock {
	unsigned int		magic;
	isc_mutex_t		lock;
	isc_condition_t		readable;
	isc_condition_t		writeable;
	isc_rwlocktype_t	type;
	unsigned int		active;
	unsigned int		granted;
	unsigned int		readers_waiting;
	unsigned int		writers_waiting;
	unsigned int		read_quota;
	unsigned int		write_quota;
} isc_rwlock_t;

isc_result_t
isc_rwlock_init(isc_rwlock_t *rwl, unsigned int read_quota,
		unsigned int write_quota);

isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

void
isc_rwlock_destroy(isc_rwlock_t *rwl);

#endif /* ISC_RWLOCK_H */
