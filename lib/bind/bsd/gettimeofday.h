#ifndef gettimeofday_h
#define gettimeofday_h
#include <sys/time.h>

int isc__gettimeofday(struct timeval *tp, struct timezone *tzp);

#endif
