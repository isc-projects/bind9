
#ifndef ISC_ERROR_H
#define ISC_ERROR_H 1

#include <stdarg.h>

typedef void (*isc_errorcallback_t)(char *, int, char *, va_list);

void isc_error_setunexpected(isc_errorcallback_t);
void isc_error_setfatal(isc_errorcallback_t);
void isc_error_unexpected(char *, int, char *, ...);
void isc_error_fatal(char *, int, char *, ...);

#define UNEXPECTED_ERROR	isc_error_unexpected
#define FATAL_ERROR		isc_error_fatal

#endif /* ISC_ERROR_H */
