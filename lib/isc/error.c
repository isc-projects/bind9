
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <isc/error.h>

static void default_unexpected_callback(char *, int, char *, va_list);
static void default_fatal_callback(char *, int, char *, va_list);

static isc_errorcallback_t unexpected_callback = default_unexpected_callback;
static isc_errorcallback_t fatal_callback = default_fatal_callback;

void
isc_error_setunexpected(isc_errorcallback_t cb) {
	if (cb == NULL)
		unexpected_callback = default_unexpected_callback;
	else
		unexpected_callback = cb;
}

void
isc_error_setfatal(isc_errorcallback_t cb) {
	if (cb == NULL)
		fatal_callback = default_fatal_callback;
	else
		fatal_callback = cb;
}

void
isc_error_unexpected(char *file, int line, char *format, ...) {
	va_list args;

	va_start(args, format);
	(unexpected_callback)(file, line, format, args);
	va_end(args);
}

void
isc_error_fatal(char *file, int line, char *format, ...) {
	va_list args;

	va_start(args, format);
	(fatal_callback)(file, line, format, args);
	va_end(args);
	abort();
}

static void
default_unexpected_callback(char *file, int line, char *format, va_list args) {
	fprintf(stderr, "%s:%d: ", file, line);
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	fflush(stderr);
}

static void
default_fatal_callback(char *file, int line, char *format, va_list args) {
	fprintf(stderr, "%s:%d: fatal error: ", file, line);
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	fflush(stderr);
}
