#include <stdio.h>
#include <isc/serial.h>

main() {
	isc_uint32_t a, b;
	char buf[1024];
	char *s, *e;


	while (fgets(buf, sizeof buf, stdin) != NULL) {
		buf[sizeof buf - 1] = '\0';
		s = buf;
		a = strtoul(s, &e, 0);
		if (s == e)
			continue;
		s = e;
		b = strtoul(s, &e, 0);
		if (s == e)
			continue;
		fprintf(stdout, "%u %u gt:%d lt:%d ge:%d le:%d eq:%d ne:%d\n",
			a, b,
			isc_serial_gt(a,b), isc_serial_lt(a,b),
			isc_serial_ge(a,b), isc_serial_le(a,b),
			isc_serial_eq(a,b), isc_serial_ne(a,b));
	}
}
