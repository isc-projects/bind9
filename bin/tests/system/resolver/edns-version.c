#include <config.h>
#include <stdio.h>

#include <isc/util.h>
#include <dns/edns.h>

int
main(int argc, char **argv) {
	UNUSED(argc);
	UNUSED(argv);
	printf("%d\n", DNS_EDNS_VERSION);
	return (0);
}
