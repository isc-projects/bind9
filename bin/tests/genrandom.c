#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int
main(int argc, char **argv) {
	unsigned int bytes;
	unsigned int k;
	char *endp;
	FILE *urandom, *fp;

	if (argc != 3) {
		printf("usage: genrandom k file\n");
		exit(1);
	}
	k = strtoul(argv[1], &endp, 10);
	if (*endp != 0) {
		printf("usage: genrandom k file\n");
		exit(1);
	}
	bytes = k << 10;

	fp = fopen(argv[2], "w");
	if (fp == NULL) {
		printf("failed to open %s\n", argv[2]);
		exit(1);
	}

	urandom = fopen("/dev/urandom", "r");
	if (urandom != NULL) {
		unsigned char data[1024];
		while (bytes > 0) {
			size_t n, toread;
			toread = sizeof(data);
			if (toread > bytes)
				toread = bytes;
			n = fread(data, 1, toread, urandom);
			if (n <= 0) {
				printf("error reading /dev/urandom\n");
				exit(1);
			}
			if (fwrite(data, 1, n, fp) != n) {
				printf("error writing to file\n");
				exit(1);
			}
			bytes -= n;
		}
		fclose(urandom);
	} else {
		unsigned int seed = (unsigned int) time(NULL);
		srand(seed);
		while (bytes > 0) {
			int x = rand();
			if (fwrite(&x, 1, sizeof(int), fp) != sizeof(int)) {
				printf("error writing to file\n");
				exit(1);
			}
			bytes -= sizeof(int);
		}
	}
	fclose(fp);

	exit(0);

	

}
