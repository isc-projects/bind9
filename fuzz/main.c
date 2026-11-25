/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <isc/string.h>

#include "fuzz.h"

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

#include <dirent.h>

static int
test_one_file(const char *filename) {
	int fd;
	int result = 1;
	struct stat st;
	char *data;
	ssize_t n;

	if ((fd = open(filename, O_RDONLY)) == -1) {
		fprintf(stderr, "Failed to open %s: %s\n", filename,
			strerror(errno));
		return 1;
	}

	if (fstat(fd, &st) != 0) {
		fprintf(stderr, "Failed to stat %s: %s\n", filename,
			strerror(errno));
		goto closefd;
	}

	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "Not a corpus file: %s\n", filename);
		goto closefd;
	}

	data = malloc(st.st_size != 0 ? st.st_size : 1);
	if (data == NULL) {
		fprintf(stderr, "Failed to allocate input for %s\n", filename);
		goto closefd;
	}
	n = read(fd, data, st.st_size);
	if (n == st.st_size) {
		printf("testing %zd bytes from %s\n", n, filename);
		fflush(stdout);
		LLVMFuzzerTestOneInput((const uint8_t *)data, n);
		fflush(stderr);
		result = 0;
	} else {
		if (n < 0) {
			fprintf(stderr,
				"Failed to read %zd bytes from %s: %s\n",
				(ssize_t)st.st_size, filename, strerror(errno));
		} else {
			fprintf(stderr,
				"Failed to read %zd bytes from %s, got %zd\n",
				(ssize_t)st.st_size, filename, n);
		}
	}
	free(data);
closefd:
	close(fd);
	return result;
}

static int
test_all_from(const char *dirname) {
	DIR *dirp;
	struct dirent *dp;
	size_t tested = 0;
	int result = 0;

	dirp = opendir(dirname);
	if (dirp == NULL) {
		fprintf(stderr, "Failed to open corpus %s: %s\n", dirname,
			strerror(errno));
		return 1;
	}

	while ((dp = readdir(dirp)) != NULL) {
		char filename[strlen(dirname) + strlen(dp->d_name) + 2];

		if (dp->d_name[0] == '.') {
			continue;
		}
		snprintf(filename, sizeof(filename), "%s/%s", dirname,
			 dp->d_name);
		if (test_one_file(filename) != 0) {
			result = 1;
		} else {
			tested++;
		}
	}

	closedir(dirp);
	if (tested == 0) {
		fprintf(stderr, "No corpus inputs tested in %s\n", dirname);
		return 1;
	}
	return result;
}

int
main(int argc, char **argv) {
	int ret;
	char corpusdir[PATH_MAX];
	const char *target = strrchr(argv[0], '/');
	const char *tail = NULL;

	ret = LLVMFuzzerInitialize(&argc, &argv);
	if (ret != 0) {
		fprintf(stderr, "LLVMFuzzerInitialize failure: %d\n", ret);
		return 1;
	}

	if (argv[1] != NULL && strcmp(argv[1], "-d") == 0) {
		debug = true;
		argv++;
		argc--;
	}

	if (argv[1] != NULL) {
		while (argv[1] != NULL) {
			if (test_one_file(argv[1]) != 0) {
				ret = 1;
			}
			argv++;
			argc--;
		}
		POST(argc);
		return ret;
	}

	target = (target != NULL) ? target + 1 : argv[0];
	tail = isc_string_stripprefix(target, "lt-");
	if (tail != NULL) {
		target = tail;
	}

	snprintf(corpusdir, sizeof(corpusdir), FUZZDIR "/%s.in", target);

	return test_all_from(corpusdir);
}

#elif defined(ENABLE_AFL) && __AFL_COMPILER

int
main(int argc, char **argv) {
	int ret;
	size_t n;
	unsigned char buf[64 * 1024];

	ret = LLVMFuzzerInitialize(&argc, &argv);
	if (ret != 0) {
		fprintf(stderr, "LLVMFuzzerInitialize failure: %d\n", ret);
		return 1;
	}

#ifdef __AFL_LOOP
	while (__AFL_LOOP(10000)) { /* only works with afl-clang-fast */
#else  /* ifdef __AFL_LOOP */
	{
#endif /* ifdef __AFL_LOOP */
		n = fread(buf, 1, sizeof(buf), stdin);
		if (ferror(stdin) != 0) {
			fprintf(stderr, "Failed to read from stdin: %s\n",
				strerror(errno));
			return 1;
		}

		LLVMFuzzerTestOneInput(buf, n);
	}

	return 0;
}

#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
