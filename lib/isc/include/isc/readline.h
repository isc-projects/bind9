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

#pragma once

/*
 * A little wrapper around readline(), and add_history() to make using
 * the readline code simpler.
 */

#ifdef HAVE_LIBEDIT

#include <editline/readline.h>

#else /* HAVE_LIBEDIT */

#include <stdio.h>
#include <stdlib.h>

#define RL_MAXCMD (128 * 1024)

static inline char *
readline(const char *prompt) {
	char *line, *buf = malloc(RL_MAXCMD);
	fprintf(stdout, "%s", prompt);
	fflush(stdout);
	line = fgets(buf, RL_MAXCMD, stdin);
	if (line == NULL) {
		free(buf);
		return NULL;
	}
	return buf;
}

#define add_history(line)

#endif /* HAVE_LIBEDIT */
