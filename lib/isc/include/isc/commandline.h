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

/*! \file isc/commandline.h */

#include <limits.h>
#include <stdbool.h>

#include <isc/dir.h>
#include <isc/result.h>
#include <isc/types.h>

/*% Index into parent argv vector. */
extern int isc_commandline_index;
/*% Character checked for validity. */
extern int isc_commandline_option;
/*% Argument associated with option. */
extern char *isc_commandline_argument;
/*% For printing error messages. */
extern char isc_commandline_progname[NAME_MAX];
/*% Print error message. */
extern bool isc_commandline_errprint;
/*% Reset getopt. */
extern bool isc_commandline_reset;

void
isc_commandline_init(int argc, char *const *argv);
/*%<
 * Initialize isc_commandline unit internal and external variables.
 * Currently, this only initializes isc_commandline_progname.
 */

int
isc_commandline_parse(int argc, char *const *argv, const char *options);
/*%<
 * Parse a command line (similar to getopt())
 */

isc_result_t
isc_commandline_strtoargv(isc_mem_t *mctx, char *s, unsigned int *argcp,
			  char ***argvp, unsigned int n);
/*%<
 * Tokenize the string "s" into whitespace-separated words,
 * returning the number of words in '*argcp' and an array
 * of pointers to the words in '*argvp'.  The caller
 * must free the array using isc_mem_free().  The string
 * is modified in-place.
 */
