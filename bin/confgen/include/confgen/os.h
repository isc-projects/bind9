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

/*! \file */

#pragma once

#include <stdio.h>

int
set_user(FILE *fd, const char *user);
/*%<
 * Set the owner of the file referenced by 'fd' to 'user'.
 * Returns:
 *   0 		success
 *   -1 	insufficient permissions, or 'user' does not exist.
 */
