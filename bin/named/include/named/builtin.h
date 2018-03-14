/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/* $Id: builtin.h,v 1.6 2007/06/19 23:46:59 tbox Exp $ */

#ifndef NAMED_BUILTIN_H
#define NAMED_BUILTIN_H 1

/*! \file */

#include <isc/types.h>

isc_result_t ns_builtin_init(void);

void ns_builtin_deinit(void);

#endif /* NAMED_BUILTIN_H */
