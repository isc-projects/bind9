/*
 * Copyright (C) 2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: builtin.h,v 1.6 2007/06/19 23:46:59 tbox Exp $ */

#ifndef NAMED_BUILTIN_H
#define NAMED_BUILTIN_H 1

/*! \file */

#include <isc/types.h>

isc_result_t ns_builtin_init(void);

void ns_builtin_deinit(void);

#endif /* NAMED_BUILTIN_H */
