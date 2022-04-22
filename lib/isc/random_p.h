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

#include <isc/lang.h>

/*! \file isc/random_p.h
 * \brief For automatically seeding and re-seeding when required.
 */

ISC_LANG_BEGINDECLS

void
isc__random_initialize(void);
/*!<
 * \brief Seed the thread-local random number state with fresh entropy.
 */

ISC_LANG_ENDDECLS
