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

#pragma once

#include <stdint.h>
#include <stdlib.h>

#include <isc/lang.h>

/*! \file isc/random.h
 * \brief Implements wrapper around system provider pseudo-random data
 * generators.
 *
 * The system providers used:
 * - On Linux - getrandom() glibc call or syscall
 * - On BSDs - arc4random()
 *
 * If neither is available, the crypto library provider is used:
 * - If OpenSSL is used - RAND_bytes()
 * - If PKCS#11 is used - pkcs_C_GenerateRandom()
 *
 */

ISC_LANG_BEGINDECLS

uint32_t
isc_random(void);

void
isc_random_buf(void *buf, size_t buflen);
/*!<
 * \brief Get random data.
 */

uint32_t
isc_random_uniform(uint32_t upper_bound);

ISC_LANG_ENDDECLS
