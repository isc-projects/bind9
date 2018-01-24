/*
 * Copyright (C) 2017, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


#ifndef ISC_DEPRECATED_H
#define ISC_DEPRECATED_H

#if (__GNUC__ + 0) > 3
#define ISC_DEPRECATED                  __attribute__((deprecated))
#else
#define ISC_DEPRECATED                  /* none */
#endif /* __GNUC__ > 3*/

#endif
