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


#ifndef ISC_ATTRIBUTE_H
#define ISC_ATTRIBUTE_H

#if (__GNUC__ + 0) > 3
#define ISC_ATTRIBUTE_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define ISC_ATTRIBUTE_WARN_UNUSED_RESULT        /* none */
#endif /* __GNUC__ > 3*/

#endif
