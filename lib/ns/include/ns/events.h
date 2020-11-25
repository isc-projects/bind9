/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef NS_EVENTS_H
#define NS_EVENTS_H 1

#include <isc/eventclass.h>

/*! \file ns/events.h
 * \brief
 * Registry of NS event numbers.
 */

#define NS_EVENT_CLIENTCONTROL (ISC_EVENTCLASS_NS + 0)
#define NS_EVENT_HOOKASYNCDONE (ISC_EVENTCLASS_NS + 1)

#endif /* NS_EVENTS_H */
