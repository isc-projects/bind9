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

#ifndef NAMED_UPDATE_H
#define NAMED_UPDATE_H 1

/*****
 ***** Module Info
 *****/

/*! \file
 * \brief
 * RFC2136 Dynamic Update
 */

/***
 *** Imports
 ***/

#include <dns/types.h>
#include <dns/result.h>

/***
 *** Types.
 ***/

/***
 *** Functions
 ***/

void
ns_update_start(ns_client_t *client, isc_result_t sigresult);

#endif /* NAMED_UPDATE_H */
