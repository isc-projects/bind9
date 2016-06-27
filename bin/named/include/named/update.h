/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: update.h,v 1.13 2007/06/19 23:46:59 tbox Exp $ */

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
