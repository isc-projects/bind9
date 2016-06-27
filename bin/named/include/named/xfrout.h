/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: xfrout.h,v 1.12 2007/06/19 23:46:59 tbox Exp $ */

#ifndef NAMED_XFROUT_H
#define NAMED_XFROUT_H 1

/*****
 ***** Module Info
 *****/

/*! \file
 * \brief
 * Outgoing zone transfers (AXFR + IXFR).
 */

/***
 *** Functions
 ***/

void
ns_xfr_start(ns_client_t *client, dns_rdatatype_t xfrtype);

#endif /* NAMED_XFROUT_H */
