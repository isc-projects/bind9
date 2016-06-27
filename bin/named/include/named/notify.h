/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2009, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: notify.h,v 1.16 2009/01/17 23:47:42 tbox Exp $ */

#ifndef NAMED_NOTIFY_H
#define NAMED_NOTIFY_H 1

#include <named/types.h>
#include <named/client.h>

/***
 ***	Module Info
 ***/

/*! \file
 * \brief
 *	RFC1996
 *	A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
 */

/***
 ***	Functions.
 ***/

void
ns_notify_start(ns_client_t *client);

/*%<
 *	Examines the incoming message to determine appropriate zone.
 *	Returns FORMERR if there is not exactly one question.
 *	Returns REFUSED if we do not serve the listed zone.
 *	Pass the message to the zone module for processing
 *	and returns the return status.
 *
 * Requires
 *\li	client to be valid.
 */

#endif /* NAMED_NOTIFY_H */

