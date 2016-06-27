/*
 * Copyright (C) 1998-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: eventclass.h,v 1.18 2007/06/19 23:47:18 tbox Exp $ */

#ifndef ISC_EVENTCLASS_H
#define ISC_EVENTCLASS_H 1

/*! \file isc/eventclass.h
 ***** Registry of Predefined Event Type Classes
 *****/

/*%
 * An event class is an unsigned 16 bit number.  Each class may contain up
 * to 65536 events.  An event type is formed by adding the event number
 * within the class to the class number.
 *
 */

#define ISC_EVENTCLASS(eclass)		((eclass) << 16)

/*@{*/
/*!
 * Classes < 1024 are reserved for ISC use.
 * Event classes >= 1024 and <= 65535 are reserved for application use.
 */

#define	ISC_EVENTCLASS_TASK		ISC_EVENTCLASS(0)
#define	ISC_EVENTCLASS_TIMER		ISC_EVENTCLASS(1)
#define	ISC_EVENTCLASS_SOCKET		ISC_EVENTCLASS(2)
#define	ISC_EVENTCLASS_FILE		ISC_EVENTCLASS(3)
#define	ISC_EVENTCLASS_DNS		ISC_EVENTCLASS(4)
#define	ISC_EVENTCLASS_APP		ISC_EVENTCLASS(5)
#define	ISC_EVENTCLASS_OMAPI		ISC_EVENTCLASS(6)
#define	ISC_EVENTCLASS_RATELIMITER	ISC_EVENTCLASS(7)
#define	ISC_EVENTCLASS_ISCCC		ISC_EVENTCLASS(8)
/*@}*/

#endif /* ISC_EVENTCLASS_H */
