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

#ifndef LWRES_RESULT_H
#define LWRES_RESULT_H 1

/*! \file lwres/result.h */

typedef unsigned int lwres_result_t;

#define LWRES_R_SUCCESS			0
#define LWRES_R_NOMEMORY		1
#define LWRES_R_TIMEOUT			2
#define LWRES_R_NOTFOUND		3
#define LWRES_R_UNEXPECTEDEND		4	/* unexpected end of input */
#define LWRES_R_FAILURE			5	/* generic failure */
#define LWRES_R_IOERROR			6
#define LWRES_R_NOTIMPLEMENTED		7
#define LWRES_R_UNEXPECTED		8
#define LWRES_R_TRAILINGDATA		9
#define LWRES_R_INCOMPLETE		10
#define LWRES_R_RETRY			11
#define LWRES_R_TYPENOTFOUND		12
#define LWRES_R_TOOLARGE		13

#endif /* LWRES_RESULT_H */
