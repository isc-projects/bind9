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

#ifndef _GEOIP_H
#define _GEOIP_H

extern dns_geoip_databases_t *ns_g_geoip;

void
ns_geoip_init(void);

void
ns_geoip_load(char *dir);

void
ns_geoip_shutdown(void);
#endif
