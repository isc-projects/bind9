/*
 * Copyright (C) 2013, 2016-2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef _GEOIP_H
#define _GEOIP_H

#ifdef HAVE_GEOIP
#include <GeoIP.h>
#include <GeoIPCity.h>
#endif /* HAVE_GEOIP */

void named_geoip_init(void);
void named_geoip_load(char *dir);

#ifdef HAVE_GEOIP
extern dns_geoip_databases_t *named_g_geoip;
#endif /* HAVE_GEOIP */
#endif
